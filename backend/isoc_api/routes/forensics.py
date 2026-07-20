"""Forensics — triage (fast IOC lookup), static, dynamic analysis."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Annotated

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user, require_analyst
from ..auth.tenancy import TenantScope, current_tenant_scope, require_in_scope
from ..db.enums import ForensicsKind, JobStatus
from ..db.models import ForensicsJob, Incident, User
from ..db.session import get_session
from ..queue import get_arq
from ..schemas import JobOut, TriageRequest
from ..settings import settings

router = APIRouter()


@router.post("/triage", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def triage_one(
    body: TriageRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    incident_id: uuid.UUID | None = None,
) -> JobOut:
    job = ForensicsJob(
        kind=ForensicsKind.TRIAGE,
        ioc_or_file=body.ioc,
        status=JobStatus.QUEUED,
        incident_id=incident_id,
    )
    session.add(job)
    await session.flush()
    enqueued = await arq.enqueue_job("forensics_triage", str(job.id), body.ioc, body.type)
    job.arq_job_id = enqueued.job_id if enqueued else None
    return JobOut.model_validate(job)


@router.post("/static", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def static_analysis(
    file: UploadFile,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    incident_id: uuid.UUID | None = None,
    file_type_hint: str | None = None,
) -> JobOut:
    """Static analysis. Optional `file_type_hint` overrides auto-detection
    and forces a specific tool wave (pe / ole / ooxml / pdf / elf / macho /
    script_* / archive). Invalid values are silently ignored by the adapter."""
    # Persist the file into the shared workspace volume.
    target_dir = settings.workspace_path / "static" / str(uuid.uuid4())
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / (file.filename or "sample.bin")
    target_path.write_bytes(await file.read())

    job = ForensicsJob(
        kind=ForensicsKind.STATIC,
        ioc_or_file=str(target_path),
        status=JobStatus.QUEUED,
        incident_id=incident_id,
    )
    session.add(job)
    await session.flush()
    enqueued = await arq.enqueue_job(
        "forensics_static",
        str(job.id),
        str(target_path),
        file_type_hint,
    )
    job.arq_job_id = enqueued.job_id if enqueued else None
    return JobOut.model_validate(job)


@router.post("/dynamic", status_code=status.HTTP_410_GONE)
async def dynamic_analysis_removed(
    _user: Annotated[User, Depends(require_analyst)],
) -> dict[str, str]:
    """**Removed by design.** Dynamic sandboxing was removed from this platform
    because shared-container detonation is unsafe for any sample worth
    analyzing — ransomware can encrypt other queued samples in the shared
    workspace volume, leftover processes contaminate the next sample's trace,
    and the kernel boundary between containers is too thin for high-assurance
    malware work.

    For dynamic analysis, integrate one of the following via their APIs:
      - Hybrid Analysis (https://www.hybrid-analysis.com/)
      - any.run        (https://app.any.run/)
      - Triage         (https://tria.ge/)
      - Joe Sandbox    (https://www.joesandbox.com/)
    They run real VMs with snapshot/restore per sample — the correct tool for
    this job.

    Returns 410 Gone so legacy clients fail loudly instead of silently
    waiting on a queue that no longer exists. Historical dynamic-job records
    remain queryable via GET /forensics/jobs and GET /forensics/jobs/{id}.
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "error": "dynamic_analysis_removed",
            "message": (
                "Dynamic sandboxing is no longer provided by this platform. "
                "Container-based detonation is unsafe for hostile samples. "
                "Use Hybrid Analysis / any.run / Triage / Joe Sandbox via their "
                "APIs for proper VM-isolated dynamic analysis."
            ),
        },
    )


@router.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> JobOut:
    job = await session.get(ForensicsJob, job_id)
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    # Scope: ad-hoc jobs (no incident_id) are shared across all authenticated
    # analysts — same rule as list_jobs. Incident-attached jobs require the
    # parent incident to be in scope.
    if scope is not None and job.incident_id is not None:
        inc = await session.get(Incident, job.incident_id)
        require_in_scope(inc.tenant_id if inc else None, scope)
    return JobOut.model_validate(job)


@router.get("/jobs", response_model=list[JobOut])
async def list_jobs(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    kind: ForensicsKind | None = None,
    status_: JobStatus | None = None,
    incident_id: uuid.UUID | None = None,
    limit: int = 50,
) -> list[JobOut]:
    """List forensics jobs.

    Scope rules:
      - Admins (scope is None): see everything.
      - Scoped users: see jobs attached to an in-scope incident
        OR ad-hoc jobs (incident_id IS NULL). Ad-hoc jobs are file-uploads,
        not tenant-scoped data, so all authenticated analysts share them —
        this is the recent-runs panel on `/forensics` for everyone.
    """
    from sqlalchemy import or_

    stmt = select(ForensicsJob).order_by(desc(ForensicsJob.created_at)).limit(limit)
    if kind:
        stmt = stmt.where(ForensicsJob.kind == kind)
    if status_:
        stmt = stmt.where(ForensicsJob.status == status_)
    if incident_id:
        stmt = stmt.where(ForensicsJob.incident_id == incident_id)

    if scope is not None:
        in_scope_incidents = select(Incident.id).where(
            Incident.tenant_id.in_(scope) if scope else False
        )
        stmt = stmt.where(
            or_(
                ForensicsJob.incident_id.in_(in_scope_incidents),
                ForensicsJob.incident_id.is_(None),
            )
        )

    rows = (await session.scalars(stmt)).all()
    return [JobOut.model_validate(r) for r in rows]


@router.get("/jobs/{job_id}/report.md", response_class=PlainTextResponse)
async def export_report_markdown(
    job_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> PlainTextResponse:
    """Render the full analyst report as markdown (matches the skill's MD style)."""
    job = await session.get(ForensicsJob, job_id)
    if not job or job.status != JobStatus.COMPLETED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found or not complete")
    if scope is not None:
        if job.incident_id is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
        inc = await session.get(Incident, job.incident_id)
        require_in_scope(inc.tenant_id if inc else None, scope)

    md = _render_markdown_report(job)
    return PlainTextResponse(
        md,
        headers={"Content-Disposition": f'attachment; filename="forensics_{str(job.id)[:8]}.md"'},
    )


def _render_markdown_report(job: ForensicsJob) -> str:
    """Render a forensics job as analyst-grade markdown.

    Mirrors the skill's MD output (Executive Summary → TI Assessment →
    Behavioral Analysis → MITRE → IOCs → Recommendations).
    """
    r = job.result or {}
    synthesis = r.get("synthesis") or {}
    file_info = r.get("file_info") or {}
    ti = r.get("ti_triage") or {}
    diec = (r.get("diec") or {}).get("parsed") or {}
    capa = r.get("capa") or {}
    yara_full = r.get("yara_full") or {}

    verdict = synthesis.get("verdict", "UNKNOWN")
    confidence = synthesis.get("confidence", "UNKNOWN")
    summary = synthesis.get("executive_summary", "_(no synthesis available)_")
    key = synthesis.get("key_finding", "")

    file_type = r.get("_file_type", "unknown")
    tools_run = r.get("_tools_run") or []

    lines = [
        f"# Forensics Report — {Path(job.ioc_or_file).name}",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Risk Level** | {verdict} |",
        f"| **Confidence** | {confidence} |",
        f"| **File Type** | `{file_type}` |",
        f"| **Analysis Date** | {(job.finished_at or job.created_at).isoformat() if (job.finished_at or job.created_at) else 'n/a'} |",
        f"| **Job ID** | `{job.id}` |",
        f"| **Kind** | {job.kind.value if hasattr(job.kind, 'value') else job.kind} |",
        f"| **Tools run** | {', '.join(tools_run) if tools_run else '—'} |",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
        f"**Key Finding:** {key}" if key else "",
        "",
        "## File Indicators",
        "",
        f"| Type | Value |",
        f"|------|-------|",
        f"| SHA256 | `{file_info.get('sha256', '—')}` |",
        f"| SHA1   | `{file_info.get('sha1', '—')}` |",
        f"| MD5    | `{file_info.get('md5', '—')}` |",
        f"| Size   | {file_info.get('size', '—')} bytes |",
        f"| Type   | {file_info.get('file_type', '—')} |",
        f"| Compiler | {diec.get('compiler', '—')} |",
        f"| Packer | {diec.get('packer', '—')} |",
        "",
    ]

    # TI section
    if ti:
        lines += [
            "## Threat Intelligence Assessment",
            "",
            f"- **Verdict:** {ti.get('verdict', 'unknown')} ({ti.get('confidence', '—')})",
            f"- **Found in sources:** {', '.join((ti.get('summary') or {}).get('found_in_sources') or []) or '(none)'}",
            f"- **VT detection:** {(ti.get('summary') or {}).get('virustotal_detection', '—')}",
            f"- **Tags:** {', '.join((ti.get('summary') or {}).get('tags') or []) or '(none)'}",
            "",
        ]

    # Behavioral assessment
    ba = synthesis.get("behavioral_assessment") or []
    if ba:
        lines += ["## Behavioral Analysis", ""]
        for item in ba:
            lines += [
                f"### {item.get('capability', '—')}",
                f"- **Confidence:** {item.get('confidence', '—')}",
                f"- **Evidence:** {item.get('evidence', '—')}",
                "",
            ]

    # MITRE
    mitre = synthesis.get("mitre_techniques") or capa.get("attack_techniques") or []
    if mitre:
        lines += [
            "## MITRE ATT&CK Mapping",
            "",
            "| Tactic | Technique | ID |",
            "|--------|-----------|----|",
        ]
        for t in mitre[:20]:
            lines.append(
                f"| {t.get('tactic', '—')} | {t.get('name') or t.get('technique', '—')} | `{t.get('id', '—')}` |"
            )
        lines.append("")

    # YARA
    if yara_full.get("matches"):
        lines += ["## YARA Family Matches", ""]
        for m in yara_full["matches"][:20]:
            lines.append(f"- `{m.get('rule')}` ({m.get('namespace', '')})")
        lines.append("")

    # IOCs
    inds = synthesis.get("indicators") or {}
    if any(inds.get(k) for k in ("urls", "ips", "emails", "hashes")):
        lines += ["## Indicators of Compromise", ""]
        for k in ("urls", "ips", "emails", "hashes"):
            if inds.get(k):
                lines.append(f"**{k.title()}**")
                for v in inds[k][:20]:
                    lines.append(f"- `{v}`")
                lines.append("")

    # Recommendations
    recs = synthesis.get("recommendations") or []
    if recs:
        lines += ["## Recommendations", ""] + [f"- {r}" for r in recs] + [""]

    # False-positive reasoning
    if synthesis.get("false_positive_likelihood"):
        lines += [
            "## False Positive Assessment",
            "",
            f"- **Likelihood:** {synthesis.get('false_positive_likelihood')}",
            f"- **Reasoning:** {synthesis.get('false_positive_reasoning', '—')}",
            "",
        ]

    return "\n".join(lines)
