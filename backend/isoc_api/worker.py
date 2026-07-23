"""ARQ worker — runs pipeline + forensics jobs in the background.

Started by docker-compose service `worker`:
    python -m isoc_api.worker
"""

from __future__ import annotations

import calendar
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arq.connections import RedisSettings
from arq.cron import cron

from . import mailer, notify
from .adapters import (
    integration_store,
    pe_static,
    remnux_adapter,
    triage_adapter,
)
from .adapters.ingest import get_adapter as get_ingest_adapter
from .db.enums import CaseStatus, IngestSource, JobStatus
from .db.models import ForensicsJob, GeneratedReport, ImportJob, Incident, IngestSourceConfig
from .db.session import AsyncSessionLocal
from .llm import client as llm_client
from .llm import forensics_prompt
from .logging_config import configure_logging, get_logger
from .pipeline import ingest_sources as ingest_helper
from .pipeline.orchestrator import run_pipeline
from .queue import redis_settings
from .settings import settings
from .threat_intel.sync import sync_all as threat_intel_sync_all

configure_logging()
logger = get_logger("isoc.worker")


async def pipeline_run(ctx, incident_id: str) -> None:
    async with AsyncSessionLocal() as session:
        await run_pipeline(session, uuid.UUID(incident_id))


async def pipeline_synthesize_only(
    ctx,
    incident_id: str,
    force_deep: bool = True,
) -> None:
    """Re-run only the LLM synthesis step (used by 'regenerate report').

    Default `force_deep=True`: any manual regenerate skips the fast tier and
    all short-circuit gates and runs the deep model directly. This is the
    analyst's escape hatch from an automatic verdict.
    """
    from .pipeline.orchestrator import _step_synthesis

    async with AsyncSessionLocal() as session:
        from .db.models import Incident

        inc = await session.get(Incident, uuid.UUID(incident_id))
        if not inc:
            return
        # _step_synthesis owns the terminal status (AWAITING_SIGNOFF at the gate,
        # or FAILED). Don't override it here.
        await _step_synthesis(session, inc, force_deep=force_deep)
        await session.commit()


async def forensics_triage(ctx, job_id: str, ioc: str, ioc_type: str | None) -> None:
    await _run_forensics(job_id, lambda: triage_adapter.triage(ioc, ioc_type, timeout=120))


async def forensics_static(ctx, job_id: str, path: str, file_type_hint: str | None = None) -> None:
    """Full static analysis pipeline:

    Step 1: file_info (hashes) — used immediately for TI triage
    Step 2: TI triage on the SHA256 in parallel with the REMnux tool wave.
            The tool wave is type-aware: PE uses peframe/capa/etc., Office
            uses olevba/oledump, PDF uses pdfid/pdf-parser, ELF uses
            radare2/readelf. file_type_hint (when set by the analyst) wins
            over auto-detection.
    Step 3: LLM synthesis turns the structured tool outputs into an
            analyst-grade verdict (LOW/MEDIUM/HIGH/CRITICAL)
    Step 4: Pipeline feedback — if this job is attached to an incident,
            the extracted IOCs and verdict are written to the incident's
            enrichment JSONB as a soft signal.
    """
    file_name = Path(path).name

    async def _do() -> dict[str, Any]:
        # Step 1: hash early so TI can begin immediately.
        info = await remnux_adapter.file_info(path)
        sha256 = info.get("sha256")

        # Health gate — if file_info couldn't reach REMnux at all, the entire
        # tool wave will fail with the same docker-socket error and the LLM
        # will hallucinate "corrupted sample". Surface the real failure now
        # instead of burning ~1k tokens to discover it second-hand.
        if info.get("error") and not (info.get("sha256") or info.get("size")):
            raise RuntimeError(f"REMnux container unreachable from worker: {info['error']}")

        # Step 2: TI + type-aware REMnux tool wave in parallel.
        import asyncio

        ti_task = triage_adapter.triage(sha256, "hash", timeout=60) if sha256 else _noop_ti()
        tool_task = remnux_adapter.static_report(path, file_type_hint=file_type_hint)
        ti_result, tool_results = await asyncio.gather(ti_task, tool_task, return_exceptions=True)

        # Ensure file_info from the parallel run beats the earlier solo call
        # (they should agree; if not, parallel wins because that's the canonical run).
        if isinstance(tool_results, dict):
            tool_results["ti_triage"] = (
                ti_result if isinstance(ti_result, dict) else {"error": str(ti_result)}
            )
            results = tool_results
        else:
            results = {
                "file_info": info,
                "ti_triage": ti_result
                if isinstance(ti_result, dict)
                else {"error": str(ti_result)},
                "tool_error": str(tool_results),
            }

        # Step 2b: pure-Python PE structural analysis (per-section entropy, RWX,
        # packer heuristics) — complements diec/portex. PE only; fail-soft.
        if isinstance(results, dict) and results.get("_file_type") == "pe":
            try:
                pe = await asyncio.to_thread(pe_static.analyze, path)
                if pe:
                    results["pe_static"] = pe
            except Exception as e:
                logger.warning("forensics.pe_static.failed", job_id=job_id, error=str(e))

        # Step 2c: enrich network IOCs embedded in the sample (peframe/floss/
        # strings) via threat intel — not just the file hash. Bounded, fail-soft.
        if isinstance(results, dict):
            try:
                results["embedded_ioc_triage"] = await _triage_embedded_iocs(results)
            except Exception as e:
                logger.warning("forensics.embedded_ioc.failed", job_id=job_id, error=str(e))

        # Step 3: LLM synthesis. Best-effort — a failure does NOT fail the
        # whole job, the tool outputs are still useful on their own.
        try:
            synthesis = await _synthesize_static(file_name, results)
            results["synthesis"] = synthesis
        except Exception as e:
            logger.exception("forensics.synthesis.failed", job_id=job_id)
            results["synthesis"] = {"error": str(e)[:500]}

        return results

    await _run_forensics(job_id, _do, attach_iocs_to_incident=True)


async def threat_intel_sync(ctx) -> dict:
    """Refresh every enabled threat feed. Idempotent; one run pulls the 6 seeded
    public OSINT feeds (Emerging Threats, Tor exit nodes, abuse.ch URLhaus /
    MalwareBazaar / ThreatFox / SSLBL — ~91k IOCs across ip/url/domain/hash).
    Triggered by the daily cron AND by a manual sync request from the admin UI."""
    async with AsyncSessionLocal() as session:
        return await threat_intel_sync_all(session)


async def report_generate(ctx) -> dict:
    """Feature 7 — generate DRAFT reports for every schedule that is due.

    Generate-to-draft ONLY; it never sends (delivery stays analyst-gated in
    routes/reports.send). Runs hourly; schedules fire at their period boundary
    (06:00 UTC), so an hourly tick picks them up within the hour. A no-op when
    nothing is due. Each schedule is isolated — one failure records a `failed`
    report row and doesn't block the others."""
    from .reports import periods as report_periods
    from .reports import service as report_service

    now = datetime.now(timezone.utc)
    generated = failed = 0
    async with AsyncSessionLocal() as session:
        due = await report_service.due_schedules(session, now)
        for s in due:
            start, end = report_periods.period_for(s.cadence, now)
            if s.cadence == "weekly":
                label = f"Week of {start:%Y-%m-%d}"
            else:
                label = f"{calendar.month_name[start.month]} {start.year}"
            # tenant_id None → all-scope (system runs unrestricted; scope=None).
            report_scope = {s.tenant_id} if s.tenant_id else None
            try:
                await report_service.generate_report(
                    session,
                    scope=report_scope,
                    template_key=s.template_key,
                    tenant_id=s.tenant_id,
                    start=start,
                    end=end,
                    label=label,
                    kind=s.cadence,
                    schedule_id=s.id,
                )
                generated += 1
            except Exception as e:  # isolate: a bad schedule shouldn't stall the rest
                logger.warning("report_generate.failed", schedule_id=str(s.id), error=str(e))
                session.add(
                    GeneratedReport(
                        tenant_id=s.tenant_id,
                        schedule_id=s.id,
                        template_key=s.template_key,
                        title=f"Report — {label}",
                        period_start=start,
                        period_end=end,
                        status="failed",
                        error=str(e)[:2000],
                    )
                )
                failed += 1
            s.last_run_at = now
            s.next_run_at = report_periods.next_run_after(s.cadence, now)
        await session.commit()
    if generated or failed:
        logger.info("report_generate.done", generated=generated, failed=failed)
    return {"generated": generated, "failed": failed}


async def send_mention_emails(ctx, payload: dict) -> dict:
    """Feature 8 — email each @mentioned user that they were named on a case.

    Runs in the worker so posting a comment stays instant. Best-effort: a no-op
    when mail isn't configured, and one recipient's failure doesn't block the
    others (the in-app notification is the reliable channel; email is a bonus)."""
    if not mailer.is_configured():
        return {"skipped": "mail not configured"}
    recipients = [e for e in (payload.get("to") or []) if e]
    if not recipients:
        return {"sent": 0}
    html_body = notify.mention_email_html(
        author=payload.get("author", ""),
        case_number=payload.get("case_number", ""),
        preview=payload.get("preview", ""),
        url=payload.get("url", ""),
    )
    subject = payload.get("subject") or "You were mentioned on a case"
    sent = 0
    for email in recipients:
        try:
            await mailer.send_html_email(to=email, subject=subject, html_body=html_body)
            sent += 1
        except Exception as e:
            logger.warning("mention_email.failed", to=email, error=str(e))
    if sent:
        logger.info("mention_email.sent", count=sent)
    return {"sent": sent}


# ── Pull ingest (scheduled console API poll → RECEIVED incident) ─────────
_PULL_DEDUP_TTL = 7 * 24 * 3600  # seconds a (provider, external_id) claim lives


async def pull_ingest(ctx) -> dict:
    """Poll every enabled + due pull source and feed each NEW alert into the same
    normalize → pipeline path the webhook uses.

    One cron serves many per-source cadences: each `ingest_sources` row is polled
    only when its interval has elapsed (with capped backoff after errors).
    Idempotent: claims each (provider, external_id) via Redis `SET NX`, with a DB
    backstop on `raw_payload.pull`. A no-op when disabled or no source is enabled,
    so it's safe to leave the cron on. Never commits a verdict — pulled alerts are
    proposals that park at the human gate like any webhook alert.
    """
    from sqlalchemy import select

    if not settings.pull_ingest_enabled:
        return {"skipped": "pull ingest disabled"}

    redis = ctx["redis"]
    now = datetime.now(timezone.utc)
    polled = 0
    ingested = 0

    async with AsyncSessionLocal() as session:
        rows = (
            (
                await session.execute(
                    select(IngestSourceConfig).where(IngestSourceConfig.enabled.is_(True))
                )
            )
            .scalars()
            .all()
        )

    for row in rows:
        # "Poll now" (set by the control plane) forces one immediate poll,
        # bypassing the interval. GETDEL consumes the flag atomically.
        forced = await redis.getdel(ingest_helper.pollnow_key(row.id))
        if not forced and not ingest_helper.is_due(
            interval_seconds=row.interval_seconds,
            consecutive_errors=row.consecutive_errors,
            last_poll_at=row.last_poll_at,
            now=now,
        ):
            continue

        adapter = get_ingest_adapter(row.provider)
        if adapter is None:
            logger.warning("pull_ingest.no_adapter", provider=row.provider)
            # Surface the reason on the row instead of skipping silently.
            await ingest_helper.record_failure(
                row.id, f"no ingestion adapter for provider '{row.provider}'"
            )
            continue
        creds = await _resolve_pull_creds(row.provider, row.identifier)
        if creds is None:
            logger.warning("pull_ingest.no_creds", provider=row.provider, identifier=row.identifier)
            # No usable credentials — tell the analyst exactly what's missing.
            # Clears automatically on the next successful poll once creds exist.
            await ingest_helper.record_failure(
                row.id,
                f"no credentials for {row.provider}/{row.identifier} — "
                f"add them in the Connectors tab (identifier must match)",
            )
            continue

        polled += 1
        t0 = time.monotonic()
        try:
            result = await adapter.fetch(
                creds=creds, cursor=row.cursor or {}, max_items=row.max_items
            )
        except Exception as e:  # noqa: BLE001 — one bad source must not break the loop
            logger.warning("pull_ingest.fetch_failed", provider=row.provider, error=str(e))
            await ingest_helper.record_failure(row.id, str(e))
            continue

        # Schema-drift sentinel (ADR-0006 P1a): fingerprint the raw vendor payloads and warn
        # when the source's field shape changes between polls (a silent field_map rot risk).
        drift = ingest_helper.drift_check(row.field_fingerprint, result.alerts)
        if drift is not None and drift.changed:
            logger.warning(
                "pull_ingest.schema_drift",
                provider=row.provider,
                identifier=row.identifier,
                old_fingerprint=row.field_fingerprint,
                new_fingerprint=drift.fingerprint,
            )
        new_fingerprint = drift.fingerprint if drift is not None else row.field_fingerprint

        ingested_this = 0
        for alert in result.alerts:
            if not ingest_helper.severity_passes(alert.get("severity"), row.min_severity):
                continue
            ext = alert.get("external_id")
            if not ext:
                continue
            # Atomic claim — skip if another poll already ingested this alert.
            claimed = await redis.set(
                ingest_helper.dedup_key(row.provider, ext), "1", nx=True, ex=_PULL_DEDUP_TTL
            )
            if not claimed:
                continue
            incident_id = await _create_pull_incident(row, alert, ext)
            if incident_id:
                await redis.enqueue_job("pipeline_run", incident_id)
                ingested += 1
                ingested_this += 1

        poll_ms = int((time.monotonic() - t0) * 1000)
        await ingest_helper.record_success(
            row.id,
            cursor=result.cursor or {},
            poll_ms=poll_ms,
            count=ingested_this,
            field_fingerprint=new_fingerprint,
        )

    if ingested or polled:
        logger.info("pull_ingest.ingested", polled=polled, ingested=ingested)
    return {"polled": polled, "ingested": ingested}


async def _resolve_pull_creds(provider: str, identifier: str):
    """Resolve credentials for a pull source from the per-customer store.

    Every provider resolves through the same generic seam. Returns None when nothing
    is configured (the source stays a no-op).
    """
    return await integration_store.get_creds(provider, identifier)


async def _pull_already_ingested(session, provider: str, external_id: str) -> bool:
    """DB backstop for the Redis dedup — survives a Redis flush/restart. The key
    lives in incident.raw_payload['pull'], not in memory."""
    from sqlalchemy import select

    row = (
        await session.execute(
            select(Incident.id)
            .where(
                Incident.raw_payload["pull"]["provider"].astext == provider,
                Incident.raw_payload["pull"]["external_id"].astext == external_id,
            )
            .limit(1)
        )
    ).first()
    return row is not None


async def _create_pull_incident(
    row: IngestSourceConfig, alert: dict, external_id: str
) -> str | None:
    """Create a RECEIVED incident from a pulled alert, or None if already ingested.

    Stores raw text + the original console object + source_hint so the
    deterministic parser/normalizer runs downstream unchanged.
    """
    async with AsyncSessionLocal() as session:
        if await _pull_already_ingested(session, row.provider, external_id):
            return None
        inc = Incident(
            title="(unparsed)",
            status=CaseStatus.RECEIVED,
            ingest_source=IngestSource.PULL,
            customer=row.customer,
            raw_payload={
                "text": alert.get("raw_text", ""),
                "source_hint": alert.get("source_hint"),
                "original": alert.get("original"),
                "field_map": row.field_map,  # config-driven mapping for parserless sources
                "pull": {"provider": row.provider, "external_id": external_id},
            },
        )
        session.add(inc)
        await session.flush()
        incident_id = str(inc.id)
        await session.commit()
        return incident_id


# ── Batch / historical import (file → RECEIVED incidents) ────────────────
_BATCH_DEDUP_TTL = 30 * 24 * 3600  # a (content-hash) claim lives 30 days


async def batch_import(ctx, job_id: str) -> dict:
    """Stream an uploaded / pointed-at file into RECEIVED incidents on the normal
    pipeline. One `pipeline_run` is enqueued per record; ARQ `max_jobs` throttles
    the downstream fan-out. Best-effort progress on the `import_jobs` row; a single
    bad record is counted and skipped, never aborting the run. Never commits a
    verdict — imported alerts park at the human gate like any other.
    """
    from .pipeline import batch_import as bi

    redis = ctx["redis"]
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(ImportJob, jid)
        if job is None:
            return {"error": "import job not found"}
        fmt, path_s, dedupe = job.fmt, job.path, job.dedupe
        source_hint, field_map, customer = job.source_hint, job.field_map, job.customer
        job.status = "running"
        await session.commit()

    path = Path(path_s)
    created = skipped = failed = processed = 0

    async def _flush(*, status: str | None = None, error: str | None = None) -> None:
        try:
            async with AsyncSessionLocal() as s:
                j = await s.get(ImportJob, jid)
                if j is None:
                    return
                j.processed, j.created_count = processed, created
                j.skipped_count, j.failed_count = skipped, failed
                if status:
                    j.status = status
                if error is not None:
                    j.error = error[:2000]
                await s.commit()
        except Exception:  # noqa: BLE001 — progress bookkeeping must not break the import
            pass

    try:
        # iter_records opens the file lazily — a missing/unreadable path raises
        # here and is handled by the reader-level except below (no blocking stat
        # in this async job; the file open lives in the sync generator).
        for record in bi.iter_records(path, fmt):
            processed += 1
            content_hash = bi.dedup_hash(record)
            if dedupe:
                claimed = await redis.set(
                    bi.dedup_key(content_hash), "1", nx=True, ex=_BATCH_DEDUP_TTL
                )
                if not claimed:
                    skipped += 1
                    continue
            try:
                payload = bi.build_import_payload(
                    record, source_hint=source_hint, field_map=field_map, job_id=job_id
                )
                async with AsyncSessionLocal() as s:
                    inc_id = await bi.create_received_incident(
                        s, customer=customer, raw_payload=payload
                    )
                    await s.commit()
                await redis.enqueue_job("pipeline_run", inc_id)
                created += 1
            except Exception as e:  # noqa: BLE001 — one bad record must not abort the import
                failed += 1
                logger.warning("batch_import.record_failed", job=job_id, error=str(e))
            if processed % 50 == 0:
                await _flush()
    except Exception as e:  # noqa: BLE001 — reader-level failure (bad file, decode error)
        logger.warning("batch_import.failed", job=job_id, error=str(e))
        await _flush(status="failed", error=str(e))
        return {"error": str(e), "created": created}

    await _flush(status="completed")
    logger.info("batch_import.done", job=job_id, created=created, skipped=skipped, failed=failed)
    return {"created": created, "skipped": skipped, "failed": failed, "processed": processed}


# ── LLM synthesis helpers ───────────────────────────────────────────────
async def _synthesize_static(file_name: str, tool_results: dict[str, Any]) -> dict[str, Any]:
    user = forensics_prompt.build_static_user_prompt(file_name, tool_results)
    res = await llm_client.complete(
        system=forensics_prompt.STATIC_SYSTEM_PROMPT,
        user=user,
        model=settings.isoc_model_deep,
        # Raised from 2500 to fit the analyst_narrative (MBC/Pyramid/detection-
        # engineering) section alongside the structured fields.
        max_tokens=4000,
        temperature=0.1,
    )
    if res.status != "ok" or not res.text:
        return {"error": res.error or "LLM returned empty", "model": res.model}
    parsed = forensics_prompt.extract_json(res.text)
    parsed["_meta"] = {
        "model": res.model,
        "input_tokens": res.input_tokens,
        "output_tokens": res.output_tokens,
        "latency_ms": res.latency_ms,
    }
    return parsed


async def _triage_embedded_iocs(results: dict[str, Any]) -> list[dict[str, Any]]:
    """Run network IOCs embedded INSIDE the sample (surfaced by peframe / floss /
    pestr) through threat intel — the file-hash triage alone misses these. Reuses
    the alert-pipeline extractor + triage. Bounded to 15, public IOCs only."""
    from .pipeline import ioc_extract

    peframe = (results.get("peframe") or {}).get("parsed") or {}
    floss = results.get("floss") or {}
    pestr = results.get("pestr") or {}
    blob = "\n".join(
        [
            *(peframe.get("urls") or []),
            *(peframe.get("ips") or []),
            *(floss.get("decoded_strings") or []),
            *(floss.get("stack_strings") or []),
            *(pestr.get("interesting") or []),
            *(pestr.get("narrative") or []),
        ]
    )
    if not blob.strip():
        return []
    extracted = ioc_extract.extract({}, blob)
    # Network IOCs only — the file hash is already triaged separately.
    net = [(t, v) for (t, v) in extracted if t.value in ("ipv4", "ipv6", "domain", "url")]
    triage_args = ioc_extract.to_triage_args(net)[:15]
    if not triage_args:
        return []
    res = await triage_adapter.triage_many(triage_args, timeout=90)
    return res or []


async def _noop_ti() -> dict[str, Any]:
    return {"verdict": "unknown", "sources": [], "summary": {"found_in_sources": []}}


# ── helper ──────────────────────────────────────────────────────────────
async def _run_forensics(job_id: str, fn, attach_iocs_to_incident: bool = False) -> None:
    async with AsyncSessionLocal() as session:
        job = await session.get(ForensicsJob, uuid.UUID(job_id))
        if not job:
            logger.error("forensics.missing", job_id=job_id)
            return
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        await session.commit()
        try:
            result = await fn()
            job.result = result if isinstance(result, dict) else {"raw": result}
            job.status = JobStatus.COMPLETED

            # Pipeline feedback: if this job is attached to an incident,
            # surface the extracted IOCs + verdict as a soft signal on that
            # incident's enrichment. The pipeline already reads enrichment
            # JSONB for downstream synthesis on the case page.
            if attach_iocs_to_incident and job.incident_id and isinstance(job.result, dict):
                await _attach_to_incident(session, job)
        except Exception as e:
            logger.exception("forensics.error", job_id=job_id)
            job.status = JobStatus.FAILED
            job.error = str(e)[:1000]
        finally:
            job.finished_at = datetime.now(timezone.utc)
            await session.commit()


async def _attach_to_incident(session, job: ForensicsJob) -> None:
    """Merge forensics IOCs + verdict into incident.enrichment under a
    `forensics` key. Safe to call multiple times — appends to the list of
    forensics runs rather than overwriting."""
    from .db.models import Incident

    inc = await session.get(Incident, job.incident_id)
    if not inc:
        return
    enrichment = dict(inc.enrichment or {})
    forensics = list(enrichment.get("forensics") or [])
    synthesis = (job.result or {}).get("synthesis") or {}
    forensics.append(
        {
            "job_id": str(job.id),
            "kind": job.kind.value if hasattr(job.kind, "value") else str(job.kind),
            "completed": datetime.now(timezone.utc).isoformat(),
            "verdict": synthesis.get("verdict"),
            "confidence": synthesis.get("confidence"),
            "key_finding": synthesis.get("key_finding"),
            "indicators": synthesis.get("indicators") or {},
        }
    )
    enrichment["forensics"] = forensics[-5:]  # keep last 5 runs
    inc.enrichment = enrichment
    logger.info(
        "forensics.attached_to_incident", job_id=str(job.id), incident_id=str(job.incident_id)
    )


class WorkerSettings:
    redis_settings: RedisSettings = redis_settings()
    functions = [
        pipeline_run,
        pipeline_synthesize_only,
        forensics_triage,
        forensics_static,
        threat_intel_sync,
        report_generate,
        send_mention_emails,
        pull_ingest,
        batch_import,
    ]
    # 04:00 UTC daily. Refresh window large enough that the user can hit
    # "Sync now" at any time without colliding with the cron.
    cron_jobs = [
        cron(threat_intel_sync, hour={4}, minute={0}, run_at_startup=False),
        # Branded reports (F7) — hourly check; schedules fire at 06:00 UTC per
        # cadence. Generates to draft only, never sends. No-op when none due.
        cron(report_generate, minute={0}, run_at_startup=False),
        # Pull ingest — every minute; per-source `interval_seconds` gates the
        # actual poll. No-op unless pull_ingest_enabled + an enabled source row.
        cron(pull_ingest, minute=set(range(60)), run_at_startup=True),
    ]
    max_jobs = 8
    job_timeout = 600  # 10 min — covers full static tool wave + LLM synthesis
    keep_result = 3600
    on_startup = None
    on_shutdown = None


# `python -m isoc_api.worker` entrypoint.
if __name__ == "__main__":
    from arq.worker import run_worker

    run_worker(WorkerSettings)
