"""Customer-facing notification cases.

Separate from the analyst-facing /incidents API. An analyst promotes any
incident (regardless of verdict) into a customer case, edits the
customer-friendly text, and (Phase-CC5) sends via SMTP.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from arq.connections import ArqRedis
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy import asc, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, html_sanitize, mailer, mentions, notify
from ..auth.deps import current_user, require_analyst
from ..auth.tenancy import (
    TenantScope,
    current_tenant_scope,
    require_in_scope,
    scope_clause_for_incidents,
)
from ..db.enums import CustomerCaseStatus, UserStatus
from ..db.models import (
    CaseComment,
    CaseWatcher,
    CustomerCase,
    CustomerCaseIncident,
    Incident,
    Tenant,
    User,
)
from ..db.session import get_session
from ..llm import client as llm_client
from ..llm import customer_prompt
from ..queue import get_arq
from ..settings import settings
from ..templates import env as jinja_env
from ..templates.labels import labels_for

router = APIRouter()


# ── helpers ────────────────────────────────────────────────────────────────


def _scope_clause_for_cases(scope: TenantScope):
    """Mirror of scope_clause_for_incidents but for customer_cases.tenant_id."""
    if scope is None:
        from sqlalchemy import literal

        return literal(True)
    if not scope:
        from sqlalchemy import false

        return false()
    return CustomerCase.tenant_id.in_(scope)


def _notification_subject(c: CustomerCase, tenant_name: str | None) -> str:
    """Customer email subject: '<CASE ID> - <CUSTOMER> - <USE CASE>'.

    Use case = the customer-facing attack type, falling back to the case title.
    Empty parts are skipped; a bare fallback keeps the subject non-empty."""
    use_case = c.attack_type_label or c.title
    subject = " - ".join(p for p in (c.case_number, tenant_name, use_case) if p)
    return subject or f"Security notification {c.case_number}"


def _serialise(
    c: CustomerCase,
    tenant_name: str | None = None,
    source_case_number: str | None = None,
    attached_incidents: list[dict] | None = None,
    tenant_notification_email: str | None = None,
    tenant_notification_email_cc: str | None = None,
) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "case_number": c.case_number,
        "source_incident_id": str(c.source_incident_id),
        "source_case_number": source_case_number,
        "tenant_id": str(c.tenant_id) if c.tenant_id else None,
        "tenant_name": tenant_name,
        # Routing snapshot for the Send modal — read-only echo from the tenant
        # row at request time.
        "tenant_notification_email": tenant_notification_email,
        "tenant_notification_email_cc": tenant_notification_email_cc,
        "status": str(c.status),
        "locale": c.locale,
        "title": c.title,
        # Customer email subject = "<CASE ID> - <CUSTOMER> - <USE CASE>".
        "notification_subject": _notification_subject(c, tenant_name),
        "incident_analysis": c.incident_analysis,
        "attack_type_label": c.attack_type_label,
        "critical_impact_summary": c.critical_impact_summary,
        "recommended_actions": c.recommended_actions or [],
        "actions_taken": c.actions_taken or [],
        "threat_intel_summary": c.threat_intel_summary,
        "attribution": c.attribution,
        "prior_cases_note": c.prior_cases_note,
        "attached_incidents": attached_incidents or [],
        "sent_at": c.sent_at.isoformat() if c.sent_at else None,
        "sent_recipients_to": c.sent_recipients_to,
        "sent_recipients_cc": c.sent_recipients_cc,
        "sent_subject": c.sent_subject,
        "edited_html": c.edited_html,
        "body_source": c.body_source,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


# IOC selection (P1) — keep customer-facing indicators free of the transport
# noise that V1-email ingestion drags in (Outlook safelinks, the SOC's own mail
# domain, the Vision One portal). 0-signal IOCs stay eligible — the analyst
# curates the final list in the editor; we only exclude envelope noise so the
# customer's own domain can't be auto-picked and mislabelled as an indicator.
_BENIGN_IOC_SUBSTR: tuple[str, ...] = (
    "safelinks.protection.outlook.com",
    ".protection.outlook.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "microsoft.com",
    "xdr.trendmicro.com",
    "trendmicro.com",
)


def _own_domains() -> set[str]:
    """The SOC's own mail domain(s) — never a customer-facing indicator."""
    domains: set[str] = set()
    mbx = settings.graph_mailbox
    if mbx and "@" in mbx:
        domains.add(mbx.split("@", 1)[1].lower())
    return domains


def _is_noise_ioc(value: str, own_domains: set[str]) -> bool:
    v = value.lower().strip()
    if not v:
        return True
    host = v.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    if any(host == d or host.endswith("." + d) for d in own_domains):
        return True
    return any(sub in v for sub in _BENIGN_IOC_SUBSTR)


def _ioc_signal(entry: dict) -> int:
    s = entry.get("summary") or {}
    total = 0
    for k in ("vt_malicious", "abuseipdb", "otx_pulses", "urlhaus_url_count"):
        try:
            total += int(s.get(k) or 0)
        except (TypeError, ValueError):
            pass
    return total


_TYPE_LABEL: dict[str, str] = {
    "sha256": "File hash (SHA256)",
    "sha1": "File hash (SHA1)",
    "md5": "File hash (MD5)",
    "hash": "File hash",
    "ipv4": "IP",
    "ipv6": "IP",
    "ip": "IP",
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
}


def _infer_ioc_type(value: str) -> str:
    if len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return {64: "sha256", 40: "sha1", 32: "md5"}[len(value)]
    if "://" in value:
        return "url"
    if value.replace(".", "").isdigit() or ":" in value:
        return "ip"
    return "domain"


def _vt_from_summary(summary: dict, ioc_type: str) -> tuple[str | None, str | None]:
    """(vt_text, vt_color) for a triage summary. triage.py reports VT only when
    the IOC is actually in VT, as "virustotal_detection": "X/Y"; when absent for
    a VT-checkable type we say so explicitly (mirrors the analyst's view)."""
    det = summary.get("virustotal_detection")
    if isinstance(det, str) and "/" in det:
        try:
            count, total = (int(x) for x in det.split("/", 1))
        except (ValueError, TypeError):
            return None, None
        if count == 0:
            return f"{count}/{total} — Clean", "green"
        if count <= 4:
            return f"{count}/{total} — Suspicious", "yellow"
        return f"{count}/{total} — Malicious", "red"
    if ioc_type in ("sha256", "sha1", "md5", "hash", "ip", "ipv4", "ipv6", "url", "domain"):
        return "Not in VirusTotal", None
    return None, None


def _build_threat_intel_ctx(
    inc: "Incident", attribution: str | None, prior_cases_note: str | None
) -> dict:
    """Assemble the structured threat-intel table the template renders.

    Pulls factual fields straight from incident.normalized + incident.enrichment
    so the LLM never paraphrases (and so can't hallucinate) the values. The
    LLM contributes only the 1-line attribution + 1-line prior-cases note,
    passed in as args here from the saved CustomerCase columns.

    Output schema:
        {
            "indicators": [                  # one row per real IOC + its reputation
                {"value", "type_label", "vt_text", "vt_color", "location"}
            ],
            "detection": str | None,         # EDR / Vision One verdict (model + score)
            "feed_sources": str | None,      # confirmed threat-feed sources
            "attribution": str | None,       # LLM 1-liner
            "prior_cases_note": str | None,  # LLM 1-liner
        }
    """
    enrichment = inc.enrichment or {}
    triage = enrichment.get("triage") or []
    ipinfo = enrichment.get("ipinfo") or []

    # Per-IOC threat-intel records — one row per real indicator + its reputation
    # (how the analyst reads it). The victim hostname (e.g. 'CSV-04') is an asset,
    # NOT an indicator, so it is never listed here. Highest-signal first; envelope
    # noise (own mail domain / safelinks / V1 portal) excluded.
    own = _own_domains()
    ipinfo_by_ip = {str(r.get("ip")): r for r in ipinfo if r.get("ip")}
    indicators: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in sorted(triage, key=_ioc_signal, reverse=True):
        q = entry.get("query") if isinstance(entry.get("query"), dict) else {}
        value = str(entry.get("ioc") or q.get("ioc") or entry.get("query") or "").strip()
        if not value or value in seen or _is_noise_ioc(value, own):
            continue
        seen.add(value)
        itype = str(q.get("type") or entry.get("type") or _infer_ioc_type(value)).lower()
        vt_text, vt_color = _vt_from_summary(entry.get("summary") or {}, itype)
        location = None
        if itype in ("ip", "ipv4", "ipv6"):
            r = ipinfo_by_ip.get(value)
            if r:
                location = " — ".join(p for p in (r.get("country"), r.get("org")) if p) or None
        indicators.append(
            {
                "value": value,
                "type_label": _TYPE_LABEL.get(itype, "Indicator"),
                "vt_text": vt_text,
                "vt_color": vt_color,
                "location": location,
            }
        )
        if len(indicators) >= 5:
            break

    # Authoritative threat-intel record from the richer enrichment the LLM prose
    # already cites (P3) but this table ignored: the EDR / Vision One detection
    # verdict and any confirmed threat-feed hits.
    detection: str | None = None
    wb = (enrichment.get("v1") or {}).get("workbench") or {}
    if wb.get("model"):
        detection = str(wb["model"])
        if wb.get("score") is not None:
            detection += f" — risk score {wb['score']}"

    feed_sources: str | None = None
    srcs: list[str] = []
    for m in (enrichment.get("threat_intel_matches") or [])[:4]:
        srcs.extend(s for s in (m.get("sources") or []) if s)
    if srcs:
        feed_sources = ", ".join(sorted(set(srcs))[:5])

    return {
        "indicators": indicators,
        "detection": detection,
        "feed_sources": feed_sources,
        "attribution": attribution,
        "prior_cases_note": prior_cases_note,
    }


async def _attached_incidents(session: AsyncSession, case_id: uuid.UUID) -> list[dict]:
    """Return the full attached-incident bundle for a case (source + extras),
    ordered by attached_at ascending."""
    rows = (
        await session.execute(
            select(
                Incident.id,
                Incident.case_number,
                Incident.title,
                Incident.severity,
                Incident.rule_name,
                Incident.source_product,
                Incident.created_at,
                CustomerCaseIncident.attached_at,
            )
            .join(CustomerCaseIncident, CustomerCaseIncident.incident_id == Incident.id)
            .where(CustomerCaseIncident.case_id == case_id)
            .order_by(CustomerCaseIncident.attached_at.asc())
        )
    ).all()
    return [
        {
            "incident_id": str(r.id),
            "case_number": r.case_number,
            "title": r.title,
            "severity": str(r.severity) if r.severity else None,
            "rule_name": r.rule_name,
            "source_product": r.source_product,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "attached_at": r.attached_at.isoformat() if r.attached_at else None,
        }
        for r in rows
    ]


async def _load_with_meta(
    session: AsyncSession, case_id: uuid.UUID
) -> tuple[CustomerCase, str | None, str | None, list[dict], str | None, str | None]:
    """Fetch case + tenant_name + source incident case_number + attached bundle +
    tenant routing fields (notification_email / _cc) for the Send modal."""
    row = (
        await session.execute(
            select(
                CustomerCase,
                Tenant.name.label("tenant_name"),
                Tenant.notification_email.label("t_email"),
                Tenant.notification_email_cc.label("t_email_cc"),
                Incident.case_number.label("src_cn"),
            )
            .join(Tenant, Tenant.id == CustomerCase.tenant_id, isouter=True)
            .join(Incident, Incident.id == CustomerCase.source_incident_id, isouter=True)
            .where(CustomerCase.id == case_id)
        )
    ).first()
    if not row:
        raise HTTPException(404, "case not found")
    bundle = await _attached_incidents(session, case_id)
    return row.CustomerCase, row.tenant_name, row.src_cn, bundle, row.t_email, row.t_email_cc


# ── SMTP status (must be declared before any /{case_id} route) ─────────────


@router.get("/smtp-status")
async def smtp_status(
    _user: Annotated[User, Depends(current_user)],
) -> dict:
    """Tell the UI whether the Send button is reachable. No sensitive data."""
    return {"configured": mailer.is_configured()}


# ── List ───────────────────────────────────────────────────────────────────


@router.get("")
async def list_cases(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    status_: CustomerCaseStatus | None = Query(default=None, alias="status"),
    customer: str | None = Query(default=None),
    q: str | None = Query(default=None, description="Free text on title + case_number"),
    sort: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> list[dict]:
    order = (asc if sort == "asc" else desc)(CustomerCase.created_at)
    stmt = (
        select(CustomerCase, Tenant.name.label("tenant_name"), Incident.case_number.label("src_cn"))
        .join(Tenant, Tenant.id == CustomerCase.tenant_id, isouter=True)
        .join(Incident, Incident.id == CustomerCase.source_incident_id, isouter=True)
        .where(_scope_clause_for_cases(scope))
        .order_by(order)
    )
    if status_:
        stmt = stmt.where(CustomerCase.status == status_)
    if customer:
        stmt = stmt.where(Tenant.name.ilike(f"%{customer}%"))
    if q:
        pat = f"%{q}%"
        stmt = stmt.where(
            or_(
                CustomerCase.title.ilike(pat),
                CustomerCase.case_number.ilike(pat),
            )
        )
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await session.execute(stmt)).all()
    return [_serialise(r.CustomerCase, r.tenant_name, r.src_cn) for r in rows]


# ── Create (promote from incident) ────────────────────────────────────────


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case(
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    """Body: { source_incident_id, locale? }. Creates a draft case linked to
    the source incident; also registers the join row so the case is bundle-ready.
    """
    src_id_raw = body.get("source_incident_id")
    if not src_id_raw:
        raise HTTPException(400, "source_incident_id is required")
    try:
        src_id = uuid.UUID(src_id_raw)
    except (ValueError, TypeError):
        raise HTTPException(400, "source_incident_id must be a UUID")

    inc = await session.get(Incident, src_id)
    if not inc:
        raise HTTPException(404, "source incident not found")
    require_in_scope(inc.tenant_id, scope)

    c = await create_case_for_incident(session, inc, user, locale=body.get("locale"), via="manual")
    case, tenant_name, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tenant_name, src_cn, bundle, t_email, t_cc)


async def create_case_for_incident(
    session: AsyncSession,
    inc: Incident,
    actor: User,
    *,
    locale: str | None = None,
    via: str = "manual",
) -> CustomerCase:
    """Create a DRAFT customer case linked to an incident (+ the M2M join row +
    audit). Shared by the create endpoint and the gate's 'Create case' action.
    Locale resolves explicit > tenant default > 'en'. Caller scopes the incident."""
    if not locale and inc.tenant_id:
        t = await session.get(Tenant, inc.tenant_id)
        locale = (t.locale if t else None) or "en"
    locale = locale or "en"

    c = CustomerCase(
        source_incident_id=inc.id,
        tenant_id=inc.tenant_id,
        status=CustomerCaseStatus.DRAFT,
        locale=locale,
        title=inc.title,  # seeded from the incident; analyst can edit
    )
    session.add(c)
    await session.flush()
    session.add(
        CustomerCaseIncident(
            case_id=c.id,
            incident_id=inc.id,
            attached_at=datetime.now(timezone.utc),
            attached_by_id=actor.id,
        )
    )
    await audit.log(
        session,
        user_id=actor.id,
        action="case.create",
        target_type="customer_case",
        target_id=c.id,
        tenant_id=c.tenant_id,
        diff={
            "case_number": c.case_number,
            "source_incident": inc.case_number,
            "locale": locale,
            "via": via,
        },
    )
    await session.flush()
    return c


# ── Detail / Edit / Status transition ────────────────────────────────────


@router.get("/{case_id}")
async def get_case(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    c, tenant_name, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, case_id)
    require_in_scope(c.tenant_id, scope)
    return _serialise(c, tenant_name, src_cn, bundle, t_email, t_cc)


_EDITABLE_FIELDS = {
    "title",
    "locale",
    "incident_analysis",
    "attack_type_label",
    "critical_impact_summary",
    "recommended_actions",
    "actions_taken",
    "threat_intel_summary",
}


@router.patch("/{case_id}")
async def patch_case(
    case_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)

    if c.status == CustomerCaseStatus.SENT:
        raise HTTPException(409, "sent cases are immutable; re-open first")

    changed: dict = {}
    for k, v in body.items():
        if k not in _EDITABLE_FIELDS:
            continue
        if getattr(c, k) != v:
            changed[k] = v
            setattr(c, k, v)
    if not changed:
        # Nothing to do — still load + return so the UI stays consistent
        case, tenant_name, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
        return _serialise(case, tenant_name, src_cn, bundle, t_email, t_cc)

    await audit.log(
        session,
        user_id=user.id,
        action="case.patch",
        target_type="customer_case",
        target_id=c.id,
        tenant_id=c.tenant_id,
        diff={"case_number": c.case_number, "fields": list(changed.keys())},
    )
    await session.flush()
    case, tenant_name, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tenant_name, src_cn, bundle, t_email, t_cc)


_ALLOWED_TRANSITIONS = {
    CustomerCaseStatus.DRAFT: {CustomerCaseStatus.REVIEWED},
    CustomerCaseStatus.REVIEWED: {CustomerCaseStatus.DRAFT},  # re-open
    CustomerCaseStatus.SENT: {CustomerCaseStatus.DRAFT},  # re-open a sent case
}


@router.post("/{case_id}/status")
async def set_status(
    case_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    """Body: {status: 'draft'|'reviewed'} — 'sent' is Phase-CC5 (SMTP) only."""
    raw = body.get("status")
    try:
        target = CustomerCaseStatus(raw)
    except ValueError:
        raise HTTPException(400, f"invalid status: {raw!r}")
    # The 'sent' state is reachable only via the dedicated send endpoint
    # (Phase-CC5). Refuse it here so a sloppy PATCH can't bypass SMTP.
    if target == CustomerCaseStatus.SENT:
        raise HTTPException(400, "use POST /customer-cases/{id}/send to mark sent")

    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)

    if target == c.status:
        case, tn, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
        return _serialise(case, tn, src_cn, bundle, t_email, t_cc)
    if target not in _ALLOWED_TRANSITIONS.get(c.status, set()):
        raise HTTPException(409, f"invalid transition: {c.status} → {target}")

    prev = c.status
    c.status = target
    if target == CustomerCaseStatus.DRAFT and prev == CustomerCaseStatus.SENT:
        # re-open clears the send snapshot so it doesn't look like it's still out
        c.sent_at = None
        c.sent_by_id = None
        c.sent_recipients_to = None
        c.sent_recipients_cc = None
        c.sent_subject = None

    await audit.log(
        session,
        user_id=user.id,
        action="case.status",
        target_type="customer_case",
        target_id=c.id,
        tenant_id=c.tenant_id,
        diff={"case_number": c.case_number, "from": str(prev), "to": str(target)},
    )
    await session.flush()
    case, tenant_name, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tenant_name, src_cn, bundle, t_email, t_cc)


# ── LLM customer-facing synthesis (Phase-CC2) ────────────────────────────


@router.post("/{case_id}/llm-generate")
async def llm_generate(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    force: Annotated[bool, Body(embed=True)] = False,
) -> dict:
    """Generate (or regenerate) the customer-facing fields for this case
    using the LLM, in the case's locale. Overwrites all six text fields on
    success. Refuses if the case has been sent (re-open first).
    """
    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)
    if c.status == CustomerCaseStatus.SENT:
        raise HTTPException(409, "sent cases are immutable; re-open first")
    if c.body_source == "edited" and not force:
        raise HTTPException(
            409,
            "case has analyst HTML edits — regenerating discards them; confirm to proceed",
        )

    # Pull the source incident + tenant for the briefing
    inc = await session.get(Incident, c.source_incident_id)
    if not inc:
        raise HTTPException(409, "source incident no longer exists")
    tenant_name = None
    if c.tenant_id:
        t = await session.get(Tenant, c.tenant_id)
        tenant_name = t.name if t else None

    system = customer_prompt.system_prompt(c.locale or "en")
    user_msg = customer_prompt.build_user_prompt(
        case_number=c.case_number,
        incident_case_number=inc.case_number,
        incident_title=inc.title,
        customer_name=tenant_name,
        normalized=inc.normalized,
        enrichment=inc.enrichment,
        analyst_report_markdown=inc.llm_report_markdown,
    )

    result = await llm_client.complete(system=system, user=user_msg)

    # Persist transcript on the *source* incident's call history so the
    # analyst sees all LLM activity per incident in one place.
    from ..db.enums import LLMStatus
    from ..db.models import LLMCall
    from ..settings import settings as _s

    keep_transcripts = bool(getattr(_s, "log_llm_transcripts", True))
    session.add(
        LLMCall(
            incident_id=c.source_incident_id,
            purpose="customer_brief",
            model=result.model,
            provider=result.provider,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            latency_ms=result.latency_ms,
            status=LLMStatus(result.status),
            prompt_hash=result.prompt_hash,
            created_at=datetime.now(timezone.utc),
            system_prompt=(result.system_prompt if keep_transcripts else None),
            user_prompt=(result.user_prompt if keep_transcripts else None),
            response_text=(result.text if keep_transcripts else None),
            error=result.error,
        )
    )

    if result.status != "ok":
        raise HTTPException(502, f"LLM {result.status}: {result.error or 'no detail'}")

    try:
        fields = customer_prompt.parse_llm_json(result.text)
    except ValueError as e:
        raise HTTPException(502, f"LLM returned unparseable JSON: {e}")

    # Apply the new fields
    c.title = fields.get("title") or c.title
    c.attack_type_label = fields.get("attack_type_label") or None
    c.incident_analysis = fields.get("incident_analysis") or None
    c.critical_impact_summary = fields.get("critical_impact_summary") or None
    c.recommended_actions = fields.get("recommended_actions") or []
    # What the SOC already did — grounded in the gate's executed actions (the LLM
    # is instructed to restate ONLY the briefing's "Actions already taken" list).
    c.actions_taken = fields.get("actions_taken") or []
    # Legacy paragraph field — newer prompts no longer produce it, but if
    # an older model still returns it we preserve it for back-compat.
    c.threat_intel_summary = fields.get("threat_intel_summary") or None
    # New structured one-liners that sit below the rendered TI table.
    c.attribution = fields.get("attribution") or None
    c.prior_cases_note = fields.get("prior_cases_note") or None
    # Fresh fields supersede any prior analyst HTML edit.
    c.body_source = "generated"
    c.edited_html = None

    await audit.log(
        session,
        user_id=user.id,
        action="case.llm_generate",
        target_type="customer_case",
        target_id=c.id,
        tenant_id=c.tenant_id,
        diff={
            "case_number": c.case_number,
            "locale": c.locale,
            "model": result.model,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "latency_ms": result.latency_ms,
        },
    )
    await session.flush()
    case, tn, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tn, src_cn, bundle, t_email, t_cc)


@router.post("/{case_id}/body")
async def save_body(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    html: Annotated[str | None, Body(embed=True)] = None,
) -> dict:
    """Store analyst-edited HTML for the customer notification. Preview + send
    then use it verbatim (sanitized on send) until the case is regenerated.
    Empty html clears the override and reverts to field-rendered output."""
    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)
    if c.status == CustomerCaseStatus.SENT:
        raise HTTPException(409, "sent cases are immutable; re-open first")

    body = (html or "").strip()
    c.edited_html = body or None
    c.body_source = "edited" if body else "generated"
    await session.flush()
    case, tn, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tn, src_cn, bundle, t_email, t_cc)


# ── HTML preview (Phase-CC3) ─────────────────────────────────────────────


@router.get("/{case_id}/preview", response_class=Response)
async def preview_html(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> Response:
    """Server-rendered HTML notification — exactly what the customer will see."""
    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)

    # Analyst HTML override wins — show exactly what will be sent.
    if c.body_source == "edited" and c.edited_html:
        return Response(content=c.edited_html, media_type="text/html; charset=utf-8")

    inc = await session.get(Incident, c.source_incident_id)
    if not inc:
        raise HTTPException(409, "source incident no longer exists")

    customer_name = None
    if c.tenant_id:
        t = await session.get(Tenant, c.tenant_id)
        customer_name = t.name if t else None

    # The template needs lightweight, pre-formatted dicts (Jinja shouldn't
    # poke at ORM objects). Build them here.
    case_ctx = {
        "case_number": c.case_number,
        "title": c.title,
        "locale": c.locale,
        "incident_analysis": c.incident_analysis,
        "attack_type_label": c.attack_type_label,
        "critical_impact_summary": c.critical_impact_summary,
        "recommended_actions": c.recommended_actions or [],
        "actions_taken": c.actions_taken or [],
        # Legacy paragraph (only renders if no structured TI table data)
        "threat_intel_summary": c.threat_intel_summary,
    }
    incident_ctx = {
        "severity": str(inc.severity) if inc.severity else None,
        "rule_name": inc.rule_name,
        "source_product": inc.source_product,
        "created_at_pretty": inc.created_at.strftime("%Y-%m-%d %H:%M UTC")
        if inc.created_at
        else None,
    }
    threat_intel_ctx = _build_threat_intel_ctx(inc, c.attribution, c.prior_cases_note)

    bundle = await _attached_incidents(session, c.id)

    html = jinja_env.get_template("customer_notification.html.j2").render(
        case=case_ctx,
        incident=incident_ctx,
        threat_intel=threat_intel_ctx,
        attached_incidents=bundle,
        customer_name=customer_name,
        labels=labels_for(c.locale),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    return Response(content=html, media_type="text/html; charset=utf-8")


# ── Incident bundling (Phase-CC4) ────────────────────────────────────────


@router.get("/{case_id}/related-incidents")
async def related_incidents(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    q: str | None = Query(default=None, description="Free-text on title / rule / case_number"),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict]:
    """Candidate incidents to attach: same tenant as the case, not yet attached,
    matching the optional free-text query. Limited to keep the UI snappy."""
    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)

    # Exclude already-attached incidents
    attached = select(CustomerCaseIncident.incident_id).where(
        CustomerCaseIncident.case_id == case_id
    )

    stmt = (
        select(
            Incident.id,
            Incident.case_number,
            Incident.title,
            Incident.severity,
            Incident.rule_name,
            Incident.created_at,
        )
        .where(Incident.id.notin_(attached))
        .where(Incident.tenant_id == c.tenant_id if c.tenant_id else Incident.tenant_id.is_(None))
        .where(scope_clause_for_incidents(scope))
        .order_by(desc(Incident.created_at))
        .limit(limit)
    )
    if q:
        pat = f"%{q}%"
        stmt = stmt.where(
            or_(
                Incident.title.ilike(pat),
                Incident.rule_name.ilike(pat),
                Incident.case_number.ilike(pat),
            )
        )

    rows = (await session.execute(stmt)).all()
    return [
        {
            "incident_id": str(r.id),
            "case_number": r.case_number,
            "title": r.title,
            "severity": str(r.severity) if r.severity else None,
            "rule_name": r.rule_name,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("/{case_id}/incidents", status_code=status.HTTP_201_CREATED)
async def attach_incident(
    case_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    """Body: { incident_id }. Attaches an incident from the same tenant."""
    raw = body.get("incident_id")
    if not raw:
        raise HTTPException(400, "incident_id is required")
    try:
        incident_id = uuid.UUID(raw)
    except (ValueError, TypeError):
        raise HTTPException(400, "incident_id must be a UUID")

    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)
    if c.status == CustomerCaseStatus.SENT:
        raise HTTPException(409, "sent cases are immutable; re-open first")

    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    # Scope check first — if the user can't see this incident, treat it as
    # not found rather than leaking that it belongs to another tenant.
    require_in_scope(inc.tenant_id, scope)
    if inc.tenant_id != c.tenant_id:
        raise HTTPException(409, "incident belongs to a different tenant")

    # Reject duplicates explicitly so the UI gets a clear 409 instead of a
    # generic DB integrity error.
    existing = await session.scalar(
        select(CustomerCaseIncident.id).where(
            CustomerCaseIncident.case_id == case_id,
            CustomerCaseIncident.incident_id == incident_id,
        )
    )
    if existing:
        raise HTTPException(409, "incident already attached to this case")

    session.add(
        CustomerCaseIncident(
            case_id=case_id,
            incident_id=incident_id,
            attached_at=datetime.now(timezone.utc),
            attached_by_id=user.id,
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="case.attach_incident",
        target_type="customer_case",
        target_id=case_id,
        tenant_id=c.tenant_id,
        diff={"case_number": c.case_number, "incident_case_number": inc.case_number},
    )
    await session.flush()
    case, tn, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tn, src_cn, bundle, t_email, t_cc)


@router.delete("/{case_id}/incidents/{incident_id}", status_code=204)
async def detach_incident(
    case_id: uuid.UUID,
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
):
    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)
    if c.status == CustomerCaseStatus.SENT:
        raise HTTPException(409, "sent cases are immutable; re-open first")

    # Cannot detach the source incident — that would orphan the case.
    if incident_id == c.source_incident_id:
        raise HTTPException(409, "cannot detach the source incident")

    m = await session.scalar(
        select(CustomerCaseIncident).where(
            CustomerCaseIncident.case_id == case_id,
            CustomerCaseIncident.incident_id == incident_id,
        )
    )
    if not m:
        raise HTTPException(404, "attachment not found")
    await audit.log(
        session,
        user_id=user.id,
        action="case.detach_incident",
        target_type="customer_case",
        target_id=case_id,
        tenant_id=c.tenant_id,
        diff={"case_number": c.case_number, "detached_incident_id": str(incident_id)},
    )
    await session.delete(m)


# ── Send via SMTP (Phase-CC5) ────────────────────────────────────────────


async def _render_case_html(session: AsyncSession, c: CustomerCase) -> str:
    """Render the case to HTML using the same path as the preview endpoint.
    Returns the HTML string."""
    inc = await session.get(Incident, c.source_incident_id)
    if not inc:
        raise HTTPException(409, "source incident no longer exists")

    customer_name = None
    if c.tenant_id:
        t = await session.get(Tenant, c.tenant_id)
        customer_name = t.name if t else None

    case_ctx = {
        "case_number": c.case_number,
        "title": c.title,
        "locale": c.locale,
        "incident_analysis": c.incident_analysis,
        "attack_type_label": c.attack_type_label,
        "critical_impact_summary": c.critical_impact_summary,
        "recommended_actions": c.recommended_actions or [],
        "actions_taken": c.actions_taken or [],
        "threat_intel_summary": c.threat_intel_summary,
    }
    incident_ctx = {
        "severity": str(inc.severity) if inc.severity else None,
        "rule_name": inc.rule_name,
        "source_product": inc.source_product,
        "created_at_pretty": inc.created_at.strftime("%Y-%m-%d %H:%M UTC")
        if inc.created_at
        else None,
    }
    threat_intel_ctx = _build_threat_intel_ctx(inc, c.attribution, c.prior_cases_note)
    bundle = await _attached_incidents(session, c.id)
    return jinja_env.get_template("customer_notification.html.j2").render(
        case=case_ctx,
        incident=incident_ctx,
        threat_intel=threat_intel_ctx,
        attached_incidents=bundle,
        customer_name=customer_name,
        labels=labels_for(c.locale),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


@router.post("/{case_id}/send")
async def send_case(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    subject: Annotated[str | None, Body(embed=True)] = None,
) -> dict:
    """Email the case to the tenant's configured notification address(es).
    TO / CC are derived from the tenant; the analyst MAY override the subject
    at send time (falls back to the derived subject when omitted/blank)."""
    if not mailer.is_configured():
        raise HTTPException(503, "Email sending is not configured on this deployment")

    c = await session.get(CustomerCase, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    require_in_scope(c.tenant_id, scope)
    if c.status == CustomerCaseStatus.SENT:
        raise HTTPException(409, "case has already been sent; re-open to send again")

    if c.tenant_id is None:
        raise HTTPException(409, "case has no tenant — assign one before sending")

    t = await session.get(Tenant, c.tenant_id)
    if not t or not t.notification_email:
        raise HTTPException(409, f"tenant has no notification_email configured")

    inc = await session.get(Incident, c.source_incident_id)
    if not inc:
        raise HTTPException(409, "source incident no longer exists")
    # Analyst override wins; otherwise the derived "<CASE> - <CUSTOMER> - <USE CASE>".
    subject = (subject or "").strip() or _notification_subject(c, t.name if t else None)

    cc_list = [a.strip() for a in (t.notification_email_cc or "").split(",") if a.strip()]
    if c.body_source == "edited" and c.edited_html:
        html = html_sanitize.sanitize_email_html(c.edited_html)
    else:
        html = await _render_case_html(session, c)

    try:
        await mailer.send_html_email(
            to=t.notification_email,
            cc=cc_list,
            subject=subject,
            html_body=html,
        )
    except mailer.MailNotConfigured:
        # Should be impossible after the is_configured() check above, but be safe.
        raise HTTPException(503, "Email backend became unavailable mid-flight")
    except Exception as e:
        # Don't change case state on transport failure — let the analyst retry.
        raise HTTPException(502, f"Email send failed: {e}")

    # Success — record snapshot + transition
    now = datetime.now(timezone.utc)
    c.status = CustomerCaseStatus.SENT
    c.sent_at = now
    c.sent_by_id = user.id
    c.sent_recipients_to = t.notification_email
    c.sent_recipients_cc = ", ".join(cc_list) if cc_list else None
    c.sent_subject = subject

    await audit.log(
        session,
        user_id=user.id,
        action="case.sent",
        target_type="customer_case",
        target_id=c.id,
        tenant_id=c.tenant_id,
        diff={
            "case_number": c.case_number,
            "to": t.notification_email,
            "cc": cc_list or None,
            "subject": subject,
        },
    )
    await session.flush()
    case, tn, src_cn, bundle, t_email, t_cc = await _load_with_meta(session, c.id)
    return _serialise(case, tn, src_cn, bundle, t_email, t_cc)


# ══════════════════════════════════════════════════════════════════════════
# Case collaboration (Feature 8): comments, @mentions, watchers
#
# Comments are append-only; @mentions + watchers drive in-app notifications
# (notify.py / B1). Reads are viewer-visible (current_user + scope); writes
# require an analyst. Nothing here touches the customer — purely internal SOC
# collaboration on the case record.
# ══════════════════════════════════════════════════════════════════════════


async def _case_in_scope(
    session: AsyncSession, case_id: uuid.UUID, scope: TenantScope
) -> CustomerCase:
    c = await session.get(CustomerCase, case_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    require_in_scope(c.tenant_id, scope)
    return c


async def _mentionable_users(session: AsyncSession) -> list[dict]:
    """Active SOC users (the mention/watch roster). Users are internal staff,
    not customers, so the whole active roster is mentionable."""
    rows = (
        await session.execute(
            select(User.id, User.full_name, User.email)
            .where(User.status == UserStatus.ACTIVE)
            .order_by(User.full_name, User.email)
        )
    ).all()
    return [{"id": str(r.id), "full_name": r.full_name, "email": r.email} for r in rows]


async def _watcher_ids(session: AsyncSession, case_id: uuid.UUID) -> list[str]:
    rows = (
        (await session.execute(select(CaseWatcher.user_id).where(CaseWatcher.case_id == case_id)))
        .scalars()
        .all()
    )
    return [str(u) for u in rows]


async def _ensure_watchers(session: AsyncSession, case_id: uuid.UUID, user_ids) -> None:
    """Idempotently add watchers (dedup against existing rows + the unique key)."""
    existing = set(await _watcher_ids(session, case_id))
    for raw in user_ids:
        uid = str(raw)
        if uid and uid not in existing:
            existing.add(uid)
            session.add(CaseWatcher(case_id=case_id, user_id=uuid.UUID(uid)))


def _comment_out(c: CaseComment, full_name: str | None, email: str | None) -> dict:
    return {
        "id": str(c.id),
        "body": c.body,
        "mentions": c.mentions or [],
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "author": {"full_name": full_name, "email": email},
    }


@router.get("/{case_id}/mentionable-users")
async def mentionable_users(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    await _case_in_scope(session, case_id, scope)
    return await _mentionable_users(session)


@router.get("/{case_id}/comments")
async def list_comments(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    await _case_in_scope(session, case_id, scope)
    rows = (
        await session.execute(
            select(CaseComment, User.full_name, User.email)
            .join(User, User.id == CaseComment.author_id, isouter=True)
            .where(CaseComment.case_id == case_id)
            .order_by(asc(CaseComment.created_at))
        )
    ).all()
    return [_comment_out(c, fn, em) for c, fn, em in rows]


@router.post("/{case_id}/comments", status_code=status.HTTP_201_CREATED)
async def add_comment(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    body: Annotated[str, Body(embed=True)],
) -> dict:
    """Post a comment. @mentions notify the named users in-app (and auto-watch
    them) AND email each of them; existing watchers get a 'commented' in-app
    notification. The author auto-watches."""
    c = await _case_in_scope(session, case_id, scope)
    body = (body or "").strip()
    if not body:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "comment body is required")

    roster = await _mentionable_users(session)
    mentioned = mentions.parse_mentions(body, roster)
    existing_watchers = await _watcher_ids(session, case_id)  # before we add new ones

    comment = CaseComment(case_id=case_id, author_id=user.id, body=body, mentions=mentioned or None)
    session.add(comment)
    await _ensure_watchers(session, case_id, [str(user.id), *mentioned])

    link = f"/cases/{case_id}"
    who = user.full_name or user.email
    preview = body[:140]
    # Mentions are the high-signal notification.
    await notify.notify_users(
        session,
        mentioned,
        kind="mention",
        title=f"{who} mentioned you on {c.case_number}",
        link=link,
        body=preview,
        actor_id=user.id,
    )
    # Email each mentioned user (feature 8) — always, to their own address, from
    # the configured mailbox. Sent from the worker so the comment POST stays
    # instant; enqueue failure is best-effort (the in-app notification still fired).
    if mentioned:
        id_to_email = {u["id"]: u["email"] for u in roster if u.get("email")}
        recipients = [id_to_email[m] for m in mentioned if id_to_email.get(m)]
        if recipients:
            public = (settings.isoc_public_url or "").rstrip("/")
            try:
                await arq.enqueue_job(
                    "send_mention_emails",
                    {
                        "to": recipients,
                        "author": who,
                        "case_number": c.case_number,
                        "url": f"{public}/cases/{case_id}" if public else "",
                        "preview": preview,
                        "subject": f"You were mentioned on {c.case_number}",
                    },
                )
            except Exception:
                pass  # best-effort: never fail the comment on a queue hiccup

    # Existing watchers (not just-mentioned, not the author) get a comment ping.
    watch_only = [w for w in existing_watchers if w not in set(mentioned)]
    await notify.notify_users(
        session,
        watch_only,
        kind="comment",
        title=f"{who} commented on {c.case_number}",
        link=link,
        body=preview,
        actor_id=user.id,
    )
    await audit.log(
        session,
        user_id=user.id,
        action="case.comment",
        target_type="customer_case",
        target_id=case_id,
        tenant_id=c.tenant_id,
        diff={"mentions": mentioned, "chars": len(body)},
    )
    await session.flush()
    return _comment_out(comment, user.full_name, user.email)


@router.get("/{case_id}/watchers")
async def list_watchers(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    await _case_in_scope(session, case_id, scope)
    rows = (
        await session.execute(
            select(CaseWatcher.user_id, User.full_name, User.email)
            .join(User, User.id == CaseWatcher.user_id)
            .where(CaseWatcher.case_id == case_id)
            .order_by(User.full_name, User.email)
        )
    ).all()
    return [{"user_id": str(uid), "full_name": fn, "email": em} for uid, fn, em in rows]


@router.post("/{case_id}/watchers", status_code=status.HTTP_201_CREATED)
async def add_watcher(
    case_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    user_id: Annotated[uuid.UUID | None, Body(embed=True)] = None,
) -> dict:
    """Watch the case. Defaults to self; pass user_id to add a teammate."""
    await _case_in_scope(session, case_id, scope)
    target = user_id or user.id
    if await session.get(User, target) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    await _ensure_watchers(session, case_id, [str(target)])
    return {"ok": True, "user_id": str(target)}


@router.delete("/{case_id}/watchers/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_watcher(
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> Response:
    await _case_in_scope(session, case_id, scope)
    w = (
        await session.execute(
            select(CaseWatcher).where(
                CaseWatcher.case_id == case_id, CaseWatcher.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    if w is not None:
        await session.delete(w)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
