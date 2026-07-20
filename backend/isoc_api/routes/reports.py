"""Reports API — monthly summaries, customer breakdowns, CSV export, and the
branded automated reports (Feature 7): tenant branding, template picker,
generate-to-draft, HTML/PDF, analyst-gated send, and schedule CRUD."""

from __future__ import annotations

import asyncio
import calendar
import csv
import io
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, mailer
from ..auth.deps import current_user, require_analyst
from ..auth.tenancy import (
    TenantScope,
    current_tenant_scope,
    require_in_scope,
    scope_clause_for_incidents,
)
from ..db.models import GeneratedReport, Incident, ReportSchedule, Tenant, TenantBranding, User
from ..db.session import get_session
from ..reports import gather as report_gather
from ..reports import periods, registry, render, service

router = APIRouter()

# Accepted logo image types (WeasyPrint rasterises PNG/JPEG; SVG is vector).
_LOGO_MIME = {"image/png", "image/jpeg", "image/svg+xml"}
_LOGO_MAX_BYTES = 512 * 1024
_HEX_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _month_bounds(year: int, month: int) -> tuple[datetime, datetime]:
    last_day = calendar.monthrange(year, month)[1]
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc)
    return start, end


@router.get("/customers")
async def list_customers(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    year: int | None = Query(default=None),
    month: int | None = Query(default=None),
) -> list[dict]:
    """All customers with incident counts. Optionally filtered to a month."""
    q = (
        select(
            Incident.customer,
            func.count(Incident.id).label("total"),
            func.sum(case((Incident.verdict == "TP", 1), else_=0)).label("tp"),
            func.sum(case((Incident.verdict == "FP", 1), else_=0)).label("fp"),
            func.sum(case((Incident.verdict == "benign", 1), else_=0)).label("benign"),
            func.avg(func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0).label(
                "avg_sla_minutes"
            ),
        )
        .where(scope_clause_for_incidents(scope))
        .group_by(Incident.customer)
        .order_by(func.count(Incident.id).desc())
    )

    if year and month:
        start, end = _month_bounds(year, month)
        q = q.where(Incident.created_at >= start, Incident.created_at <= end)

    rows = (await session.execute(q)).all()
    return [
        {
            "customer": r.customer or "Unknown",
            "total": int(r.total),
            "tp": int(r.tp or 0),
            "fp": int(r.fp or 0),
            "benign": int(r.benign or 0),
            "avg_sla_minutes": round(float(r.avg_sla_minutes), 1) if r.avg_sla_minutes else None,
        }
        for r in rows
    ]


@router.get("/monthly")
async def monthly_summary(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    year: int = Query(default_factory=lambda: datetime.now(timezone.utc).year),
    month: int = Query(default_factory=lambda: datetime.now(timezone.utc).month),
    customer: str | None = Query(default=None),
) -> dict:
    """Full monthly summary for a given month and optional customer filter.

    Delegates to reports.gather.gather_monthly_stats — the single source of the
    monthly aggregation, also consumed by the Feature-7 report generator so the
    numbers on a report match the dashboard exactly."""
    return await report_gather.gather_monthly_stats(session, scope, year, month, customer)


@router.get("/export/csv")
async def export_csv(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    year: int = Query(default_factory=lambda: datetime.now(timezone.utc).year),
    month: int = Query(default_factory=lambda: datetime.now(timezone.utc).month),
    customer: str | None = Query(default=None),
) -> StreamingResponse:
    """Download incidents for a month as CSV."""
    start, end = _month_bounds(year, month)
    q = (
        select(
            Incident.case_number,
            Incident.title,
            Incident.customer,
            Incident.status,
            Incident.severity,
            Incident.verdict,
            Incident.source_product,
            Incident.rule_name,
            Incident.created_at,
            Incident.closed_at,
            Incident.llm_input_tokens,
            Incident.llm_output_tokens,
        )
        .where(
            Incident.created_at >= start,
            Incident.created_at <= end,
            scope_clause_for_incidents(scope),
        )
        .order_by(Incident.created_at)
    )
    if customer:
        q = q.where(Incident.customer == customer)

    rows = (await session.execute(q)).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "case_number",
            "title",
            "customer",
            "status",
            "severity",
            "verdict",
            "source_product",
            "rule_name",
            "created_at",
            "closed_at",
            "llm_input_tokens",
            "llm_output_tokens",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r.case_number,
                r.title,
                r.customer or "",
                r.status,
                r.severity,
                r.verdict,
                r.source_product or "",
                r.rule_name or "",
                r.created_at.isoformat() if r.created_at else "",
                r.closed_at.isoformat() if r.closed_at else "",
                r.llm_input_tokens or 0,
                r.llm_output_tokens or 0,
            ]
        )

    fname = f"isoc-report-{year}-{month:02d}"
    if customer:
        fname += f"-{customer.lower().replace(' ', '_')}"
    fname += ".csv"

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ══════════════════════════════════════════════════════════════════════════
# Feature 7 — branded automated reports
#
# Invariant: the scheduler + these endpoints only ever GENERATE to a draft and
# RENDER; the sole outbound action (send) is analyst-gated (require_analyst) and
# never fires automatically.
# ══════════════════════════════════════════════════════════════════════════


def _report_summary(r: GeneratedReport) -> dict:
    """History-list view of a report row (never includes the HTML body)."""
    return {
        "id": str(r.id),
        "tenant_id": str(r.tenant_id) if r.tenant_id else None,
        "schedule_id": str(r.schedule_id) if r.schedule_id else None,
        "template_key": r.template_key,
        "title": r.title,
        "status": r.status,
        "period_start": r.period_start.isoformat() if r.period_start else None,
        "period_end": r.period_end.isoformat() if r.period_end else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "sent_at": r.sent_at.isoformat() if r.sent_at else None,
        "sent_to": r.sent_to,
    }


def _schedule_summary(s: ReportSchedule) -> dict:
    return {
        "id": str(s.id),
        "tenant_id": str(s.tenant_id) if s.tenant_id else None,
        "template_key": s.template_key,
        "cadence": s.cadence,
        "enabled": s.enabled,
        "auto_send": s.auto_send,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
    }


async def _require_tenant_in_scope(
    session: AsyncSession, tenant_id: uuid.UUID | None, scope: TenantScope
) -> None:
    """404 if the tenant is out of scope or doesn't exist. tenant_id None is
    allowed only for unrestricted (admin) scope — an all-scope report."""
    if tenant_id is None:
        if scope is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "all-scope reports require admin scope")
        return
    require_in_scope(tenant_id, scope)
    if await session.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")


# ── Templates ─────────────────────────────────────────────────────────────
@router.get("/templates")
async def list_report_templates(_user: Annotated[User, Depends(current_user)]) -> list[dict]:
    """The built-in report templates for the picker."""
    return registry.list_templates()


@router.get("/tenants")
async def list_report_tenants(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    """In-scope tenants (id + name) for the report tenant/branding picker."""
    q = select(Tenant.id, Tenant.name).order_by(Tenant.name)
    if scope is not None:
        if not scope:
            return []
        q = q.where(Tenant.id.in_(scope))
    rows = (await session.execute(q)).all()
    return [{"id": str(r.id), "name": r.name} for r in rows]


# ── Branding (B2) ───────────────────────────────────────────────────────────
@router.get("/branding")
async def get_branding(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    tenant_id: uuid.UUID = Query(...),
) -> dict:
    """The tenant's report branding (accent + whether a logo is set)."""
    require_in_scope(tenant_id, scope)
    b = await session.get(TenantBranding, tenant_id)
    return {
        "tenant_id": str(tenant_id),
        "accent_color": b.accent_color if b else None,
        "display_name": b.display_name if b else None,
        "has_logo": bool(b and b.logo_bytes),
        "logo_mime": b.logo_mime if b else None,
    }


@router.put("/branding")
async def put_branding(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    tenant_id: Annotated[uuid.UUID, Form()],
    accent_color: Annotated[str | None, Form()] = None,
    display_name: Annotated[str | None, Form()] = None,
    logo: Annotated[UploadFile | None, File()] = None,
) -> dict:
    """Upsert a tenant's report branding. Multipart: accent_color (#RRGGBB),
    display_name, and/or a logo image (PNG/JPEG/SVG, ≤512KB). Omitted fields are
    left unchanged; only a newly-uploaded logo replaces the stored one."""
    await _require_tenant_in_scope(session, tenant_id, scope)
    if accent_color and not _HEX_RE.match(accent_color):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "accent_color must be #RRGGBB hex")

    b = await session.get(TenantBranding, tenant_id)
    if b is None:
        b = TenantBranding(tenant_id=tenant_id)
        session.add(b)
    if accent_color is not None:
        b.accent_color = accent_color or None
    if display_name is not None:
        b.display_name = display_name.strip() or None
    if logo is not None:
        data = await logo.read()
        if len(data) > _LOGO_MAX_BYTES:
            raise HTTPException(413, f"logo exceeds {_LOGO_MAX_BYTES // 1024}KB")
        mime = (logo.content_type or "image/png").split(";")[0].strip()
        if mime not in _LOGO_MIME:
            raise HTTPException(415, f"logo must be PNG, JPEG or SVG (got {mime})")
        b.logo_bytes = data
        b.logo_mime = mime
    b.updated_by_id = user.id
    await audit.log(
        session,
        user_id=user.id,
        action="report.branding_update",
        target_type="tenant_branding",
        target_id=tenant_id,
        tenant_id=tenant_id,
        diff={"accent_color": b.accent_color, "logo_updated": logo is not None},
    )
    return {"ok": True, "tenant_id": str(tenant_id), "has_logo": bool(b.logo_bytes)}


@router.get("/branding/{tenant_id}/logo")
async def get_branding_logo(
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> Response:
    """Raw logo bytes for the UI preview."""
    require_in_scope(tenant_id, scope)
    b = await session.get(TenantBranding, tenant_id)
    if not b or not b.logo_bytes:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no logo set")
    return Response(content=b.logo_bytes, media_type=b.logo_mime or "image/png")


# ── Generate (on-demand → draft) ─────────────────────────────────────────────
@router.post("/generate")
async def generate_report(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    template_key: Annotated[str, Body()],
    tenant_id: Annotated[uuid.UUID | None, Body()] = None,
    year: Annotated[int | None, Body()] = None,
    month: Annotated[int | None, Body()] = None,
) -> dict:
    """Render a report for a month (default: current) and store it as a DRAFT.
    A `tenant_id` scopes the report to one customer (and layers their branding);
    omit it, with admin scope, for an all-customer report."""
    if not registry.is_valid(template_key):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown template '{template_key}'")
    await _require_tenant_in_scope(session, tenant_id, scope)

    now = datetime.now(timezone.utc)
    year = year or now.year
    month = month or now.month
    if not (1 <= month <= 12):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "month must be 1–12")
    start, end, label, kind = report_gather.month_window(year, month)

    # Narrow the incident scope to the single tenant for a per-customer report.
    report_scope: TenantScope = {tenant_id} if tenant_id else scope
    row = await service.generate_report(
        session,
        scope=report_scope,
        template_key=template_key,
        tenant_id=tenant_id,
        start=start,
        end=end,
        label=label,
        kind=kind,
        generated_by_id=user.id,
    )
    await audit.log(
        session,
        user_id=user.id,
        action="report.generate",
        target_type="generated_report",
        target_id=row.id,
        tenant_id=tenant_id,
        diff={"template_key": template_key, "period": label},
    )
    return _report_summary(row)


# ── History + artifacts ───────────────────────────────────────────────────
@router.get("/generated")
async def list_generated(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    tenant_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict]:
    """Generated-report history, newest first, tenant-scoped."""
    q = select(GeneratedReport).order_by(GeneratedReport.created_at.desc()).limit(limit)
    if scope is not None:
        # Non-admins never see all-scope (tenant_id NULL) reports.
        q = q.where(GeneratedReport.tenant_id.in_(scope))
    if tenant_id is not None:
        require_in_scope(tenant_id, scope)
        q = q.where(GeneratedReport.tenant_id == tenant_id)
    rows = (await session.execute(q)).scalars().all()
    return [_report_summary(r) for r in rows]


@router.get("/generated/{report_id}/html")
async def get_report_html(
    report_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> HTMLResponse:
    """The rendered HTML — for in-app preview."""
    row = await service.scope_visible_report(session, report_id, scope)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return HTMLResponse(content=row.html or "<p>Empty report.</p>")


@router.get("/generated/{report_id}/pdf")
async def get_report_pdf(
    report_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> Response:
    """The report as a PDF (rendered on the fly from the stored HTML)."""
    row = await service.scope_visible_report(session, report_id, scope)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    if not row.html:
        raise HTTPException(status.HTTP_409_CONFLICT, "report has no rendered content")
    try:
        pdf = await asyncio.to_thread(render.html_to_pdf, row.html)
    except render.PdfUnavailable as e:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"PDF rendering is unavailable on this deployment ({e}); use HTML preview instead",
        )
    fname = (
        f"eksir-{row.template_key}-{row.period_end:%Y%m%d}.pdf"
        if row.period_end
        else "eksir-report.pdf"
    )
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Send (ANALYST-GATED — the only outbound action) ─────────────────────────
@router.post("/generated/{report_id}/send")
async def send_report(
    report_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    subject: Annotated[str | None, Body(embed=True)] = None,
) -> dict:
    """Email the report to the tenant's notification address(es), PDF attached.
    Analyst-gated and never automatic — mirrors the customer-case send path."""
    row = await service.scope_visible_report(session, report_id, scope)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    if row.status == "sent":
        raise HTTPException(status.HTTP_409_CONFLICT, "report already sent; regenerate to resend")
    if row.tenant_id is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "all-scope reports have no customer recipient — generate a per-customer report to send",
        )
    if not mailer.is_configured():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "email sending is not configured")

    t = await session.get(Tenant, row.tenant_id)
    if not t or not t.notification_email:
        raise HTTPException(status.HTTP_409_CONFLICT, "tenant has no notification_email configured")

    subj = (subject or "").strip() or row.title
    cc = [a.strip() for a in (t.notification_email_cc or "").split(",") if a.strip()]

    attachments: list[tuple[str, str, bytes]] = []
    body_html = row.html or ""
    try:
        pdf = await asyncio.to_thread(render.html_to_pdf, row.html or "")
        fname = (
            f"eksir-{row.template_key}-{row.period_end:%Y%m%d}.pdf"
            if row.period_end
            else "eksir-report.pdf"
        )
        attachments.append((fname, "application/pdf", pdf))
        body_html = _send_cover_html(row, t.name)
    except render.PdfUnavailable:
        # No native PDF stack on this deployment — fall back to sending the
        # inline HTML report as the email body (audit records pdf_attached=False).
        pass

    try:
        await mailer.send_html_email(
            to=t.notification_email,
            cc=cc,
            subject=subj,
            html_body=body_html,
            attachments=attachments,
        )
    except mailer.MailNotConfigured:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "email backend unavailable")
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"email send failed: {e}")

    row.status = "sent"
    row.sent_at = datetime.now(timezone.utc)
    row.sent_by_id = user.id
    row.sent_to = t.notification_email
    await audit.log(
        session,
        user_id=user.id,
        action="report.send",
        target_type="generated_report",
        target_id=row.id,
        tenant_id=row.tenant_id,
        diff={"to": t.notification_email, "pdf_attached": bool(attachments)},
    )
    return _report_summary(row)


def _send_cover_html(row: GeneratedReport, customer_name: str | None) -> str:
    """Short, email-safe (inline-styled) cover note for the send body; the full
    branded report rides along as the PDF attachment."""
    who = customer_name or "your organisation"
    return (
        '<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;'
        'background:#07111F;color:#E6EDF7;padding:24px;border-radius:8px;max-width:560px;">'
        '<div style="font-weight:700;letter-spacing:1.5px;color:#00D4FF;">⬡ EKSIR · SOC Report</div>'
        f'<h2 style="margin:12px 0 6px;font-size:18px;">{row.title}</h2>'
        f'<p style="margin:0;color:#A6B0CF;font-size:14px;">Please find the attached SOC report for {who}.</p>'
        "</div>"
    )


# ── Schedules (recurring generation → draft) ────────────────────────────────
@router.get("/schedules")
async def list_schedules(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    q = select(ReportSchedule).order_by(ReportSchedule.created_at.desc())
    if scope is not None:
        q = q.where(ReportSchedule.tenant_id.in_(scope))
    rows = (await session.execute(q)).scalars().all()
    return [_schedule_summary(s) for s in rows]


@router.post("/schedules")
async def create_schedule(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    template_key: Annotated[str, Body()],
    cadence: Annotated[str, Body()] = "monthly",
    tenant_id: Annotated[uuid.UUID | None, Body()] = None,
) -> dict:
    """Create a recurring report. next_run_at is seeded so it fires at the next
    period boundary (not immediately)."""
    if not registry.is_valid(template_key):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown template '{template_key}'")
    if cadence not in periods.CADENCES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"cadence must be one of {periods.CADENCES}"
        )
    await _require_tenant_in_scope(session, tenant_id, scope)

    s = ReportSchedule(
        tenant_id=tenant_id,
        template_key=template_key,
        cadence=cadence,
        enabled=True,
        next_run_at=periods.next_run_after(cadence, datetime.now(timezone.utc)),
        created_by_id=user.id,
    )
    session.add(s)
    await session.flush()
    await audit.log(
        session,
        user_id=user.id,
        action="report.schedule_create",
        target_type="report_schedule",
        target_id=s.id,
        tenant_id=tenant_id,
        diff={"template_key": template_key, "cadence": cadence},
    )
    return _schedule_summary(s)


@router.put("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    enabled: Annotated[bool | None, Body()] = None,
    cadence: Annotated[str | None, Body()] = None,
    template_key: Annotated[str | None, Body()] = None,
) -> dict:
    s = await session.get(ReportSchedule, schedule_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    require_in_scope(s.tenant_id, scope) if s.tenant_id else _admin_only(scope)
    if template_key is not None:
        if not registry.is_valid(template_key):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown template '{template_key}'")
        s.template_key = template_key
    if cadence is not None:
        if cadence not in periods.CADENCES:
            raise HTTPException(400, f"cadence must be one of {periods.CADENCES}")
        s.cadence = cadence
        s.next_run_at = periods.next_run_after(cadence, datetime.now(timezone.utc))
    if enabled is not None:
        s.enabled = enabled
    await audit.log(
        session,
        user_id=user.id,
        action="report.schedule_update",
        target_type="report_schedule",
        target_id=s.id,
        tenant_id=s.tenant_id,
        diff={"enabled": s.enabled, "cadence": s.cadence, "template_key": s.template_key},
    )
    return _schedule_summary(s)


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    s = await session.get(ReportSchedule, schedule_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    require_in_scope(s.tenant_id, scope) if s.tenant_id else _admin_only(scope)
    await session.delete(s)
    await audit.log(
        session,
        user_id=user.id,
        action="report.schedule_delete",
        target_type="report_schedule",
        target_id=schedule_id,
        tenant_id=s.tenant_id,
    )
    return {"ok": True}


def _admin_only(scope: TenantScope) -> None:
    """Guard for all-scope (tenant_id NULL) schedule rows."""
    if scope is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
