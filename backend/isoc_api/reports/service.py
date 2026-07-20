"""Report generation service (Feature 7).

The one place that coordinates gather → build_context → render → persist a
DRAFT GeneratedReport. Shared by the on-demand route (routes/reports.generate)
and the cron (worker.report_generate) so both produce identical artifacts. It
never sends and never commits — the caller owns the transaction; delivery is
analyst-gated in routes/reports.send.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.tenancy import TenantScope
from ..db.models import GeneratedReport, Tenant, TenantBranding
from . import data as report_data
from . import gather, registry, render


async def load_branding_ctx(session: AsyncSession, tenant_id: uuid.UUID | None) -> dict | None:
    """Branding context for a tenant: {logo_data_uri, accent_color, display_name}.
    None when the tenant has no branding row (renderer falls back to the theme)."""
    if tenant_id is None:
        return None
    b = await session.get(TenantBranding, tenant_id)
    if b is None:
        return None
    return {
        "logo_data_uri": render.logo_data_uri(b.logo_bytes, b.logo_mime),
        "accent_color": b.accent_color,
        "display_name": b.display_name,
    }


async def _scope_label(
    session: AsyncSession, tenant_id: uuid.UUID | None, customer: str | None, branding: dict | None
) -> str:
    if branding and branding.get("display_name"):
        return branding["display_name"]
    if tenant_id is not None:
        t = await session.get(Tenant, tenant_id)
        if t is not None:
            return t.name
    return customer or "All customers"


async def generate_report(
    session: AsyncSession,
    *,
    scope: TenantScope,
    template_key: str,
    tenant_id: uuid.UUID | None,
    start: datetime,
    end: datetime,
    label: str,
    kind: str = "monthly",
    customer: str | None = None,
    generated_by_id: uuid.UUID | None = None,
    schedule_id: uuid.UUID | None = None,
) -> GeneratedReport:
    """Render a report for `scope`/period and persist it as a DRAFT row (flushed
    so `.id` is populated; NOT committed). `scope` must already be narrowed by
    the caller (e.g. {tenant_id} for a single-customer report)."""
    if not registry.is_valid(template_key):
        template_key = registry.DEFAULT_TEMPLATE

    branding = await load_branding_ctx(session, tenant_id)
    report = await gather.gather_report_data(
        session, scope, start=start, end=end, label=label, kind=kind, customer=customer
    )
    report["scope_label"] = await _scope_label(session, tenant_id, customer, branding)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ctx = report_data.build_report_context(
        report, template_key=template_key, branding=branding, generated_at=generated_at
    )
    html = render.render_report_html(ctx)

    row = GeneratedReport(
        tenant_id=tenant_id,
        schedule_id=schedule_id,
        template_key=template_key,
        title=f"{ctx['template']['title']} — {label}",
        period_start=start,
        period_end=end,
        params={"template_key": template_key, "label": label, "kind": kind, "customer": customer},
        html=html,
        status="draft",
        generated_by_id=generated_by_id,
    )
    session.add(row)
    await session.flush()
    return row


async def scope_visible_report(
    session: AsyncSession, report_id: uuid.UUID, scope: TenantScope
) -> GeneratedReport | None:
    """Fetch a GeneratedReport only if it's visible under `scope` (its tenant is
    in scope, or scope is unrestricted). Returns None otherwise — callers 404."""
    from ..auth.tenancy import in_scope

    row = await session.get(GeneratedReport, report_id)
    if row is None:
        return None
    # Unassigned (tenant_id NULL) all-scope reports are admin-only (scope None).
    if row.tenant_id is None:
        return row if scope is None else None
    return row if in_scope(row.tenant_id, scope) else None


async def due_schedules(session: AsyncSession, now: datetime) -> list:
    """Enabled schedules whose next_run_at has passed (or is unset)."""
    from ..db.models import ReportSchedule
    from .periods import schedule_due

    rows = (
        (await session.execute(select(ReportSchedule).where(ReportSchedule.enabled.is_(True))))
        .scalars()
        .all()
    )
    return [s for s in rows if schedule_due(s.next_run_at, now)]
