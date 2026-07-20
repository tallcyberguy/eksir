"""MSSP Dashboard — a multi-tenant overview for HOST/MSSP operators.

Live-computed (no snapshot table): per accessible tenant, current open / urgent /
at-the-gate counts plus window totals, rolled up over the existing tenant
hierarchy + scope. The aggregation (`build_overview`) is pure + unit-tested.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.enums import CaseStatus, Severity
from ..db.models import Incident, Tenant, User
from ..db.session import get_session

router = APIRouter()


def build_overview(
    tenants: list[dict], open_by: dict, win_by: dict, *, window_days: int
) -> dict[str, Any]:
    """Pure rollup. `tenants`: accessible tenant rows. `open_by`/`win_by`: per-tenant
    aggregates keyed by tenant id."""
    rows = []
    total_open = total_awaiting = total_urgent = 0
    for t in tenants:
        tid = t["id"]
        o = open_by.get(tid, {})
        w = win_by.get(tid, {})
        open_n = int(o.get("open", 0))
        urgent = int(o.get("urgent", 0))
        awaiting = int(o.get("awaiting", 0))
        rows.append(
            {
                "tenant_id": str(tid),
                "name": t.get("name"),
                "slug": t.get("slug"),
                "tier": str(t.get("tier")) if t.get("tier") is not None else None,
                "tier_label": t.get("tier_label"),
                "open": open_n,
                "open_urgent": urgent,
                "awaiting_signoff": awaiting,
                "total": int(w.get("total", 0)),
                "closed": int(w.get("closed", 0)),
            }
        )
        total_open += open_n
        total_awaiting += awaiting
        total_urgent += urgent

    # Most attention-needing first: at-the-gate, then urgent, then open volume.
    rows.sort(
        key=lambda r: (-r["awaiting_signoff"], -r["open_urgent"], -r["open"], r["name"] or "")
    )

    return {
        "window_days": window_days,
        "tenant_count": len(rows),
        "total_open": total_open,
        "total_awaiting_signoff": total_awaiting,
        "total_urgent": total_urgent,
        "tenants": rows,
    }


@router.get("/overview")
async def mssp_overview(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window_days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)
    scope_w = scope_clause_for_incidents(scope)

    # Accessible tenants (None scope = all; empty set = none).
    if scope is not None and not scope:
        return build_overview([], {}, {}, window_days=window_days)
    tq = select(Tenant.id, Tenant.name, Tenant.slug, Tenant.tier, Tenant.tier_label)
    if scope is not None:
        tq = tq.where(Tenant.id.in_(scope))
    tenants = [
        {"id": r.id, "name": r.name, "slug": r.slug, "tier": r.tier, "tier_label": r.tier_label}
        for r in (await session.execute(tq)).all()
    ]

    open_rows = (
        await session.execute(
            select(
                Incident.tenant_id,
                func.count(Incident.id).label("open"),
                func.count(Incident.id)
                .filter(Incident.severity.in_([Severity.CRITICAL, Severity.HIGH]))
                .label("urgent"),
                func.count(Incident.id)
                .filter(Incident.status == CaseStatus.AWAITING_SIGNOFF)
                .label("awaiting"),
            )
            .where(
                Incident.status.notin_([CaseStatus.CLOSED, CaseStatus.FAILED]),
                Incident.deleted_at.is_(None),
                Incident.tenant_id.is_not(None),
                scope_w,
            )
            .group_by(Incident.tenant_id)
        )
    ).all()
    open_by = {
        r.tenant_id: {"open": r.open, "urgent": r.urgent, "awaiting": r.awaiting} for r in open_rows
    }

    win_rows = (
        await session.execute(
            select(
                Incident.tenant_id,
                func.count(Incident.id).label("total"),
                func.count(Incident.id)
                .filter(Incident.status == CaseStatus.CLOSED)
                .label("closed"),
            )
            .where(
                Incident.created_at >= cutoff,
                Incident.deleted_at.is_(None),
                Incident.tenant_id.is_not(None),
                scope_w,
            )
            .group_by(Incident.tenant_id)
        )
    ).all()
    win_by = {r.tenant_id: {"total": r.total, "closed": r.closed} for r in win_rows}

    out = build_overview(tenants, open_by, win_by, window_days=window_days)
    out["generated_at"] = now.isoformat()
    return out
