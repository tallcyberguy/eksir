"""SLA Tracking — per-severity resolution-time SLA over the case lifecycle.

Reads the F1 attribution/lifecycle data: resolution time = `closed_at − created_at`
(the gate sets `closed_at`; auto-closed cases now set it too). Targets default in
`pipeline/sla.py` and are admin-overridable via `sla_targets`. The aggregation
(`sla.build_sla_dashboard`) is pure + unit-tested; the endpoint runs the queries.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import current_user, require_admin
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.enums import CaseStatus
from ..db.models import Incident, SLATarget, User
from ..db.session import get_session
from ..pipeline import sla

router = APIRouter()


async def _load_targets(session: AsyncSession) -> tuple[dict[str, int], dict[str, int]]:
    """(resolution_targets, response_targets), each = defaults + admin overrides."""
    rows = (await session.scalars(select(SLATarget))).all()
    res_over = {r.severity: r.target_minutes for r in rows}
    resp_over = {r.severity: r.response_target_minutes for r in rows if r.response_target_minutes}
    return sla.effective_targets(res_over), sla.effective_response_targets(resp_over)


@router.get("/targets")
async def get_targets(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    resolution, response = await _load_targets(session)
    return {
        "targets": resolution,
        "response_targets": response,
        "defaults": sla.DEFAULT_TARGET_MINUTES,
        "response_defaults": sla.DEFAULT_RESPONSE_MINUTES,
    }


class TargetIn(BaseModel):
    severity: str
    target_minutes: int | None = Field(None, ge=1, le=100000)
    response_target_minutes: int | None = Field(None, ge=1, le=100000)


@router.put("/targets")
async def set_target(
    body: TargetIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    if body.severity not in sla.SEVERITIES:
        raise HTTPException(400, f"severity must be one of {sla.SEVERITIES}")
    if body.target_minutes is None and body.response_target_minutes is None:
        raise HTTPException(400, "provide target_minutes and/or response_target_minutes")
    row = await session.get(SLATarget, body.severity)
    if row is None:
        # `target_minutes` is NOT NULL — default it if only a response target came in.
        row = SLATarget(
            severity=body.severity,
            target_minutes=body.target_minutes or sla.DEFAULT_TARGET_MINUTES[body.severity],
        )
        session.add(row)
    if body.target_minutes is not None:
        row.target_minutes = body.target_minutes
    if body.response_target_minutes is not None:
        row.response_target_minutes = body.response_target_minutes
    row.updated_by_id = admin.id
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="sla.target.set",
        target_type="sla_target",
        target_id=None,
        diff={
            "severity": body.severity,
            "target_minutes": body.target_minutes,
            "response_target_minutes": body.response_target_minutes,
        },
    )
    resolution, response = await _load_targets(session)
    return {"targets": resolution, "response_targets": response}


@router.get("/dashboard")
async def sla_dashboard(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window_days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)
    scope_w = scope_clause_for_incidents(scope)
    resolution_targets, response_targets = await _load_targets(session)

    closed_rows = (
        await session.execute(
            select(
                Incident.case_number,
                Incident.severity,
                Incident.created_at,
                Incident.closed_at,
                Incident.claimed_at,
            ).where(
                Incident.status == CaseStatus.CLOSED,
                Incident.closed_at.is_not(None),
                Incident.closed_at >= cutoff,
                scope_w,
            )
        )
    ).all()
    closed = [
        {
            "case_number": r.case_number,
            "severity": str(r.severity),
            "created_at": r.created_at,
            "closed_at": r.closed_at,
            "claimed_at": r.claimed_at,
        }
        for r in closed_rows
    ]

    open_rows = (
        await session.execute(
            select(
                Incident.case_number,
                Incident.severity,
                Incident.created_at,
                Incident.claimed_at,
            ).where(
                Incident.status.notin_([CaseStatus.CLOSED, CaseStatus.FAILED]),
                Incident.deleted_at.is_(None),
                scope_w,
            )
        )
    ).all()
    open_cases = [
        {
            "case_number": r.case_number,
            "severity": str(r.severity),
            "created_at": r.created_at,
            "claimed_at": r.claimed_at,
        }
        for r in open_rows
    ]

    out = sla.build_sla_dashboard(
        closed,
        open_cases,
        resolution_targets,
        window_days=window_days,
        now=now,
        response_targets=response_targets,
    )
    out["generated_at"] = now.isoformat()
    return out
