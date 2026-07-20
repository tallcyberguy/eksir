"""Investigation Queue (3.6) — a claimable, SLA-ranked worklist over incidents.

Strictly orthogonal to the analyst gate: claim / release / snooze write ONLY
ownership + scheduling columns (`assignee_id` / `claimed_at` / `snoozed_*`).
They never touch `verdict`, `status`, `closed_at`, `AWAITING_SIGNOFF`, or fire a
V1 response action — `routes/cases.py POST /approve` stays the sole commit point.

The ranking (`sla.build_queue`) is pure + unit-tested; this module runs the
scoped query and the atomic single-writer claim.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import current_user
from ..auth.tenancy import (
    TenantScope,
    current_tenant_scope,
    require_in_scope,
    scope_clause_for_incidents,
)
from ..db.enums import CaseStatus, Role
from ..db.models import Incident, SLATarget, User
from ..db.session import get_session
from ..pipeline import sla

router = APIRouter()

# Terminal / non-actionable states never belong in a worklist.
_HIDDEN_STATES = [CaseStatus.CLOSED, CaseStatus.FAILED, CaseStatus.DECIDED_SHORT_CIRCUIT]
_PERIOD_DAYS = {"24h": 1, "7d": 7, "30d": 30}
_SNOOZE_PRESETS = {15, 60, 240, 1440}


async def _effective_targets(session: AsyncSession) -> dict[str, int]:
    rows = (await session.scalars(select(SLATarget))).all()
    return sla.effective_targets({r.severity: r.target_minutes for r in rows})


def _project_actions(enrichment: dict | None) -> list[str]:
    acts = (enrichment or {}).get("proposed_actions") or []
    out: list[str] = []
    for a in acts[:5]:
        if isinstance(a, dict):
            out.append(str(a.get("kind") or a.get("type") or a.get("label") or "action"))
        else:
            out.append(str(a))
    return out


def _project_asset(normalized: dict | None) -> str | None:
    n = normalized or {}
    for k in ("asset", "hostname", "host", "endpoint", "entity", "src_host"):
        v = n.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


@router.get("")
async def list_queue(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    severity: str | None = Query(None),
    assignee: str | None = Query(None, description="me | unassigned | <user-uuid>"),
    tenant: str | None = Query(None, description="tenant uuid"),
    period: str = Query("all", pattern="^(24h|7d|30d|all)$"),
    limit: int = Query(200, ge=1, le=500),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    conds = [
        Incident.status.notin_(_HIDDEN_STATES),
        Incident.deleted_at.is_(None),
        scope_clause_for_incidents(scope),
    ]
    if severity:
        conds.append(Incident.severity == severity)
    if assignee == "me":
        conds.append(Incident.assignee_id == user.id)
    elif assignee == "unassigned":
        conds.append(Incident.assignee_id.is_(None))
    elif assignee:
        try:
            conds.append(Incident.assignee_id == uuid.UUID(assignee))
        except ValueError as exc:
            raise HTTPException(400, "assignee must be me|unassigned|<uuid>") from exc
    if tenant:
        try:
            conds.append(Incident.tenant_id == uuid.UUID(tenant))
        except ValueError as exc:
            raise HTTPException(400, "tenant must be a uuid") from exc
    if period in _PERIOD_DAYS:
        conds.append(Incident.created_at >= now - timedelta(days=_PERIOD_DAYS[period]))

    res = (
        await session.execute(
            select(
                Incident.id,
                Incident.case_number,
                Incident.title,
                Incident.severity,
                Incident.status,
                Incident.tenant_id,
                Incident.customer,
                Incident.assignee_id,
                Incident.snoozed_until,
                Incident.created_at,
                Incident.enrichment,
                Incident.normalized,
            )
            .where(*conds)
            .order_by(Incident.created_at.desc())
            .limit(limit)
        )
    ).all()

    rows = [
        {
            "id": r.id,
            "case_number": r.case_number,
            "title": r.title,
            "severity": r.severity,
            "status": r.status,
            "tenant_id": r.tenant_id,
            "customer": r.customer,
            "assignee_id": r.assignee_id,
            "snoozed_until": r.snoozed_until,
            "created_at": r.created_at,
            "proposed_actions": _project_actions(r.enrichment),
            "asset": _project_asset(r.normalized),
        }
        for r in res
    ]

    targets = await _effective_targets(session)
    return sla.build_queue(rows, me_id=str(user.id), now=now, targets=targets)


async def _load_in_scope(
    session: AsyncSession, incident_id: uuid.UUID, scope: TenantScope
) -> Incident:
    inc = await session.get(Incident, incident_id)
    if inc is None or inc.deleted_at is not None:
        raise HTTPException(404, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    return inc


@router.post("/{incident_id}/claim")
async def claim(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    inc = await _load_in_scope(session, incident_id, scope)
    if inc.assignee_id == user.id:
        return {"ok": True, "already_mine": True, "owner_id": str(user.id)}

    # Atomic compare-and-set: only the writer that finds assignee_id NULL wins.
    won = (
        await session.execute(
            update(Incident)
            .where(Incident.id == incident_id, Incident.assignee_id.is_(None))
            .values(assignee_id=user.id, claimed_at=now)
            .returning(Incident.assignee_id)
        )
    ).first()
    if won is None:
        # Lost the race (or already owned by someone). Surface the current owner.
        await session.refresh(inc, ["assignee_id"])
        raise HTTPException(
            409,
            detail={
                "error": "already_claimed",
                "owner_id": str(inc.assignee_id) if inc.assignee_id else None,
            },
        )

    sla.record_sla_event(session, inc, sla.ACKNOWLEDGED, actor_id=user.id)
    await audit.log(
        session,
        user_id=user.id,
        action="queue.claim",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
    )
    return {"ok": True, "owner_id": str(user.id)}


@router.post("/{incident_id}/release")
async def release(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    inc = await _load_in_scope(session, incident_id, scope)
    if inc.assignee_id is not None and inc.assignee_id != user.id and user.role != Role.ADMIN:
        raise HTTPException(403, "only the owner or an admin can release")
    inc.assignee_id = None
    inc.claimed_at = None
    await audit.log(
        session,
        user_id=user.id,
        action="queue.release",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
    )
    return {"ok": True}


@router.post("/{incident_id}/snooze")
async def snooze(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    minutes: int = Body(..., embed=True, ge=1, le=43200),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    inc = await _load_in_scope(session, incident_id, scope)
    inc.snoozed_until = now + timedelta(minutes=minutes)
    inc.snoozed_by_id = user.id
    await audit.log(
        session,
        user_id=user.id,
        action="queue.snooze",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={"minutes": minutes},
    )
    return {"ok": True, "snoozed_until": inc.snoozed_until.isoformat()}
