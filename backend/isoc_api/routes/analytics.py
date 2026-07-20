"""Team Analytics (3.5) — per-analyst leaderboard off F1 gate attribution.

Read-only: reads `Incident.approved_by_id`/`signed_off_at` (written ONLY by the
gate at `cases._commit_verdict`) + the `sla_events` ledger, and aggregates them
via the pure `analytics.scoring.build_leaderboard`. Writes nothing, proposes
nothing — the gate stays the sole commit point.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics import scoring
from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.models import Incident, SLAEvent, User
from ..db.session import get_session
from ..pipeline import sla

router = APIRouter()


@router.get("/leaderboard")
async def leaderboard(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window_days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)

    if scope is not None and not scope:  # explicit empty scope sees nothing
        return scoring.build_leaderboard([], window_days=window_days, now=now)

    inc_rows = (
        await session.execute(
            select(
                Incident.id,
                Incident.approved_by_id,
                Incident.created_at,
                Incident.signed_off_at,
                Incident.verdict,
                User.full_name,
                User.email,
            )
            .join(User, Incident.approved_by_id == User.id)
            .where(
                Incident.signed_off_at >= cutoff,
                Incident.approved_by_id.is_not(None),
                Incident.deleted_at.is_(None),
                scope_clause_for_incidents(scope),
            )
        )
    ).all()

    ids = [r.id for r in inc_rows]

    # Flip detection: an incident with ≥2 `closed` events whose meta.verdict
    # differs was re-verdicted. Attribute the flip to the FIRST closed actor (the
    # original signer). v1 attaches it only when that signer is still the current
    # approver (self-correction — the common case); a cross-analyst corrective
    # re-verdict isn't attributed to either (documented limitation).
    flipped_first_actor: dict[Any, Any] = {}
    if ids:
        ev = (
            await session.execute(
                select(SLAEvent.incident_id, SLAEvent.actor_id, SLAEvent.at, SLAEvent.meta)
                .where(SLAEvent.kind == sla.CLOSED, SLAEvent.incident_id.in_(ids))
                .order_by(SLAEvent.at)
            )
        ).all()
        closed_by_inc: dict[Any, list] = defaultdict(list)
        for e in ev:
            closed_by_inc[e.incident_id].append(e)
        for inc_id, evs in closed_by_inc.items():
            verdicts = {(e.meta or {}).get("verdict") for e in evs if (e.meta or {}).get("verdict")}
            if len(evs) >= 2 and len(verdicts) >= 2:
                flipped_first_actor[inc_id] = evs[0].actor_id

    rows = [
        {
            "analyst_id": r.approved_by_id,
            "analyst_name": r.full_name or r.email,
            "created_at": r.created_at,
            "signed_off_at": r.signed_off_at,
            "verdict": str(r.verdict),
            "was_flipped": flipped_first_actor.get(r.id) == r.approved_by_id,
        }
        for r in inc_rows
    ]

    return scoring.build_leaderboard(rows, window_days=window_days, now=now)
