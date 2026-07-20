"""Shift Handoff (Phase 3) — read-only handoff board from live incident state.

`GET /shifts/handoff` ranks the open worklist for the incoming shift and rolls up
what the current shift did over the window. `GET /shifts/handoff.md` returns the
same as a copy-pasteable markdown note. Tenant-scoped; no schema; nothing here
writes state or fires an action — it only describes the board.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.enums import CaseStatus
from ..db.models import Incident, User
from ..db.session import get_session
from ..pipeline.shifts import build_handoff, render_handoff_markdown

router = APIRouter()

_OPEN = [s for s in CaseStatus if s not in (CaseStatus.CLOSED, CaseStatus.FAILED)]


def _proposed_actions(enrichment: dict | None) -> list:
    if not enrichment:
        return []
    pa = enrichment.get("proposed_actions")
    return pa if isinstance(pa, list) else []


async def _gather(
    session: AsyncSession, scope: TenantScope, *, now: datetime, window_hours: int
) -> dict[str, Any]:
    scope_w = scope_clause_for_incidents(scope)
    if scope is not None and not scope:
        return build_handoff([], [], now=now, window_hours=window_hours)

    cutoff = now - timedelta(hours=window_hours)

    # Open worklist (+ assignee email for display).
    open_q = (
        select(Incident, User.email)
        .outerjoin(User, Incident.assignee_id == User.id)
        .where(
            Incident.status.in_(_OPEN),
            Incident.deleted_at.is_(None),
            scope_w,
        )
        .order_by(Incident.created_at.asc())
        .limit(200)
    )
    open_rows: list[dict] = []
    for inc, email in (await session.execute(open_q)).all():
        open_rows.append(
            {
                "id": inc.id,
                "case_number": inc.case_number,
                "title": inc.title,
                "severity": str(inc.severity),
                "status": str(inc.status),
                "verdict": str(inc.verdict) if inc.verdict else None,
                "customer": inc.customer,
                "assignee_id": inc.assignee_id,
                "assignee_name": (email.split("@")[0] if email else None),
                "created_at": inc.created_at,
                "snoozed_until": inc.snoozed_until,
                "proposed_actions": _proposed_actions(inc.enrichment),
                "handoff_note": inc.handoff_note,
            }
        )

    # Window rows for the rollup (created OR closed in window).
    win_q = (
        select(
            Incident.created_at,
            Incident.closed_at,
            Incident.signed_off_at,
            Incident.approved_by_id,
        )
        .where(
            or_(Incident.created_at >= cutoff, Incident.closed_at >= cutoff),
            Incident.deleted_at.is_(None),
            scope_w,
        )
        .limit(5000)
    )
    window_rows = [
        {
            "created_at": r.created_at,
            "closed_at": r.closed_at,
            "signed_off_at": r.signed_off_at,
            "approved_by_id": r.approved_by_id,
        }
        for r in (await session.execute(win_q)).all()
    ]
    return build_handoff(open_rows, window_rows, now=now, window_hours=window_hours)


@router.get("/handoff")
async def handoff(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window_hours: int = Query(default=12, ge=1, le=72),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    out = await _gather(session, scope, now=now, window_hours=window_hours)
    out["on_duty"] = user.email.split("@")[0] if user.email else None
    return out


@router.get("/handoff.md", response_class=PlainTextResponse)
async def handoff_markdown(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window_hours: int = Query(default=12, ge=1, le=72),
) -> str:
    now = datetime.now(timezone.utc)
    out = await _gather(session, scope, now=now, window_hours=window_hours)
    out["on_duty"] = user.email.split("@")[0] if user.email else None
    return render_handoff_markdown(out)
