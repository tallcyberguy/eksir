"""Autonomy guardrails (3.9) — admin policy editor.

Manages the per-action-kind confidence ladder that drives the auto/review/
escalate RECOMMENDATION badge. v1 edits the GLOBAL policy (tenant_id NULL);
per-tenant overrides are read at synthesis time but not edited here yet. Nothing
in this module executes an action — it only tunes a badge. Effect/containment
kinds stay clamped to escalate in `guardrails.recommend` regardless of edits.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import current_user, require_admin
from ..auth.tenancy import TenantScope, current_tenant_scope
from ..db.models import AutonomyThreshold, User
from ..db.session import get_session
from ..pipeline import guardrails
from ..settings import settings

router = APIRouter()


def _row_dict(r: AutonomyThreshold) -> dict[str, Any]:
    return {
        "action_kind": r.action_kind,
        "blast_radius": r.blast_radius,
        "auto_confidence": r.auto_confidence,
        "review_confidence": r.review_confidence,
        "escalation_confidence": r.escalation_confidence,
        "source": r.source,
        "reason": r.reason,
    }


@router.get("/policy")
async def get_policy(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    global_rows = (
        (
            await session.execute(
                select(AutonomyThreshold).where(AutonomyThreshold.tenant_id.is_(None))
            )
        )
        .scalars()
        .all()
    )
    tenant_rows: list = []
    if scope and len(scope) == 1:
        (tid,) = tuple(scope)
        tenant_rows = (
            (
                await session.execute(
                    select(AutonomyThreshold).where(AutonomyThreshold.tenant_id == tid)
                )
            )
            .scalars()
            .all()
        )

    yaml_map = guardrails._load_yaml_policy(settings.isoc_autonomy_policy or "")
    return guardrails.build_effective_policy(
        yaml_map=yaml_map,
        global_rows=[_row_dict(r) for r in global_rows],
        tenant_rows=[_row_dict(r) for r in tenant_rows],
    )


class PolicyIn(BaseModel):
    blast_radius: str | None = None
    auto: float = Field(..., ge=0.0, le=2.0)
    review: float = Field(..., ge=0.0, le=2.0)
    escalation: float = Field(..., ge=0.0, le=2.0)
    reason: str | None = None


@router.put("/policy/{kind}")
async def set_policy(
    kind: str,
    body: PolicyIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    if kind not in guardrails.BLAST_RADIUS:
        raise HTTPException(400, f"unknown action kind: {kind}")
    if not (body.escalation <= body.review <= body.auto):
        raise HTTPException(400, "require escalation ≤ review ≤ auto")

    row = await session.scalar(
        select(AutonomyThreshold).where(
            AutonomyThreshold.action_kind == kind, AutonomyThreshold.tenant_id.is_(None)
        )
    )
    if row is None:
        row = AutonomyThreshold(action_kind=kind, tenant_id=None)
        session.add(row)
    row.blast_radius = body.blast_radius or guardrails.BLAST_RADIUS.get(kind, "high")
    row.auto_confidence = body.auto
    row.review_confidence = body.review
    row.escalation_confidence = body.escalation
    row.source = "db"
    row.reason = body.reason
    row.updated_by_id = admin.id
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="autonomy.policy.set",
        target_type="autonomy_threshold",
        target_id=row.id,
        diff={
            "kind": kind,
            "auto": body.auto,
            "review": body.review,
            "escalation": body.escalation,
        },
    )
    return {"ok": True, "kind": kind}


@router.delete("/policy/{kind}")
async def reset_policy(
    kind: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    if kind not in guardrails.BLAST_RADIUS:
        raise HTTPException(400, f"unknown action kind: {kind}")
    row = await session.scalar(
        select(AutonomyThreshold).where(
            AutonomyThreshold.action_kind == kind, AutonomyThreshold.tenant_id.is_(None)
        )
    )
    if row is not None:
        await session.delete(row)
        await audit.log(
            session,
            user_id=admin.id,
            action="autonomy.policy.reset",
            target_type="autonomy_threshold",
            target_id=row.id,
            diff={"kind": kind},
        )
    return {"ok": True, "kind": kind}
