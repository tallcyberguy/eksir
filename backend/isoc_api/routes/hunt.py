"""Hunt (3.13) — NL→query translate + saved hunts (translate-only).

`POST /hunt/translate` turns a plain-English question into S1QL / KQL / Sigma via
the deterministic translator (behind the F3 egress contract). Saved hunts persist
the question + its translation. **Execution is deliberately not wired** — `run`
re-translates and stamps `last_run_at` but never queries SentinelOne or writes a
verdict (that's the documented fast-follow). The analyst gate is untouched.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope
from ..db.enums import Role
from ..db.models import SavedHunt, User
from ..db.session import get_session
from ..hunt import translate as hunt_translate

router = APIRouter()


def _hunt_out(h: SavedHunt) -> dict[str, Any]:
    return {
        "id": str(h.id),
        "name": h.name,
        "nl_query": h.nl_query,
        "translated": h.translated or {},
        "language": h.language,
        "time_range": h.time_range,
        "last_run_at": h.last_run_at.isoformat() if h.last_run_at else None,
        "created_at": h.created_at.isoformat() if h.created_at else None,
    }


def _visible(scope: TenantScope):
    # Personal/global hunts (tenant_id NULL) are always visible; tenant hunts
    # only within the active scope.
    if scope is None:
        return SavedHunt.id == SavedHunt.id
    if not scope:
        return SavedHunt.tenant_id.is_(None)
    return or_(SavedHunt.tenant_id.is_(None), SavedHunt.tenant_id.in_(scope))


class TranslateIn(BaseModel):
    question: str = Field(..., min_length=3, max_length=2000)
    time_range: str | None = None


@router.post("/translate")
async def translate(
    body: TranslateIn,
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return await hunt_translate.translate(body.question, body.time_range)


@router.get("/saved")
async def list_saved(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    rows = (
        await session.scalars(
            select(SavedHunt)
            .where(_visible(scope))
            .order_by(SavedHunt.created_at.desc())
            .limit(limit)
        )
    ).all()
    return {"hunts": [_hunt_out(h) for h in rows]}


class SavedHuntIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    nl_query: str = Field(..., min_length=1)
    translated: dict[str, Any] = Field(default_factory=dict)
    language: str = "s1ql"
    time_range: str | None = None


@router.post("/saved")
async def create_saved(
    body: SavedHuntIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    lang = body.language if body.language in hunt_translate.LANGUAGES else "s1ql"
    # Tag with the active tenant only when the scope is a single tenant.
    tenant_id = next(iter(scope)) if scope and len(scope) == 1 else None
    h = SavedHunt(
        name=body.name.strip(),
        nl_query=body.nl_query.strip(),
        translated=body.translated or None,
        language=lang,
        time_range=body.time_range,
        tenant_id=tenant_id,
        created_by_id=user.id,
    )
    session.add(h)
    await session.flush()
    return _hunt_out(h)


@router.delete("/saved/{hunt_id}")
async def delete_saved(
    hunt_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    h = await session.get(SavedHunt, hunt_id)
    if h is None:
        raise HTTPException(404, "saved hunt not found")
    if h.created_by_id not in (None, user.id) and user.role != Role.ADMIN:
        raise HTTPException(403, "only the owner or an admin can delete this hunt")
    await session.delete(h)
    return {"ok": True}


@router.post("/saved/{hunt_id}/run")
async def run_saved(
    hunt_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    """v1 = translate-only: refresh the translation + stamp last_run_at. Does NOT
    execute against SentinelOne (the deferred fast-follow)."""
    h = await session.get(SavedHunt, hunt_id)
    if h is None:
        raise HTTPException(404, "saved hunt not found")
    fresh = await hunt_translate.translate(h.nl_query, h.time_range)
    if fresh.get("status") == "ok":
        h.translated = {k: fresh[k] for k in ("s1ql", "kql", "sigma", "explanation")}
    h.last_run_at = datetime.now(timezone.utc)
    return {
        "status": "translate_only",
        "translated": h.translated or {},
        "message": "Translated and saved. Live execution against SentinelOne is a fast-follow — "
        "copy the query into your console to run it.",
        "last_run_at": h.last_run_at.isoformat(),
    }
