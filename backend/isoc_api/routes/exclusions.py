"""Exclusion routes — analyst-curated allowlist for IOC triage.

Reads are open to any authenticated user. Mutations are admin-only.

The Exclusion table is *global* (no tenant scoping), mirroring the threat_iocs
pattern. Practical implication for MSSPs: an exclusion entered by the host
admin suppresses an IOC across every client's incidents.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import current_user, require_admin
from ..db.models import Exclusion, ExclusionSuggestion, User
from ..db.session import get_session
from ..exclusions import auto_tune

router = APIRouter()

_VALID_TYPES = ("ip", "cidr", "domain", "hash")


# ── Schemas ──────────────────────────────────────────────────────────────
class ExclusionCreate(BaseModel):
    value: str
    ioc_type: str
    notes: str | None = None
    enabled: bool = True
    customer: str | None = None


class ExclusionPatch(BaseModel):
    value: str | None = None
    ioc_type: str | None = None
    notes: str | None = None
    enabled: bool | None = None


def _out(r: Exclusion) -> dict:
    return {
        "id": str(r.id),
        "value": r.value,
        "ioc_type": r.ioc_type,
        "notes": r.notes,
        "enabled": r.enabled,
        "customer": r.customer,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


def _suggestion_out(s: ExclusionSuggestion) -> dict:
    return {
        "id": str(s.id),
        "value": s.value,
        "ioc_type": s.ioc_type,
        "customer": s.customer,
        "fp_count": s.fp_count,
        "distinct_rules": len(s.seen_rules or []),
        "seen_rules": s.seen_rules or [],
        "distinct_incidents": len(s.seen_incidents or []),
        "last_rule_name": s.last_rule_name,
        "confidence": s.confidence,
        "status": s.status,
        "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else None,
        "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
    }


def _validate(value: str, ioc_type: str) -> None:
    if ioc_type not in _VALID_TYPES:
        raise HTTPException(400, f"ioc_type must be one of: {', '.join(_VALID_TYPES)}")
    v = (value or "").strip()
    if not v:
        raise HTTPException(400, "value cannot be empty")
    if ioc_type == "ip":
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise HTTPException(400, f"`{v}` is not a valid IP address")
    elif ioc_type == "cidr":
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise HTTPException(400, f"`{v}` is not a valid CIDR network")
    elif ioc_type == "hash":
        if len(v) not in (32, 40, 64, 128):  # md5, sha1, sha256, sha512
            raise HTTPException(
                400, "hash length must be 32 (md5), 40 (sha1), 64 (sha256), or 128 (sha512)"
            )
        if not all(c in "0123456789abcdefABCDEF" for c in v):
            raise HTTPException(400, "hash must be hex")
    # domain: light check — no scheme, has a dot, no slashes
    elif ioc_type == "domain":
        if "://" in v or "/" in v or " " in v or "." not in v:
            raise HTTPException(400, "domain must be a bare hostname (no scheme, no path)")


# ── Endpoints ────────────────────────────────────────────────────────────
@router.get("")
async def list_exclusions(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    q: str | None = Query(None, description="substring search on value or notes"),
    ioc_type: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    where = []
    if q:
        like = f"%{q}%"
        where.append((Exclusion.value.ilike(like)) | (Exclusion.notes.ilike(like)))
    if ioc_type:
        where.append(Exclusion.ioc_type == ioc_type)

    total_stmt = select(func.count(Exclusion.id))
    rows_stmt = select(Exclusion).order_by(Exclusion.created_at.desc())
    for clause in where:
        total_stmt = total_stmt.where(clause)
        rows_stmt = rows_stmt.where(clause)

    total = (await session.execute(total_stmt)).scalar() or 0
    rows = (await session.scalars(rows_stmt.limit(limit).offset(offset))).all()
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "items": [_out(r) for r in rows],
    }


@router.get("/stats")
async def stats(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
) -> dict:
    total = (await session.execute(select(func.count(Exclusion.id)))).scalar() or 0
    enabled = (
        await session.execute(select(func.count(Exclusion.id)).where(Exclusion.enabled.is_(True)))
    ).scalar() or 0
    by_type_rows = (
        await session.execute(
            select(Exclusion.ioc_type, func.count(Exclusion.id))
            .where(Exclusion.enabled.is_(True))
            .group_by(Exclusion.ioc_type)
        )
    ).all()
    return {
        "total": int(total),
        "enabled": int(enabled),
        "by_type": {k: int(n) for (k, n) in by_type_rows},
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_exclusion(
    body: ExclusionCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    _validate(body.value, body.ioc_type)
    r = Exclusion(
        value=body.value.strip(),
        ioc_type=body.ioc_type,
        notes=body.notes,
        enabled=body.enabled,
        customer=(body.customer or None),
        created_by_id=user.id,
    )
    session.add(r)
    try:
        await session.flush()
    except Exception:
        raise HTTPException(409, "exclusion already exists for this (value, type)")
    await audit.log(
        session,
        user_id=user.id,
        action="exclusion.create",
        target_type="exclusion",
        target_id=r.id,
        diff={"value": r.value, "ioc_type": r.ioc_type},
    )
    return _out(r)


@router.patch("/{exclusion_id}")
async def patch_exclusion(
    exclusion_id: uuid.UUID,
    body: ExclusionPatch,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    r = await session.get(Exclusion, exclusion_id)
    if not r:
        raise HTTPException(404, "exclusion not found")

    updates = body.model_dump(exclude_unset=True)
    # Re-validate if value or type changed.
    new_value = updates.get("value", r.value)
    new_type = updates.get("ioc_type", r.ioc_type)
    if "value" in updates or "ioc_type" in updates:
        _validate(new_value, new_type)
    for k, v in updates.items():
        setattr(r, k, v)
    await audit.log(
        session,
        user_id=user.id,
        action="exclusion.patch",
        target_type="exclusion",
        target_id=r.id,
        diff=updates,
    )
    return _out(r)


@router.delete("/{exclusion_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_exclusion(
    exclusion_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
):
    r = await session.get(Exclusion, exclusion_id)
    if not r:
        raise HTTPException(404, "exclusion not found")
    await audit.log(
        session,
        user_id=user.id,
        action="exclusion.delete",
        target_type="exclusion",
        target_id=r.id,
        diff={"value": r.value, "ioc_type": r.ioc_type},
    )
    await session.delete(r)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Auto-tuned suggestion review queue (feature F8) ──────────────────────
@router.get("/suggestions")
async def list_suggestions(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    status_filter: str = Query("pending", alias="status"),
    ready_only: bool = Query(True, description="only suggestions with enough corroboration"),
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    """Candidate exclusions learned from repeated FP/Benign verdicts. These are
    NOT applied — an admin approves them into real (scoped) exclusions."""
    stmt = (
        select(ExclusionSuggestion)
        .where(ExclusionSuggestion.status == status_filter)
        .order_by(ExclusionSuggestion.confidence.desc(), ExclusionSuggestion.fp_count.desc())
        .limit(limit)
    )
    rows = (await session.scalars(stmt)).all()
    if ready_only and status_filter == "pending":
        rows = [s for s in rows if auto_tune.is_promotable(s)]
    return {"items": [_suggestion_out(s) for s in rows], "count": len(rows)}


@router.post("/suggestions/{suggestion_id}/approve", status_code=status.HTTP_201_CREATED)
async def approve_suggestion(
    suggestion_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    """Promote a suggestion into a real, customer-scoped exclusion."""
    s = await session.get(ExclusionSuggestion, suggestion_id)
    if not s:
        raise HTTPException(404, "suggestion not found")
    if s.status == "approved":
        raise HTTPException(409, "suggestion already approved")

    _validate(s.value, s.ioc_type)
    note = (
        f"auto-tuned from {s.fp_count} FP/Benign verdict(s) across "
        f"{len(s.seen_rules or [])} rule(s)" + (f" for {s.customer}" if s.customer else "")
    )
    r = Exclusion(
        value=s.value.strip(),
        ioc_type=s.ioc_type,
        notes=note,
        enabled=True,
        customer=s.customer,
        created_by_id=user.id,
    )
    session.add(r)
    try:
        await session.flush()
    except Exception:
        # A global/scoped rule for this (value,type) already exists — treat the
        # suggestion as satisfied rather than erroring.
        await session.rollback()
        s = await session.get(ExclusionSuggestion, suggestion_id)
        if s:
            s.status = "approved"
        raise HTTPException(409, "an exclusion for this (value, type) already exists")
    s.status = "approved"
    await audit.log(
        session,
        user_id=user.id,
        action="exclusion.suggestion.approve",
        target_type="exclusion",
        target_id=r.id,
        diff={"value": r.value, "ioc_type": r.ioc_type, "customer": r.customer},
    )
    return _out(r)


@router.post("/suggestions/{suggestion_id}/dismiss")
async def dismiss_suggestion(
    suggestion_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    """Reject a suggestion. It will not be resurrected by future verdicts."""
    s = await session.get(ExclusionSuggestion, suggestion_id)
    if not s:
        raise HTTPException(404, "suggestion not found")
    s.status = "dismissed"
    await audit.log(
        session,
        user_id=user.id,
        action="exclusion.suggestion.dismiss",
        target_type="exclusion_suggestion",
        target_id=s.id,
        diff={"value": s.value, "ioc_type": s.ioc_type},
    )
    return _suggestion_out(s)
