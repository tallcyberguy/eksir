"""Audit log — list/detail with filters + free-text search."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope
from ..db.models import AuditLog, Tenant, User
from ..db.session import get_session

router = APIRouter()


def _scope_clause_for_audit(scope: TenantScope, viewer_user_id: uuid.UUID):
    """Audit visibility for scoped users:
      • entries they themselves created (any action), OR
      • entries tagged with a tenant_id they can see
    Admins (scope=None) bypass this. With Phase-5 every action that affects
    a tenant carries its tenant_id, so this is a direct column filter.
    """
    if scope is None:
        return None  # no filter
    if not scope:
        # Scoped to nothing → only their own actions
        return AuditLog.user_id == viewer_user_id
    return or_(
        AuditLog.user_id == viewer_user_id,
        AuditLog.tenant_id.in_(scope),
    )


@router.get("")
async def list_audit(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    action: str | None = Query(
        default=None, description="Action prefix or substring, e.g. 'incident.' or 'pipeline'"
    ),
    actor: str | None = Query(default=None, description="Actor email substring"),
    target_type: str | None = Query(default=None),
    target_id: uuid.UUID | None = Query(default=None),
    tenant_id: uuid.UUID | None = Query(default=None, description="Filter to one tenant"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    q: str | None = Query(default=None, description="Free-text search across action + diff JSON"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> dict:
    stmt = (
        select(AuditLog, User.email, Tenant.name.label("tenant_name"))
        .join(User, AuditLog.user_id == User.id, isouter=True)
        .join(Tenant, AuditLog.tenant_id == Tenant.id, isouter=True)
        .order_by(desc(AuditLog.ts))
    )

    audit_scope = _scope_clause_for_audit(scope, user.id)
    if audit_scope is not None:
        stmt = stmt.where(audit_scope)
    if tenant_id is not None:
        stmt = stmt.where(AuditLog.tenant_id == tenant_id)

    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action}%"))
    if actor:
        stmt = stmt.where(User.email.ilike(f"%{actor}%"))
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
    if until:
        stmt = stmt.where(AuditLog.ts <= until)
    if q:
        pat = f"%{q}%"
        stmt = stmt.where(
            or_(
                AuditLog.action.ilike(pat),
                cast(AuditLog.diff, String).ilike(pat),
                User.email.ilike(pat),
            )
        )

    # Total count (a separate query so we can paginate cleanly)
    count_stmt = stmt.with_only_columns(func.count(AuditLog.id)).order_by(None)
    total = (await session.execute(count_stmt)).scalar() or 0

    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await session.execute(stmt)).all()

    return {
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": str(row.AuditLog.id),
                "action": row.AuditLog.action,
                "target_type": row.AuditLog.target_type,
                "target_id": str(row.AuditLog.target_id) if row.AuditLog.target_id else None,
                "tenant_id": str(row.AuditLog.tenant_id) if row.AuditLog.tenant_id else None,
                "tenant_name": row.tenant_name,
                "diff": row.AuditLog.diff,
                "ts": row.AuditLog.ts.isoformat() if row.AuditLog.ts else None,
                "actor_email": row.email,
                "user_id": str(row.AuditLog.user_id) if row.AuditLog.user_id else None,
            }
            for row in rows
        ],
    }


@router.get("/facets")
async def facets(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    """Distinct action + target_type values — used to populate filter dropdowns."""
    audit_scope = _scope_clause_for_audit(scope, user.id)

    actions_q = select(AuditLog.action, func.count(AuditLog.id))
    targets_q = select(AuditLog.target_type, func.count(AuditLog.id)).where(
        AuditLog.target_type.is_not(None)
    )
    if audit_scope is not None:
        actions_q = actions_q.where(audit_scope)
        targets_q = targets_q.where(audit_scope)

    actions = (
        await session.execute(
            actions_q.group_by(AuditLog.action).order_by(desc(func.count(AuditLog.id))).limit(50)
        )
    ).all()
    targets = (
        await session.execute(
            targets_q.group_by(AuditLog.target_type).order_by(desc(func.count(AuditLog.id)))
        )
    ).all()
    return {
        "actions": [{"value": a, "count": int(c)} for a, c in actions],
        "target_types": [{"value": t, "count": int(c)} for t, c in targets],
    }


@router.get("/{entry_id}")
async def get_entry(
    entry_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    stmt = (
        select(AuditLog, User.email, Tenant.name.label("tenant_name"))
        .join(User, AuditLog.user_id == User.id, isouter=True)
        .join(Tenant, AuditLog.tenant_id == Tenant.id, isouter=True)
        .where(AuditLog.id == entry_id)
    )
    audit_scope = _scope_clause_for_audit(scope, user.id)
    if audit_scope is not None:
        stmt = stmt.where(audit_scope)
    row = (await session.execute(stmt)).first()
    if not row:
        raise HTTPException(404, "audit entry not found")
    return {
        "id": str(row.AuditLog.id),
        "action": row.AuditLog.action,
        "target_type": row.AuditLog.target_type,
        "target_id": str(row.AuditLog.target_id) if row.AuditLog.target_id else None,
        "tenant_id": str(row.AuditLog.tenant_id) if row.AuditLog.tenant_id else None,
        "tenant_name": row.tenant_name,
        "diff": row.AuditLog.diff,
        "ts": row.AuditLog.ts.isoformat() if row.AuditLog.ts else None,
        "actor_email": row.email,
        "user_id": str(row.AuditLog.user_id) if row.AuditLog.user_id else None,
    }
