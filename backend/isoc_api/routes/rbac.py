"""RBAC (3.10) — role / permission CRUD (admin).

Gated by the NEW `require_permission` dep (backed by the static-fallback resolver
in `auth/permissions.py`), so existing admins still pass. These routes only CRUD
authorization metadata — they never touch incidents, verdicts, or response
actions; the analyst gate (`routes/cases.py`) is untouched. Shaping logic lives
in pure, unit-tested builders.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.permissions import require_permission
from ..auth.tenancy import TenantScope, current_tenant_scope
from ..db.models import Permission, RBACRole, RolePermission, User, UserRole
from ..db.session import get_session

router = APIRouter()


# ── pure builders ────────────────────────────────────────────────────────
def build_role_view(role: dict, perm_names: list[str]) -> dict[str, Any]:
    return {
        "id": str(role["id"]),
        "tenant_id": str(role["tenant_id"]) if role.get("tenant_id") else None,
        "name": role["name"],
        "description": role.get("description"),
        "is_system": bool(role.get("is_system")),
        "permissions": sorted(perm_names),
        "permission_count": len(perm_names),
    }


def build_permission_matrix(perms: list[dict]) -> dict[str, list[dict]]:
    """Group permissions by category for the checkbox matrix (stable order)."""
    out: dict[str, list[dict]] = {}
    for p in sorted(perms, key=lambda x: (x.get("category") or "", x["name"])):
        out.setdefault(p.get("category") or "other", []).append(
            {"id": str(p["id"]), "name": p["name"], "description": p.get("description")}
        )
    return out


def validate_role_mutation(
    role_is_system: bool, perm_ids: list[str], known_perm_ids: set[str]
) -> str | None:
    """Returns an error reason, or None if the mutation is allowed."""
    if role_is_system:
        return "system roles are read-only"
    unknown = [p for p in perm_ids if p not in known_perm_ids]
    if unknown:
        return f"unknown permission ids: {', '.join(unknown)}"
    return None


def _role_visibility(scope: TenantScope):
    # Global (system) roles are always visible; tenant roles only within scope.
    if scope is None:
        return RBACRole.id == RBACRole.id  # all
    if not scope:
        return RBACRole.tenant_id.is_(None)
    return or_(RBACRole.tenant_id.is_(None), RBACRole.tenant_id.in_(scope))


# ── permissions ──────────────────────────────────────────────────────────
@router.get("/permissions")
async def list_permissions(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_permission("roles:read"))],
) -> dict[str, Any]:
    rows = (await session.execute(select(Permission))).scalars().all()
    perms = [
        {"id": r.id, "name": r.name, "category": r.category, "description": r.description}
        for r in rows
    ]
    return {"permissions": build_permission_matrix(perms), "count": len(perms)}


# ── roles ────────────────────────────────────────────────────────────────
async def _perm_names_for_role(session: AsyncSession, role_id: uuid.UUID) -> list[str]:
    return list(
        (
            await session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .where(RolePermission.role_id == role_id)
            )
        )
        .scalars()
        .all()
    )


@router.get("/roles")
async def list_roles(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_permission("roles:read"))],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    roles = (await session.execute(select(RBACRole).where(_role_visibility(scope)))).scalars().all()
    counts = dict(
        (
            await session.execute(
                select(RolePermission.role_id, func.count()).group_by(RolePermission.role_id)
            )
        ).all()
    )
    out = [
        {
            "id": str(r.id),
            "tenant_id": str(r.tenant_id) if r.tenant_id else None,
            "name": r.name,
            "description": r.description,
            "is_system": r.is_system,
            "permission_count": int(counts.get(r.id, 0)),
        }
        for r in roles
    ]
    out.sort(key=lambda x: (not x["is_system"], x["name"]))
    return {"roles": out}


@router.get("/roles/{role_id}")
async def get_role(
    role_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_permission("roles:read"))],
) -> dict[str, Any]:
    role = await session.get(RBACRole, role_id)
    if role is None:
        raise HTTPException(404, "role not found")
    names = await _perm_names_for_role(session, role_id)
    return build_role_view(
        {
            "id": role.id,
            "tenant_id": role.tenant_id,
            "name": role.name,
            "description": role.description,
            "is_system": role.is_system,
        },
        names,
    )


class RoleIn(BaseModel):
    name: str
    description: str | None = None
    permission_ids: list[str] = []


async def _known_perm_ids(session: AsyncSession) -> dict[str, uuid.UUID]:
    rows = (await session.execute(select(Permission.id))).scalars().all()
    return {str(r): r for r in rows}


@router.post("/roles")
async def create_role(
    body: RoleIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_permission("roles:write"))],
) -> dict[str, Any]:
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")
    known = await _known_perm_ids(session)
    err = validate_role_mutation(False, body.permission_ids, set(known))
    if err:
        raise HTTPException(400, err)
    # Custom roles are global (tenant_id NULL) in v1; name must not clash.
    exists = await session.scalar(
        select(RBACRole.id).where(RBACRole.tenant_id.is_(None), RBACRole.name == name)
    )
    if exists:
        raise HTTPException(409, f"a role named '{name}' already exists")

    role = RBACRole(name=name, description=body.description, is_system=False, tenant_id=None)
    session.add(role)
    await session.flush()
    for pid in body.permission_ids:
        session.add(RolePermission(role_id=role.id, permission_id=known[pid]))
    await audit.log(
        session,
        user_id=user.id,
        action="rbac.role.create",
        target_type="role",
        target_id=role.id,
        diff={"name": name},
    )
    return {"id": str(role.id), "name": name}


@router.patch("/roles/{role_id}")
async def update_role(
    role_id: uuid.UUID,
    body: RoleIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_permission("roles:write"))],
) -> dict[str, Any]:
    role = await session.get(RBACRole, role_id)
    if role is None:
        raise HTTPException(404, "role not found")
    known = await _known_perm_ids(session)
    err = validate_role_mutation(role.is_system, body.permission_ids, set(known))
    if err:
        raise HTTPException(403 if role.is_system else 400, err)

    role.name = body.name.strip() or role.name
    role.description = body.description
    # Replace the permission set wholesale.
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    for pid in body.permission_ids:
        session.add(RolePermission(role_id=role_id, permission_id=known[pid]))
    await audit.log(
        session,
        user_id=user.id,
        action="rbac.role.update",
        target_type="role",
        target_id=role_id,
        diff={"permissions": len(body.permission_ids)},
    )
    return {"ok": True}


@router.delete("/roles/{role_id}")
async def delete_role(
    role_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_permission("roles:write"))],
) -> dict[str, Any]:
    role = await session.get(RBACRole, role_id)
    if role is None:
        raise HTTPException(404, "role not found")
    if role.is_system:
        raise HTTPException(403, "system roles cannot be deleted")
    await session.delete(role)
    await audit.log(
        session,
        user_id=user.id,
        action="rbac.role.delete",
        target_type="role",
        target_id=role_id,
        diff={"name": role.name},
    )
    return {"ok": True}


# ── user ↔ role assignment ───────────────────────────────────────────────
class AssignIn(BaseModel):
    role_id: uuid.UUID


@router.post("/users/{user_id}/roles")
async def assign_role(
    user_id: uuid.UUID,
    body: AssignIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    actor: Annotated[User, Depends(require_permission("roles:write"))],
) -> dict[str, Any]:
    if await session.get(User, user_id) is None:
        raise HTTPException(404, "user not found")
    if await session.get(RBACRole, body.role_id) is None:
        raise HTTPException(404, "role not found")
    exists = await session.get(UserRole, {"user_id": user_id, "role_id": body.role_id})
    if exists is None:
        session.add(UserRole(user_id=user_id, role_id=body.role_id, assigned_by=actor.id))
        await audit.log(
            session,
            user_id=actor.id,
            action="rbac.user_role.assign",
            target_type="user",
            target_id=user_id,
            diff={"role_id": str(body.role_id)},
        )
    return {"ok": True}


@router.delete("/users/{user_id}/roles/{role_id}")
async def remove_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    actor: Annotated[User, Depends(require_permission("roles:write"))],
) -> dict[str, Any]:
    await session.execute(
        delete(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    await audit.log(
        session,
        user_id=actor.id,
        action="rbac.user_role.remove",
        target_type="user",
        target_id=user_id,
        diff={"role_id": str(role_id)},
    )
    return {"ok": True}
