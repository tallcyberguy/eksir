"""RBAC (3.10) — permission catalogue + the single enforcement resolver.

AiSOC's bug: 133 routes used a static role→perm map while only ~5 consulted the
DB, so custom roles were cosmetic and `roles:*` existed in the DB but not the
static map. isoc avoids it by keeping the existing coarse gate (`require_role`)
on all current routes and adding `require_permission` ONLY on the new RBAC
routes, backed by a resolver that **unions** a user's DB role-permissions with a
**static fallback** derived from `User.role`. A user with zero `user_roles` rows
authorizes exactly as today; custom roles can only ADD perms, never demote below
the coarse gate. `effective_permissions` is pure + unit-tested.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.enums import Role
from ..db.models import Permission, RolePermission, User, UserRole
from ..db.session import get_session
from .deps import current_user

WILDCARD = "*"

# (name, category, description) — trimmed to isoc's actual surfaces.
CATALOGUE: list[tuple[str, str, str]] = [
    ("incidents:read", "incidents", "View incidents and timelines"),
    ("incidents:write", "incidents", "Edit incidents, notes, assignment"),
    ("incidents:approve", "incidents", "Sign off a verdict at the gate"),
    ("incidents:delete", "incidents", "Archive / delete incidents"),
    ("cases:read", "cases", "View customer-facing cases"),
    ("cases:write", "cases", "Edit / send customer notifications"),
    ("forensics:read", "forensics", "View forensic jobs and reports"),
    ("forensics:run", "forensics", "Submit forensic analysis jobs"),
    ("threat_intel:read", "threat_intel", "View IOC feed and matches"),
    ("threat_intel:write", "threat_intel", "Manage threat feeds"),
    ("exclusions:read", "exclusions", "View exclusion rules"),
    ("exclusions:write", "exclusions", "Manage exclusion rules"),
    ("knowledge_base:read", "knowledge_base", "View knowledge base"),
    ("knowledge_base:write", "knowledge_base", "Edit knowledge base"),
    ("v1actions:read", "v1actions", "View response actions"),
    ("v1actions:execute", "v1actions", "Run approved response actions"),
    ("integrations:read", "integrations", "View integrations"),
    ("integrations:write", "integrations", "Manage integration credentials"),
    ("users:read", "users", "View users"),
    ("users:write", "users", "Create / edit users"),
    ("users:delete", "users", "Delete users"),
    ("roles:read", "roles", "View roles and permissions"),
    ("roles:write", "roles", "Create / edit roles and assignments"),
    ("audit:read", "audit", "View the audit log"),
    ("admin:read", "admin", "View administration"),
    ("admin:write", "admin", "Change administration settings"),
]

ALL_PERMS: set[str] = {name for name, _, _ in CATALOGUE}
_READ_PERMS: set[str] = {p for p in ALL_PERMS if p.endswith(":read")}

# Writes an L2 analyst legitimately performs (NOT user/role/admin mgmt or delete).
_ANALYST_WRITES: set[str] = {
    "incidents:write",
    "incidents:approve",
    "cases:write",
    "threat_intel:write",
    "exclusions:write",
    "knowledge_base:write",
    "forensics:run",
    "v1actions:execute",
}

# The conservative bridge — reproduces today's coarse `require_role` gate as perms.
STATIC_FALLBACK: dict[Role, set[str]] = {
    Role.ADMIN: {WILDCARD},
    Role.ANALYST: _READ_PERMS | _ANALYST_WRITES,
    Role.VIEWER: set(_READ_PERMS),
}


def effective_permissions(role: Role, db_perms: set[str]) -> set[str]:
    """Pure: the authority set for a user given their coarse role + any DB
    role-permissions. Admin bypasses (wildcard). No DB roles → exactly the
    static fallback (today's behavior). Otherwise union — never demotes."""
    if role == Role.ADMIN:
        return {WILDCARD}
    fb = set(STATIC_FALLBACK.get(role, set()))
    if not db_perms:
        return fb
    return fb | set(db_perms)


def has_permission(perms: set[str], perm: str) -> bool:
    return WILDCARD in perms or perm in perms


async def resolve_permissions(user: User, session: AsyncSession) -> set[str]:
    if user.role == Role.ADMIN:
        return {WILDCARD}
    db_perms = set(
        (
            await session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user.id)
            )
        )
        .scalars()
        .all()
    )
    return effective_permissions(user.role, db_perms)


def require_permission(perm: str):
    """FastAPI dep factory — 403 unless the resolved set grants `perm`."""

    async def _dep(
        user: Annotated[User, Depends(current_user)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> User:
        perms = await resolve_permissions(user, session)
        if not has_permission(perms, perm):
            raise HTTPException(403, f"missing permission: {perm}")
        return user

    return _dep
