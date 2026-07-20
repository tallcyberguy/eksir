"""Tenant scoping — who can see what.

A `TenantScope` is one of:
  • None    — unrestricted (global ADMIN or HOST-tenant member). Sees everything.
  • set()   — empty. User has no memberships and is not admin. Sees nothing.
  • {ids}   — user can see incidents whose tenant_id is in this set.

Apply scope at the WHERE clause of every list query and at the single-row
lookup of every detail / mutation route.
"""

from __future__ import annotations

import re
import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException
from sqlalchemy import false, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.enums import Role, TenantTier
from ..db.models import Tenant, User, UserTenantMembership
from ..db.session import get_session
from .deps import current_user

TenantScope = set[uuid.UUID] | None


# ── Scope resolution ─────────────────────────────────────────────────────


async def resolve_tenant_scope(user: User, session: AsyncSession) -> TenantScope:
    """Compute the set of tenant IDs this user is allowed to see."""
    # Global ADMIN role bypasses tenancy entirely.
    if user.role == Role.ADMIN:
        return None

    rows = (
        await session.execute(
            select(Tenant.id, Tenant.tier)
            .join(UserTenantMembership, UserTenantMembership.tenant_id == Tenant.id)
            .where(UserTenantMembership.user_id == user.id)
        )
    ).all()

    if not rows:
        return set()  # no memberships → sees nothing

    # HOST membership = unrestricted, same as global admin
    if any(tier == TenantTier.HOST for _, tier in rows):
        return None

    scope: set[uuid.UUID] = set()
    expand: list[uuid.UUID] = []
    for tid, tier in rows:
        scope.add(tid)
        if tier == TenantTier.MSSP:
            expand.append(tid)

    if expand:
        scope.update(await _descendants(expand, session))

    return scope


async def _descendants(parent_ids: list[uuid.UUID], session: AsyncSession) -> set[uuid.UUID]:
    """Walk the tenant tree downward from each parent_id. BFS; small N."""
    seen: set[uuid.UUID] = set(parent_ids)
    frontier: set[uuid.UUID] = set(parent_ids)
    while frontier:
        children = set(
            (await session.execute(select(Tenant.id).where(Tenant.parent_id.in_(frontier))))
            .scalars()
            .all()
        )
        new = children - seen
        if not new:
            break
        seen.update(new)
        frontier = new
    return seen


# FastAPI dep — supports an optional X-Tenant-Scope header override that
# narrows the scope to one tenant (+ its descendants), provided that tenant
# is within the user's natural scope. Used by the Topbar tenant switcher.
async def current_tenant_scope(
    user: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    x_tenant_scope: Annotated[str | None, Header(alias="X-Tenant-Scope")] = None,
) -> TenantScope:
    natural = await resolve_tenant_scope(user, session)
    if not x_tenant_scope:
        return natural

    try:
        override_id = uuid.UUID(x_tenant_scope)
    except ValueError:
        return natural  # malformed header — silently ignore

    # Validate: the override must be inside the user's natural scope.
    # natural=None means "admin / unlimited" → any existing tenant is allowed.
    if natural is not None and override_id not in natural:
        return natural
    # Sanity check: the tenant still exists.
    if not await session.scalar(select(Tenant.id).where(Tenant.id == override_id)):
        return natural

    # Effective scope = override + all its descendants.
    return await _descendants([override_id], session)


# ── Per-row + per-query helpers ──────────────────────────────────────────


def in_scope(tenant_id: uuid.UUID | None, scope: TenantScope) -> bool:
    """True if a row with the given tenant_id is visible under this scope."""
    if scope is None:
        return True
    if tenant_id is None:
        return False  # unassigned rows only visible to admins
    return tenant_id in scope


def scope_clause_for_incidents(scope: TenantScope):
    """Returns a SQLAlchemy where-clause expression for the Incident table.

    Use as:  stmt = stmt.where(scope_clause_for_incidents(scope))
    """
    from ..db.models import Incident

    if scope is None:
        return true_clause()
    if not scope:
        return false()
    return Incident.tenant_id.in_(scope)


def true_clause():
    """A WHERE-clause-compatible no-op (always true)."""
    from sqlalchemy import literal

    return literal(True)


# ── Tenant lookup / auto-create ──────────────────────────────────────────

_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


def slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name).strip("-").lower()
    return slug or "unnamed"


async def ensure_tenant_for_customer(session: AsyncSession, customer: str) -> uuid.UUID:
    """Return the tenant id for a customer name, creating a CLIENT tenant if
    needed. Idempotent — safe to call on every ingest."""
    name = customer.strip()
    if not name:
        raise ValueError("customer name must be non-empty")

    existing = await session.scalar(select(Tenant.id).where(Tenant.name == name))
    if existing:
        return existing

    base = slugify(name)
    slug = base
    n = 1
    # Resolve slug collisions deterministically
    while await session.scalar(select(Tenant.id).where(Tenant.slug == slug)):
        n += 1
        slug = f"{base}-{n}"

    t = Tenant(name=name, slug=slug, tier=TenantTier.CLIENT)
    session.add(t)
    await session.flush()
    return t.id


# ── Mutation-time access check ───────────────────────────────────────────


def require_in_scope(tenant_id: uuid.UUID | None, scope: TenantScope) -> None:
    """Raise 404 if the row is out of scope. 404 (not 403) so we don't leak
    existence to users who shouldn't know the incident exists."""
    if not in_scope(tenant_id, scope):
        raise HTTPException(404, "incident not found")
