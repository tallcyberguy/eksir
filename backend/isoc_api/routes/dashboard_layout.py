"""Per-user + per-tenant dashboard layout persistence.

Hierarchy (highest priority first):
  1. users.dashboard_layout   — personal override
  2. tenants.dashboard_layout — admin-set default for the user's first tenant
  3. NULL                     — frontend falls back to the built-in default

The layout JSONB shape matches react-grid-layout's `Layouts` prop:
  {
    "lg": [{"i": "kpi-incidents", "x": 0, "y": 0, "w": 3, "h": 2}, …],
    "md": [...],
    "sm": [...]
  }
Plus an optional `hidden: ["panel-id", ...]` array of panels the user
chose to remove. The frontend always renders the full set of available
panel ids, filtering out anything in `hidden` and applying coordinates
from the corresponding breakpoint array.

We don't validate the shape on the backend beyond "must be a JSON object" —
react-grid-layout itself rejects malformed entries at render time, and
constraining the shape here would force a backend deploy every time we
add a new panel.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user, require_admin
from ..db.models import Tenant, User, UserTenantMembership
from ..db.session import get_session

router = APIRouter()


class LayoutPayload(BaseModel):
    layout: dict[str, Any] | None = None


class EffectiveLayout(BaseModel):
    """What the dashboard page fetches on load: the layout to actually render
    plus which source it came from so the UI can show 'using tenant default'
    vs 'using personal override'."""

    layout: dict[str, Any] | None
    source: str  # "user" | "tenant" | "default"
    tenant_id: uuid.UUID | None = None


async def _first_tenant_for_user(session: AsyncSession, user_id: uuid.UUID) -> Tenant | None:
    """Pick the tenant whose default we apply for this user. Today we just
    take the first membership row by created_at — multi-tenant users with
    diverging tenant-default layouts is a UX rabbit hole I'd rather avoid
    until someone asks for it."""
    row = await session.scalar(
        select(UserTenantMembership)
        .where(UserTenantMembership.user_id == user_id)
        .order_by(UserTenantMembership.created_at)
        .limit(1)
    )
    if row is None:
        return None
    return await session.get(Tenant, row.tenant_id)


# ── User-scoped routes ─────────────────────────────────────────────────
@router.get("/me/dashboard-layout", response_model=EffectiveLayout)
async def get_my_layout(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> EffectiveLayout:
    if user.dashboard_layout:
        return EffectiveLayout(layout=user.dashboard_layout, source="user")

    tenant = await _first_tenant_for_user(session, user.id)
    if tenant and tenant.dashboard_layout:
        return EffectiveLayout(layout=tenant.dashboard_layout, source="tenant", tenant_id=tenant.id)

    return EffectiveLayout(layout=None, source="default", tenant_id=tenant.id if tenant else None)


@router.put("/me/dashboard-layout", response_model=EffectiveLayout)
async def save_my_layout(
    body: LayoutPayload,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> EffectiveLayout:
    """Persist the layout as the user's personal override.

    A `null` body resets to the tenant default (same as DELETE)."""
    if body.layout is None:
        return await delete_my_layout(session, user)
    user.dashboard_layout = body.layout
    await session.commit()
    return EffectiveLayout(layout=user.dashboard_layout, source="user")


@router.delete("/me/dashboard-layout", response_model=EffectiveLayout)
async def delete_my_layout(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> EffectiveLayout:
    """Clear the personal override; effective layout falls back to tenant default."""
    user.dashboard_layout = None
    await session.commit()

    tenant = await _first_tenant_for_user(session, user.id)
    if tenant and tenant.dashboard_layout:
        return EffectiveLayout(layout=tenant.dashboard_layout, source="tenant", tenant_id=tenant.id)
    return EffectiveLayout(layout=None, source="default", tenant_id=tenant.id if tenant else None)


# ── Tenant-scoped routes (admin only) ──────────────────────────────────
@router.get("/admin/tenants/{tenant_id}/dashboard-layout", response_model=LayoutPayload)
async def get_tenant_layout(
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> LayoutPayload:
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    return LayoutPayload(layout=tenant.dashboard_layout)


@router.put("/admin/tenants/{tenant_id}/dashboard-layout", response_model=LayoutPayload)
async def save_tenant_layout(
    tenant_id: uuid.UUID,
    body: LayoutPayload,
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> LayoutPayload:
    """Set the tenant default layout. A `null` body clears it (everyone in
    the tenant who hasn't set a personal override falls back to the built-in
    default)."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    tenant.dashboard_layout = body.layout
    await session.commit()
    return LayoutPayload(layout=tenant.dashboard_layout)
