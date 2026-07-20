"""EASM (Phase 3) — external asset register + on-demand recon.

`GET/POST/DELETE /easm/assets` manage the watched-asset register; `POST
/easm/assets/{id}/scan` runs read-only recon (DNS, SPF/DMARC posture, TLS expiry,
WHOIS) and stores the result; `GET /easm/overview` rolls up KPIs. Recon only
observes — it never changes external state, and there is no analyst gate to touch.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters import recon_adapter
from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, require_in_scope
from ..db.enums import Role
from ..db.models import EASMAsset, User
from ..db.session import get_session
from ..easm import recon

router = APIRouter()


def _asset_out(a: EASMAsset) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "value": a.value,
        "asset_type": a.asset_type,
        "tags": a.tags or [],
        "notes": a.notes,
        "enabled": a.enabled,
        "last_result": a.last_result,
        "last_scanned_at": a.last_scanned_at.isoformat() if a.last_scanned_at else None,
        "tenant_id": str(a.tenant_id) if a.tenant_id else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _visible(scope: TenantScope):
    if scope is None:
        return EASMAsset.id == EASMAsset.id
    if not scope:
        return EASMAsset.tenant_id.is_(None)
    return or_(EASMAsset.tenant_id.is_(None), EASMAsset.tenant_id.in_(scope))


@router.get("/assets")
async def list_assets(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    rows = (
        await session.scalars(
            select(EASMAsset).where(_visible(scope)).order_by(EASMAsset.created_at.desc())
        )
    ).all()
    return {"assets": [_asset_out(a) for a in rows]}


@router.get("/overview")
async def overview(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    rows = (await session.scalars(select(EASMAsset).where(_visible(scope)))).all()
    assets = [{"asset_type": a.asset_type, "last_result": a.last_result} for a in rows]
    out = recon.summarize(assets)
    out["generated_at"] = datetime.now(timezone.utc).isoformat()
    return out


class AssetIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=255)
    asset_type: str | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


@router.post("/assets")
async def add_asset(
    body: AssetIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    value = body.value.strip()
    asset_type = (body.asset_type or recon.classify_asset(value)).lower()
    tenant_id = next(iter(scope)) if scope and len(scope) == 1 else None
    a = EASMAsset(
        value=value,
        asset_type=asset_type,
        tags=body.tags or None,
        notes=body.notes,
        tenant_id=tenant_id,
        created_by_id=user.id,
    )
    session.add(a)
    await session.flush()
    return _asset_out(a)


@router.post("/assets/{asset_id}/scan")
async def scan_asset(
    asset_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    a = await session.get(EASMAsset, asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    require_in_scope(a.tenant_id, scope)
    result = await recon_adapter.scan_asset(a.value, a.asset_type)
    # Preserve a prior port scan (DNS recon and port scan are separate actions).
    prior = a.last_result or {}
    for k in ("ports", "ports_scanned_at", "ports_error"):
        if k in prior:
            result[k] = prior[k]
    result["risk"] = recon.risk_score(result)  # re-score including carried-over ports
    a.last_result = result
    a.last_scanned_at = datetime.now(timezone.utc)
    return _asset_out(a)


@router.post("/assets/{asset_id}/portscan")
async def portscan_asset(
    asset_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    """On-demand nmap port + service/version scan. Merges open ports into the
    asset's last_result and re-scores risk (exposed admin/db/cleartext services
    raise it). Read-only observation — nmap only probes, it changes nothing."""
    a = await session.get(EASMAsset, asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    require_in_scope(a.tenant_id, scope)
    scan = await recon_adapter.port_scan(a.value)
    # Merge into the existing result (keep DNS/posture/TLS/WHOIS if present).
    result = dict(a.last_result or {})
    result.setdefault("value", a.value)
    result.setdefault("asset_type", a.asset_type)
    result["ports"] = scan["ports"]
    result["ports_scanned_at"] = scan["ports_scanned_at"]
    result["ports_error"] = scan["ports_error"]
    result["risk"] = recon.risk_score(result)  # re-score with the new ports
    a.last_result = result
    a.last_scanned_at = datetime.now(timezone.utc)
    return _asset_out(a)


@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    a = await session.get(EASMAsset, asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    require_in_scope(a.tenant_id, scope)
    if a.created_by_id not in (None, user.id) and user.role != Role.ADMIN:
        raise HTTPException(403, "only the owner or an admin can delete this asset")
    await session.delete(a)
    return {"ok": True}
