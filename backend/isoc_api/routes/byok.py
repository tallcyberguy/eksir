"""BYOK — per-tenant LLM provider overrides (Settings → Deployment & AI).

Admin-managed CRUD over `tenant_llm_credentials`. The API key is Fernet-encrypted
at rest and **write-only**: GET never returns it (only `has_api_key`). An enabled
row overrides the global `llm_config` for that tenant's synthesis (resolved in
`llm/byok_store.py` + `llm/client._resolve_call`).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import require_admin
from ..db.models import Tenant, TenantLLMCredential, User
from ..db.session import get_session
from ..llm.byok_store import (
    BYOK_PROVIDERS,
    provider_requires_api_key,
    provider_requires_base_url,
)
from ..llm.config_store import encrypt_secret
from ..security import url_safety

router = APIRouter()


class BYOKIn(BaseModel):
    tenant_id: uuid.UUID
    provider: str = Field(..., description=f"one of: {', '.join(BYOK_PROVIDERS)}")
    base_url: str | None = Field(
        None, max_length=500, description="endpoint; provider default if omitted (SaaS)"
    )
    model: str | None = Field(
        None, max_length=200, description="model id; falls back to global/env if omitted"
    )
    api_key: str | None = Field(None, description="omit/null on update to keep the existing key")
    enabled: bool = True


class BYOKOut(BaseModel):
    tenant_id: str
    provider: str
    base_url: str | None
    model: str | None
    has_api_key: bool  # never the key itself
    enabled: bool
    last_rotated_at: str | None
    updated_at: str | None


def _out(row: TenantLLMCredential) -> BYOKOut:
    return BYOKOut(
        tenant_id=str(row.tenant_id),
        provider=row.provider,
        base_url=row.base_url,
        model=row.model,
        has_api_key=bool(row.api_key_encrypted),
        enabled=row.enabled,
        last_rotated_at=row.last_rotated_at.isoformat() if row.last_rotated_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _validate(body: BYOKIn, *, existing_has_key: bool) -> None:
    if body.provider not in BYOK_PROVIDERS:
        raise HTTPException(400, f"provider must be one of {BYOK_PROVIDERS}")
    if provider_requires_base_url(body.provider) and not body.base_url:
        raise HTTPException(400, f"{body.provider} requires base_url")
    if provider_requires_api_key(body.provider) and not body.api_key and not existing_has_key:
        raise HTTPException(400, f"{body.provider} requires api_key")


@router.get("", response_model=list[BYOKOut])
async def list_byok(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[BYOKOut]:
    rows = (await session.scalars(select(TenantLLMCredential))).all()
    return [_out(r) for r in rows]


@router.get("/{tenant_id}", response_model=BYOKOut | None)
async def get_byok(
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> BYOKOut | None:
    row = await session.get(TenantLLMCredential, tenant_id)
    return _out(row) if row else None


@router.put("", response_model=BYOKOut)
async def upsert_byok(
    body: BYOKIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> BYOKOut:
    if not await session.get(Tenant, body.tenant_id):
        raise HTTPException(404, "tenant not found")

    row = await session.get(TenantLLMCredential, body.tenant_id)
    _validate(body, existing_has_key=bool(row and row.api_key_encrypted))
    if body.base_url:
        # BYOK endpoints may be internal (a tenant's own LiteLLM), so allow
        # private/loopback but block the cloud metadata address + bad shapes.
        try:
            await url_safety.assert_endpoint_url(body.base_url)
        except url_safety.UrlSafetyError as e:
            raise HTTPException(400, f"base_url rejected (SSRF guard): {e}") from e

    rotated = False
    if row is None:
        row = TenantLLMCredential(tenant_id=body.tenant_id)
        session.add(row)
    # A provider switch invalidates the stored key — require a fresh one for SaaS.
    if (
        row.api_key_encrypted
        and row.provider != body.provider
        and provider_requires_api_key(body.provider)
        and not body.api_key
    ):
        raise HTTPException(400, "changing provider requires a new api_key")

    row.provider = body.provider
    row.base_url = body.base_url
    row.model = body.model
    row.enabled = body.enabled
    row.updated_by_id = admin.id
    if body.api_key is not None:  # omit/null → keep existing key
        row.api_key_encrypted = encrypt_secret(body.api_key)
        row.last_rotated_at = datetime.now(timezone.utc)
        rotated = True

    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="byok.upsert",
        target_type="tenant_llm_credential",
        target_id=None,
        tenant_id=row.tenant_id,
        diff={"provider": row.provider, "enabled": row.enabled, "rotated": rotated},
    )
    return _out(row)


@router.delete("/{tenant_id}", status_code=204)
async def delete_byok(
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    row = await session.get(TenantLLMCredential, tenant_id)
    if not row:
        raise HTTPException(404, "no BYOK credential for tenant")
    await audit.log(
        session,
        user_id=admin.id,
        action="byok.delete",
        target_type="tenant_llm_credential",
        target_id=None,
        tenant_id=tenant_id,
        diff={"provider": row.provider},
    )
    await session.delete(row)
