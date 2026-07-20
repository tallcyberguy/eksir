"""BYOK — per-tenant LLM credential resolution (Settings → Deployment & AI).

Layers ABOVE the global admin `llm_config`: `resolve_tenant_llm(tenant_id)`
returns the tenant's *enabled* override (decrypted, with the provider's default
base URL filled in), or None to fall back to the admin/env config. Reuses the
Fernet helpers from `config_store`. **Never raises** — a DB or decrypt hiccup
resolves to None so inference falls back cleanly.
"""

from __future__ import annotations

import uuid as _uuid
from dataclasses import dataclass

from ..logging_config import get_logger
from .config_store import decrypt_secret

logger = get_logger("isoc.llm.byok")

# Providers the BYOK editor accepts. SaaS authenticate by api_key (base_url
# optional → provider default); local/custom authenticate by base_url.
BYOK_PROVIDERS = (
    "openai",
    "anthropic",
    "azure_openai",
    "ollama",
    "vllm",
    "litellm",
    "custom",
)
_SAAS = {"openai", "anthropic", "azure_openai"}
_LOCAL = {"ollama", "vllm", "litellm", "custom"}

# Default OpenAI-compatible base URL for SaaS providers that don't need an
# explicit one. (Anthropic ships an OpenAI-compatible endpoint.)
_DEFAULT_BASE_URL = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}


def provider_requires_api_key(provider: str) -> bool:
    return provider in _SAAS


def provider_requires_base_url(provider: str) -> bool:
    # azure_openai needs an explicit resource endpoint; local providers need a host.
    return provider in _LOCAL or provider == "azure_openai"


@dataclass(slots=True)
class TenantLLM:
    provider: str
    base_url: str | None  # effective (row value, else provider default); None if unknown
    model: str | None  # None → caller falls back to admin/env model
    api_key: str  # decrypted; "" when the row stores no key (local no-auth)


def _coerce_uuid(tenant_id: object) -> _uuid.UUID | None:
    if isinstance(tenant_id, _uuid.UUID):
        return tenant_id
    try:
        return _uuid.UUID(str(tenant_id))
    except (ValueError, TypeError):
        return None


async def resolve_tenant_llm(tenant_id: object) -> TenantLLM | None:
    """The enabled BYOK override for a tenant, or None. Never raises."""
    tid = _coerce_uuid(tenant_id)
    if tid is None:
        return None

    from ..db.models import TenantLLMCredential
    from ..db.session import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as session:
            row = await session.get(TenantLLMCredential, tid)
        if row is None or not row.enabled:
            return None
        key = ""
        if row.api_key_encrypted:
            try:
                key = decrypt_secret(row.api_key_encrypted)
            except Exception as exc:
                logger.warning("byok.decrypt_failed", error=str(exc))
                key = ""
        base_url = row.base_url or _DEFAULT_BASE_URL.get(row.provider)
        return TenantLLM(provider=row.provider, base_url=base_url, model=row.model, api_key=key)
    except Exception as exc:
        logger.warning("byok.resolve_failed", error=str(exc))
        return None
