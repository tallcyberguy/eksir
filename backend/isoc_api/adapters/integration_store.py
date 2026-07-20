"""Per-customer integration credentials — the resolution seam (ADR-0003 / ADR-0005).

Resolution order for Vision One (most specific first):
  1. `integrations` row (provider='vision_one', identifier=<customer>, enabled)
  2. `integrations` row (provider='vision_one', identifier='default', enabled)  ← global row
  3. env-var fallback: settings.v1_api_key + settings.v1_region

Multi-tenant isolation: with `settings.strict_tenant_creds` ON, steps 2 and 3 are
REFUSED for a named customer — only that customer's own row resolves, else None (fail
closed). This applies to every provider (the generic `get_creds` path too), so an
unmapped customer can never borrow another tenant's / a shared key.

Keys are Fernet-encrypted at rest (reusing llm.config_store helpers) and only ever
returned decrypted to the backend (never to the API/UI — see routes/admin.py masking).

Resolving credentials and region **together** is deliberate: the V1 JWT carries no
region claim and a token only authenticates against its own region, so a region
parsed from an alert console URL is a *hint*, honoured only when it matches the
credential's configured region.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from ..llm.config_store import decrypt_secret
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.integration_store")

V1_PROVIDER = "vision_one"
V1_DEFAULT_IDENTIFIER = "default"
DEFAULT_IDENTIFIER = "default"


@dataclass(slots=True)
class V1Creds:
    api_key: str  # plaintext bearer token
    region: str  # us | eu | jp | au | sg | in | mea
    source: str  # "integration" (DB row) | "global" (env fallback)


@dataclass(slots=True)
class Creds:
    """Generic resolved credential for any EDR/XDR/TI provider (F2 seam)."""

    provider: str
    identifier: str  # the row that matched ('default' or a specific customer/host)
    api_key: str  # decrypted bearer/api key; "" when the row stores no key
    base_url: str | None  # console host / endpoint, when configured
    region: str | None
    source: str = "integration"
    # OAuth client credentials (crowdstrike / microsoft_defender). Empty when the
    # provider authenticates with a single api_key instead.
    client_id: str | None = None
    client_secret: str = ""  # decrypted; "" when the row stores no secret
    oauth_tenant_id: str | None = None


def _is_named_customer(identifier: str | None) -> bool:
    """A specific tenant identifier that must be isolated (not the global 'default')."""
    return bool(identifier) and identifier != DEFAULT_IDENTIFIER


def _candidate_identifiers(identifier: str | None) -> list[str]:
    """Most-specific → global resolution order: [identifier, 'default'].

    In strict-tenant mode (``settings.strict_tenant_creds``) a NAMED customer must have
    its OWN row — the 'default' fallback is dropped, so an unmapped customer fails closed
    (no creds) rather than borrowing a shared key. Global lookups (identifier None/'default')
    are unaffected.
    """
    ids: list[str] = []
    if identifier:
        ids.append(identifier)
    # Append the global 'default' fallback unless (a) the identifier already IS 'default',
    # or (b) strict mode isolates a named customer.
    if identifier != DEFAULT_IDENTIFIER and not (
        settings.strict_tenant_creds and _is_named_customer(identifier)
    ):
        ids.append(DEFAULT_IDENTIFIER)
    return ids


async def _fetch_row(provider: str, identifier: str | None):
    """Best-matching enabled `integrations` row for (provider, identifier).

    Own short-lived session (mirrors `_fetch_v1_row`). Never raises — a DB hiccup
    resolves to None so callers fall back cleanly.
    """
    from ..db.models import Integration
    from ..db.session import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as session:
            for ident in _candidate_identifiers(identifier):
                row = (
                    await session.execute(
                        select(Integration).where(
                            Integration.provider == provider,
                            Integration.identifier == ident,
                            Integration.enabled.is_(True),
                        )
                    )
                ).scalar_one_or_none()
                if row is not None:
                    return row
    except Exception as exc:
        logger.warning("integration_store.fetch_failed", provider=provider, error=str(exc))
    return None


async def get_creds(provider: str, identifier: str | None = None) -> Creds | None:
    """Resolve credentials for any provider from the `integrations` table.

    The generalized seam behind every EDR/XDR/TI/recon integration (Connectors,
    Hunt, EASM, credentialed TI feeds). Resolution is customer/host-specific →
    global ('default'). Returns None when nothing enabled is configured. The
    decrypted key may be "" (some providers authenticate by base_url only) — the
    caller decides whether that's usable. Never raises.

    NOTE: Vision One keeps its own `get_creds_v1` because it additionally folds in
    the env-var fallback and the region-hint reconciliation; this generic path is
    DB-only by design.
    """
    row = await _fetch_row(provider, identifier)
    if row is None:
        return None
    key = ""
    if row.api_key_encrypted:
        try:
            key = decrypt_secret(row.api_key_encrypted)
        except Exception as exc:
            logger.warning("integration_store.decrypt_failed", provider=provider, error=str(exc))
            key = ""
    client_secret = ""
    if getattr(row, "client_secret_encrypted", None):
        try:
            client_secret = decrypt_secret(row.client_secret_encrypted)
        except Exception as exc:
            logger.warning(
                "integration_store.decrypt_failed",
                provider=provider,
                field="client_secret",
                error=str(exc),
            )
            client_secret = ""
    return Creds(
        provider=provider,
        identifier=row.identifier,
        api_key=key,
        base_url=row.base_url,
        region=row.region,
        source="integration",
        client_id=getattr(row, "client_id", None),
        client_secret=client_secret,
        oauth_tenant_id=getattr(row, "oauth_tenant_id", None),
    )


async def list_identifiers(provider: str) -> list[dict]:
    """Enabled `integrations` rows for a provider → [{identifier, label, region}].

    Powers the global Actions page tenant pickers (which customer/tenant an ad-hoc
    response action fires against). Never raises — a DB hiccup returns []."""
    from ..db.models import Integration
    from ..db.session import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as session:
            rows = (
                (
                    await session.execute(
                        select(Integration)
                        .where(
                            Integration.provider == provider,
                            Integration.enabled.is_(True),
                        )
                        .order_by(Integration.identifier)
                    )
                )
                .scalars()
                .all()
            )
            return [
                {"identifier": r.identifier, "label": r.label or r.identifier, "region": r.region}
                for r in rows
            ]
    except Exception as exc:
        logger.warning("integration_store.list_failed", provider=provider, error=str(exc))
        return []


async def _fetch_v1_row(customer: str | None):
    """Return the best-matching enabled vision_one Integration row, or None.

    Own short-lived session (callers don't pass one — mirrors config_store).
    """
    from ..db.models import Integration
    from ..db.session import AsyncSessionLocal

    # Same most-specific→global order + strict-tenant guard as the generic path.
    identifiers = _candidate_identifiers(customer)

    try:
        async with AsyncSessionLocal() as session:
            for ident in identifiers:
                row = (
                    await session.execute(
                        select(Integration).where(
                            Integration.provider == V1_PROVIDER,
                            Integration.identifier == ident,
                            Integration.enabled.is_(True),
                        )
                    )
                ).scalar_one_or_none()
                if row is not None:
                    return row
    except Exception as exc:  # never let a DB hiccup break enrichment — fall back to env
        logger.warning("integration_store.fetch_failed", error=str(exc))
    return None


async def get_creds_v1(customer: str | None, *, region_hint: str | None = None) -> V1Creds | None:
    """Resolve (api_key, region) for a customer's Vision One tenant.

    DB row (customer-specific → global) first, else the env-var fallback. Returns
    None when nothing is configured. `region_hint` (parsed from the alert console
    URL) is honoured only when it matches the resolved region.
    """
    row = await _fetch_v1_row(customer)
    if row is not None and row.api_key_encrypted:
        try:
            key = decrypt_secret(row.api_key_encrypted)
        except Exception as exc:
            logger.warning("integration_store.decrypt_failed", error=str(exc))
            key = ""
        if key:
            region = (row.region or settings.v1_region).lower()
            if region_hint and region_hint.lower() == region:
                region = region_hint.lower()
            return V1Creds(api_key=key, region=region, source="integration")

    # env-var fallback (single-tenant global key) — refused in strict-tenant mode for a
    # named customer, so they fail closed instead of borrowing the shared global key.
    if settings.v1_api_key and not (settings.strict_tenant_creds and _is_named_customer(customer)):
        region = settings.v1_region.lower()
        if region_hint and region_hint.lower() == region:
            region = region_hint.lower()
        return V1Creds(
            api_key=settings.v1_api_key.get_secret_value(), region=region, source="global"
        )

    return None
