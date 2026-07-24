"""Per-customer integration credentials: the resolution seam (ADR-0003 / ADR-0005).

Every provider (Vision One, Microsoft Defender, SentinelOne, CrowdStrike, TI feeds,
...) resolves credentials the same way, keyed on the incident's customer:

  1. `integrations` row (provider, identifier=<customer>, enabled)
  2. `integrations` row (provider, identifier='default', enabled)  (global row)

Multi-tenant isolation: with `settings.strict_tenant_creds` ON, step 2 is REFUSED for a
named customer, so only that customer's own row resolves, else None (fail closed). An
unmapped customer can never borrow another tenant's or a shared key.

The resolved `Creds` carries whatever the provider needs: `api_key` + `region` for
token+region providers (Vision One, SentinelOne), the OAuth triple (`client_id` /
`client_secret` / `oauth_tenant_id`) for Defender / CrowdStrike, and `base_url` for
console-scoped ones. Region is resolved from the row, so a token that only authenticates
against its own region always pairs with that region.

Keys are Fernet-encrypted at rest (reusing llm.config_store helpers) and only ever
returned decrypted to the backend (never to the API/UI, see routes/admin.py masking).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from ..llm.config_store import decrypt_secret
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.integration_store")

V1_PROVIDER = "vision_one"
DEFAULT_IDENTIFIER = "default"


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

    Own short-lived session. Never raises; a DB hiccup resolves to None so callers
    fall back cleanly.
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

    Every provider resolves through here, including Vision One (token+region) and
    Defender (OAuth). DB-only by design; there is no env-var fallback.
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
