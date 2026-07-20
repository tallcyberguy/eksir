"""Microsoft 365 Defender, expressed in the typed `Connector` contract (ADR-0006 — LIVE).

OAuth client-credentials (Azure AD app). `fetch` delegates to `adapters/ingest/microsoft_defender.py`
(Graph Security `alerts_v2`), `test_connection` reuses `defender_adapter.ping` (a token fetch), and
the vendored `microsoft_defender` parser normalizes each alert. The Graph API + parser fields are
schema-verified against the public Graph Security v1.0 docs (2026-07), not yet exercised on a live
tenant — see `defender_adapter`. The same auth shape later serves Defender for Office 365 and
Microsoft Sentinel.
"""

from __future__ import annotations

from typing import Any

from ...ingest.base import FetchResult
from ..base import Connector
from ..capabilities import Capability
from ..fields import CLIENT_ID, CLIENT_SECRET, OAUTH_TENANT_ID, AuthShape, Field, OAuthHints


class MicrosoftDefenderConnector(Connector):
    key = "microsoft_defender"
    label = "Microsoft 365 Defender"
    category = "edr"
    identifier_label = "Customer"
    adapter_status = "live"
    auth_shape = AuthShape.OAUTH_CLIENT_CREDS
    parser_source = "microsoft_defender"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (CLIENT_ID, CLIENT_SECRET, OAUTH_TENANT_ID)

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.ENRICH_IOC, Capability.ISOLATE_HOST)

    @classmethod
    def oauth_hints(cls) -> OAuthHints | None:
        return OAuthHints(
            token_url="https://login.microsoftonline.com/{oauth_tenant_id}/oauth2/v2.0/token",
            scopes=("https://graph.microsoft.com/.default",),
            supported_in_hosted=False,
        )

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        from ...ingest.microsoft_defender import MicrosoftDefenderIngestAdapter

        return await MicrosoftDefenderIngestAdapter().fetch(
            creds=creds, cursor=cursor, max_items=max_items
        )

    async def test_connection(self, creds: Any) -> dict:
        from ...defender_adapter import DefenderError, ping

        try:
            await ping(
                tenant_id=getattr(creds, "oauth_tenant_id", None),
                client_id=getattr(creds, "client_id", None),
                client_secret=getattr(creds, "client_secret", None),
            )
            return {"ok": True, "status": "ok", "detail": "Authenticated to Microsoft Defender."}
        except DefenderError as exc:
            return {
                "ok": False,
                "status": "auth_failed",
                "detail": f"Defender error {getattr(exc, 'status', '?')}: {str(exc)[:200]}",
            }
        except Exception as exc:  # network / timeout / unexpected
            return {"ok": False, "status": "error", "detail": str(exc)[:200]}
