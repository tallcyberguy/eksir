"""CrowdStrike Falcon, expressed in the typed `Connector` contract (ADR-0006 — LIVE).

OAuth client-credentials EDR. `fetch` delegates to `adapters/ingest/crowdstrike.py` (unified Alerts
API v2), `test_connection` reuses `crowdstrike_adapter.ping` (a token fetch), and the vendored
`crowdstrike` parser normalizes each alert. The Alerts API + parser fields are schema-verified
against the public Falcon Alerts v2 docs (2026-07), not yet exercised on a live tenant — see
`crowdstrike_adapter`.
"""

from __future__ import annotations

from typing import Any

from ...ingest.base import FetchResult
from ..base import Connector
from ..capabilities import Capability
from ..fields import CLIENT_ID, CLIENT_SECRET, AuthShape, Field, FieldType, OAuthHints


class CrowdStrikeConnector(Connector):
    key = "crowdstrike"
    label = "CrowdStrike Falcon"
    category = "edr"
    identifier_label = "Customer"
    adapter_status = "live"
    auth_shape = AuthShape.OAUTH_CLIENT_CREDS
    parser_source = "crowdstrike"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (
            CLIENT_ID,
            CLIENT_SECRET,
            Field(
                "base_url",
                "API base URL",
                type=FieldType.SELECT,
                required=True,
                options=(
                    "https://api.crowdstrike.com",
                    "https://api.us-2.crowdstrike.com",
                    "https://api.eu-1.crowdstrike.com",
                    "https://api.laggar.gcw.crowdstrike.com",
                ),
                help="Falcon cloud region base URL.",
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.ENRICH_IOC,
            Capability.ISOLATE_HOST,
        )

    @classmethod
    def oauth_hints(cls) -> OAuthHints | None:
        return OAuthHints(
            token_url="{base_url}/oauth2/token",
            scopes=(),
            supported_in_hosted=False,
        )

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        from ...ingest.crowdstrike import CrowdStrikeIngestAdapter

        return await CrowdStrikeIngestAdapter().fetch(
            creds=creds, cursor=cursor, max_items=max_items
        )

    async def test_connection(self, creds: Any) -> dict:
        from ...crowdstrike_adapter import CrowdStrikeError, ping

        try:
            await ping(
                base_url=getattr(creds, "base_url", None),
                client_id=getattr(creds, "client_id", None),
                client_secret=getattr(creds, "client_secret", None),
            )
            return {"ok": True, "status": "ok", "detail": "Authenticated to CrowdStrike Falcon."}
        except CrowdStrikeError as exc:
            return {
                "ok": False,
                "status": "auth_failed",
                "detail": f"CrowdStrike error {getattr(exc, 'status', '?')}: {str(exc)[:200]}",
            }
        except Exception as exc:  # network / timeout / unexpected
            return {"ok": False, "status": "error", "detail": str(exc)[:200]}
