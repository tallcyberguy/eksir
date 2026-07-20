"""SentinelOne, expressed in the typed `Connector` contract (ADR-0006 reference port — LIVE).

Demonstrates the contract wrapping code that already exists: `fetch` delegates to the existing
`adapters/ingest/sentinelone.py` adapter, `test_connection` reuses `sentinelone_adapter.ping`, and
the parser is the vendored `sentinelone` source. Nothing new is implemented here — this is the
one-file home the four scattered pieces collapse into.
"""

from __future__ import annotations

from typing import Any

from ...ingest.base import FetchResult
from ..base import Connector
from ..capabilities import Capability
from ..fields import API_KEY, BASE_URL, AuthShape, Field


class SentinelOneConnector(Connector):
    key = "sentinelone"
    label = "SentinelOne"
    category = "edr"
    identifier_label = "Console host"
    adapter_status = "live"
    auth_shape = AuthShape.TOKEN
    parser_source = "sentinelone"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (
            API_KEY,
            Field(
                "base_url",
                "Console host",
                type=BASE_URL.type,
                required=True,
                placeholder="euce1-105.sentinelone.net",
                help="SentinelOne console host; the API token authenticates as ApiToken.",
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.ENRICH_IOC,
            Capability.HUNT_QUERY,
            Capability.ISOLATE_HOST,
            Capability.SCAN_ENDPOINT,
        )

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        # Delegate to the existing pull-ingest adapter (no logic duplicated).
        from ...ingest.sentinelone import SentinelOneIngestAdapter

        return await SentinelOneIngestAdapter().fetch(
            creds=creds, cursor=cursor, max_items=max_items
        )

    async def test_connection(self, creds: Any) -> dict:
        from ...sentinelone_adapter import SentinelOneError, ping

        try:
            await ping(
                base_url=getattr(creds, "base_url", None), api_key=getattr(creds, "api_key", None)
            )
            return {"ok": True, "status": "ok", "detail": "Authenticated to SentinelOne."}
        except SentinelOneError as exc:
            return {
                "ok": False,
                "status": "auth_failed",
                "detail": f"SentinelOne error {getattr(exc, 'status', '?')}: {str(exc)[:200]}",
            }
        except Exception as exc:  # network / timeout / unexpected
            return {"ok": False, "status": "error", "detail": str(exc)[:200]}
