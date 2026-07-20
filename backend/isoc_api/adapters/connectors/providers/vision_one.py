"""Trend Micro Vision One, expressed in the typed `Connector` contract (ADR-0006 — LIVE).

Delegates `fetch` to the existing `adapters/ingest/vision_one.py` adapter and `test_connection` to
`v1_adapter.search_endpoints` (a minimal read-only call). `health.py` now routes every live
connector's test through `Connector.test_connection`, so this method is the V1 tester. Credentials
+ region resolve through the V1-specific `integration_store.get_creds_v1` seam.
"""

from __future__ import annotations

from typing import Any

from ...ingest.base import FetchResult
from ..base import Connector
from ..capabilities import Capability
from ..fields import API_KEY, AuthShape, Field, region_field

V1_REGIONS = ("us", "eu", "jp", "au", "sg", "in", "mea")


class VisionOneConnector(Connector):
    key = "vision_one"
    label = "Trend Micro Vision One"
    category = "edr"
    identifier_label = "Customer name"
    adapter_status = "live"
    auth_shape = AuthShape.TOKEN
    parser_source = "visionone"
    docs_url = "https://automation.trendmicro.com/xdr/home"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY, region_field(V1_REGIONS))

    @classmethod
    def region_options(cls) -> tuple[str, ...]:
        return V1_REGIONS

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.ENRICH_IOC, Capability.ISOLATE_HOST)

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        from ...ingest.vision_one import VisionOneIngestAdapter

        return await VisionOneIngestAdapter().fetch(creds=creds, cursor=cursor, max_items=max_items)

    async def test_connection(self, creds: Any) -> dict:
        from ...v1_adapter import VisionOneError, search_endpoints

        try:
            await search_endpoints(
                filter_expr="",
                top=1,
                region=getattr(creds, "region", None),
                api_key=getattr(creds, "api_key", None),
            )
            return {"ok": True, "status": "ok", "detail": "Authenticated to Vision One."}
        except VisionOneError as exc:
            return {
                "ok": False,
                "status": "auth_failed",
                "detail": f"Vision One error {getattr(exc, 'status', '?')}: {str(exc)[:200]}",
            }
        except Exception as exc:  # network / timeout / unexpected
            return {"ok": False, "status": "error", "detail": str(exc)[:200]}
