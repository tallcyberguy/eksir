"""Vision One pull-ingestion adapter.

Pulls Workbench alerts via the v3.0 API and hands each raw alert to the shared
parser/normalizer. This is the direct-API replacement for forwarding V1 alerts
by email — and it carries richer data (impactScope, matchedRules with MITRE,
indicators) than the email ever did. Credentials + region resolve through the
existing per-customer store (`integration_store.get_creds_v1`).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import v1_adapter
from . import register
from .base import FetchResult, PulledAlert

_PROVIDER = "vision_one"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VisionOneIngestAdapter:
    provider = _PROVIDER

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        # Cold start = ~now (no backfill): the first poll takes only new alerts.
        start = cursor.get("last_poll_at") or _iso(
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        region = getattr(creds, "region", None)
        api_key = getattr(creds, "api_key", None)

        raw_alerts = await v1_adapter.list_workbench_alerts(
            start=start,
            region=region,
            api_key=api_key,
            top=min(max_items, 200),
            max_records=max_items,
        )

        alerts: list[PulledAlert] = []
        for a in raw_alerts:
            ext = _external_id(a)
            if not ext:
                continue
            alerts.append(
                PulledAlert(
                    external_id=ext,
                    source_hint="visionone",
                    raw_text=json.dumps(a, ensure_ascii=False, default=str),
                    original=a,
                    severity=(a.get("severity") if isinstance(a, dict) else None),
                    occurred_at=(a.get("createdDateTime") if isinstance(a, dict) else None),
                )
            )

        # Always advance the cursor to "now" on a successful call — the API is
        # queried by created-time window, so the next poll starts from here.
        return FetchResult(alerts=alerts, cursor={"last_poll_at": _iso(datetime.now(timezone.utc))})


def _external_id(alert: dict) -> str | None:
    if not isinstance(alert, dict):
        return None
    for key in ("id", "workbenchId", "alertId"):
        val = alert.get(key)
        if val:
            return str(val)
    return None


register(VisionOneIngestAdapter())
