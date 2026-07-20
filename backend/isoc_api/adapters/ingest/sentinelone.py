"""SentinelOne pull-ingestion adapter.

Pulls threats via the v2.1 API and hands each raw threat to the shared
parser/normalizer. Credentials (console host + API token) resolve through the
per-customer Integration store (``Creds.base_url`` + ``Creds.api_key``).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import sentinelone_adapter
from . import register
from .base import FetchResult, PulledAlert

_PROVIDER = "sentinelone"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def _severity_word(threat: dict) -> str | None:
    info = threat.get("threatInfo") or {}
    conf = str(info.get("confidenceLevel") or "").lower()
    if conf == "malicious":
        return "high"
    if conf == "suspicious":
        return "medium"
    return None


class SentinelOneIngestAdapter:
    provider = _PROVIDER

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        base_url = getattr(creds, "base_url", None)
        api_key = getattr(creds, "api_key", None)
        # Cold start = ~now (no backfill), matching mailbox_poll's "only new".
        since = cursor.get("last_poll_at") or _iso(
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )

        threats = await sentinelone_adapter.list_threats(
            base_url=base_url,
            api_key=api_key,
            since=since,
            limit=min(max_items, 1000),
            max_records=max_items,
        )

        alerts: list[PulledAlert] = []
        for t in threats:
            ext = str(t.get("id") or "")
            if not ext:
                continue
            info = t.get("threatInfo") or {}
            alerts.append(
                PulledAlert(
                    external_id=ext,
                    source_hint="sentinelone",
                    raw_text=json.dumps(t, ensure_ascii=False, default=str),
                    original=t,
                    severity=_severity_word(t),
                    occurred_at=info.get("createdAt"),
                )
            )

        return FetchResult(alerts=alerts, cursor={"last_poll_at": _iso(datetime.now(timezone.utc))})


register(SentinelOneIngestAdapter())
