"""CrowdStrike Falcon pull-ingestion adapter.

Pulls Falcon alerts via the unified Alerts API and hands each raw alert to the shared
parser/normalizer. Credentials (client_id + client_secret + region base_url) resolve through the
per-customer Integration store (OAuth client-credentials).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import crowdstrike_adapter
from . import register
from .base import FetchResult, PulledAlert

_PROVIDER = "crowdstrike"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_word(alert: dict) -> str | None:
    """Raw severity band ('critical'/'high'/'medium'/'low') for the ingest min-severity floor."""
    name = str(alert.get("severity_name") or "").lower()
    if name in ("critical", "high", "medium", "low"):
        return name
    sev = alert.get("severity")
    if isinstance(sev, (int, float)):
        if sev >= 80:
            return "critical"
        if sev >= 60:
            return "high"
        if sev >= 40:
            return "medium"
        return "low"
    return None


class CrowdStrikeIngestAdapter:
    provider = _PROVIDER

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        # Cold start = ~now (no backfill), matching the other pull adapters.
        since = cursor.get("last_poll_at") or _iso(
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )

        alerts = await crowdstrike_adapter.list_alerts(
            base_url=getattr(creds, "base_url", None),
            client_id=getattr(creds, "client_id", None),
            client_secret=getattr(creds, "client_secret", None),
            since=since,
            limit=min(max_items, 1000),
            max_records=max_items,
        )

        out: list[PulledAlert] = []
        for a in alerts:
            ext = str(a.get("composite_id") or a.get("id") or "")
            if not ext:
                continue
            out.append(
                PulledAlert(
                    external_id=ext,
                    source_hint="crowdstrike",
                    raw_text=json.dumps(a, ensure_ascii=False, default=str),
                    original=a,
                    severity=_severity_word(a),
                    occurred_at=a.get("created_timestamp"),
                )
            )

        return FetchResult(alerts=out, cursor={"last_poll_at": _iso(datetime.now(timezone.utc))})


register(CrowdStrikeIngestAdapter())
