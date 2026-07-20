"""Microsoft 365 Defender pull-ingestion adapter.

Pulls Graph Security ``alerts_v2`` alerts and hands each raw alert to the shared
parser/normalizer. Credentials (client_id + client_secret + oauth_tenant_id) resolve through the
per-customer Integration store (OAuth client-credentials).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import defender_adapter
from . import register
from .base import FetchResult, PulledAlert

_PROVIDER = "microsoft_defender"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_word(alert: dict) -> str | None:
    """Graph severity ('high'/'medium'/'low'/'informational') for the min-severity floor."""
    sev = str(alert.get("severity") or "").lower()
    if sev in ("high", "medium", "low"):
        return sev
    if sev == "informational":
        return "low"
    return None


class MicrosoftDefenderIngestAdapter:
    provider = _PROVIDER

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        since = cursor.get("last_poll_at") or _iso(
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )

        alerts = await defender_adapter.list_alerts(
            tenant_id=getattr(creds, "oauth_tenant_id", None),
            client_id=getattr(creds, "client_id", None),
            client_secret=getattr(creds, "client_secret", None),
            since=since,
            top=min(max_items, 1000),
            max_records=max_items,
        )

        out: list[PulledAlert] = []
        for a in alerts:
            ext = str(a.get("id") or "")
            if not ext:
                continue
            out.append(
                PulledAlert(
                    external_id=ext,
                    source_hint="microsoft_defender",
                    raw_text=json.dumps(a, ensure_ascii=False, default=str),
                    original=a,
                    severity=_severity_word(a),
                    occurred_at=a.get("createdDateTime"),
                )
            )

        return FetchResult(alerts=out, cursor={"last_poll_at": _iso(datetime.now(timezone.utc))})


register(MicrosoftDefenderIngestAdapter())
