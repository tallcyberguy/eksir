"""CrowdStrike Falcon REST API adapter (read-only).

Thin async httpx wrapper — no business logic. OAuth2 client-credentials against the configured
Falcon cloud region, then the unified Alerts API (v2). Credentials (client_id + client_secret +
region base_url) come from the per-customer Integration store.

Auth: ``POST {base_url}/oauth2/token`` (client_id + client_secret, form-encoded) -> bearer.
Alerts: ``GET /alerts/queries/alerts/v2`` (composite_ids) + ``POST /alerts/entities/alerts/v2``.

NOTE: the endpoints, FQL, composite_ids body, and OAuth flow are schema-verified against the
public Falcon Alerts v2 docs (FalconPy wiki + CrowdStrike developer docs, 2026-07) but not yet
exercised against a live tenant. Auth/endpoint failures surface via ``test_connection`` and the
cron's ``record_failure``. Paging caveat: the query endpoint's offset paging tops out ~10k
results, so a backfill with ``max_records`` > 10000 would silently stop past that point.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..logging_config import get_logger

logger = get_logger("isoc.crowdstrike")


class CrowdStrikeError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _secret(value: Any) -> str:
    return value.get_secret_value() if hasattr(value, "get_secret_value") else str(value or "")


async def _token(base_url: str | None, client_id: Any, client_secret: Any) -> str:
    """OAuth2 client-credentials -> bearer token. Any non-2xx raises."""
    if not base_url:
        raise CrowdStrikeError(0, "CrowdStrike base_url (region API URL) not configured")
    cid, sec = _secret(client_id), _secret(client_secret)
    if not cid or not sec:
        raise CrowdStrikeError(0, "CrowdStrike client_id/client_secret not configured")
    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=30.0) as c:
        resp = await c.post(
            "/oauth2/token",
            data={"client_id": cid, "client_secret": sec},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not resp.is_success:
            logger.warning("crowdstrike.token_error", status=resp.status_code)
            raise CrowdStrikeError(resp.status_code, resp.text[:300])
        token = (resp.json() or {}).get("access_token")
        if not token:
            raise CrowdStrikeError(resp.status_code, "no access_token in token response")
        return str(token)


async def list_alerts(
    *,
    base_url: str | None,
    client_id: Any,
    client_secret: Any,
    since: str,
    limit: int = 100,
    max_records: int = 100,
) -> list[dict]:
    """List Falcon alerts created since ``since`` (RFC3339 `Z`), oldest first.

    Read-only two-step: query composite_ids by FQL, then POST them for full details. Paginates by
    offset until exhausted or ``max_records`` is reached.
    """
    token = await _token(base_url, client_id, client_secret)
    base = (base_url or "").rstrip("/")  # _token above guarantees base_url is set
    headers = {"Authorization": f"Bearer {token}"}
    fql = f"created_timestamp:>'{since}'"
    page = min(max(int(limit), 1), 1000)
    items: list[dict] = []
    offset = 0
    async with httpx.AsyncClient(base_url=base, headers=headers, timeout=30.0) as c:
        while len(items) < max_records:
            q = await c.get(
                "/alerts/queries/alerts/v2",
                params={
                    "filter": fql,
                    "sort": "created_timestamp.asc",
                    "limit": page,
                    "offset": offset,
                },
            )
            if not q.is_success:
                raise CrowdStrikeError(q.status_code, q.text[:300])
            ids = (q.json() or {}).get("resources") or []
            if not ids:
                break
            d = await c.post("/alerts/entities/alerts/v2", json={"composite_ids": ids})
            if not d.is_success:
                raise CrowdStrikeError(d.status_code, d.text[:300])
            items.extend((d.json() or {}).get("resources") or [])
            offset += len(ids)
            if len(ids) < page:
                break
    return items[:max_records]


async def ping(*, base_url: str | None, client_id: Any, client_secret: Any) -> None:
    """Minimal read-only auth check — a successful token fetch means the creds authenticate."""
    await _token(base_url, client_id, client_secret)
