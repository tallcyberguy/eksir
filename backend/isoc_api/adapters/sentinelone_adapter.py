"""SentinelOne REST API adapter.

Thin async wrapper — no business logic, just HTTP calls. The console host and
API token come from the per-customer Integration store (base_url + api_key).

Auth: ``Authorization: ApiToken <token>``.
Base: ``https://<console>.sentinelone.net/`` → ``/web/api/v2.1/…``.

NOTE: the endpoint path + params below follow the documented v2.1 Threats API
but are UNVERIFIED against a live tenant — confirm before enabling live.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..logging_config import get_logger

logger = get_logger("isoc.s1")


class SentinelOneError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _token(api_key: Any) -> str:
    return (
        api_key.get_secret_value() if hasattr(api_key, "get_secret_value") else str(api_key or "")
    )


def _client(base_url: str | None, api_key: Any) -> httpx.AsyncClient:
    """Per-call SentinelOne client scoped to a customer's console + token."""
    if not base_url:
        raise SentinelOneError(0, "SentinelOne base_url (console host) not configured")
    token = _token(api_key)
    if not token:
        raise SentinelOneError(0, "SentinelOne api_key not configured")
    return httpx.AsyncClient(
        base_url=base_url.rstrip("/") + "/",
        headers={"Authorization": f"ApiToken {token}"},
        timeout=30.0,
    )


async def _raise_for(resp: httpx.Response) -> dict:
    if resp.is_success:
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()
    try:
        body = resp.json()
        errors = body.get("errors") if isinstance(body, dict) else None
        msg = (errors[0].get("detail") if errors else None) or str(body)
    except Exception:
        msg = resp.text[:300]
    logger.warning("s1.api_error", status=resp.status_code, msg=msg)
    raise SentinelOneError(resp.status_code, msg)


async def list_threats(
    *,
    base_url: str | None,
    api_key: Any,
    since: str,
    limit: int = 100,
    max_records: int = 100,
) -> list[dict]:
    """List threats created since ``since`` (RFC3339 `Z`), oldest first.

    Read-only. Follows SentinelOne cursor pagination
    (``pagination.nextCursor``) until exhausted or ``max_records`` is reached.
    """
    base_params: dict[str, Any] = {
        "createdAt__gte": since,
        "sortBy": "createdAt",
        "sortOrder": "asc",
        "limit": min(max(int(limit), 1), 1000),
    }
    items: list[dict] = []
    cursor: str | None = None
    async with _client(base_url, api_key) as c:
        while len(items) < max_records:
            params = dict(base_params)
            if cursor:
                params["cursor"] = cursor
            resp = await c.get("web/api/v2.1/threats", params=params)
            data = await _raise_for(resp)
            page = data.get("data", []) if isinstance(data, dict) else []
            items.extend(page)
            cursor = (
                (data.get("pagination") or {}).get("nextCursor") if isinstance(data, dict) else None
            )
            if not cursor or not page:
                break
    return items[:max_records]


async def ping(*, base_url: str | None, api_key: Any) -> dict:
    """Minimal read-only auth check (one threat). Any 2xx means the token works."""
    async with _client(base_url, api_key) as c:
        resp = await c.get("web/api/v2.1/threats", params={"limit": 1})
        return await _raise_for(resp)
