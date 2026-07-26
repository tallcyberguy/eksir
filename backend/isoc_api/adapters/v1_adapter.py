"""Trend Micro Vision One REST API adapter.

Thin async wrapper — no business logic, just HTTP calls.
Base URL: https://api.{region}.xdr.trendmicro.com/

All methods return the parsed JSON body on success.
Raises VisionOneError on non-2xx with the API error message surfaced.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.v1")

_BASE_US = "https://api.xdr.trendmicro.com/"
_BASE_JP = "https://api.jp.xdr.trendmicro.com/"


class VisionOneError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _base_url(region: str) -> str:
    if region == "us":
        return _BASE_US
    if region == "jp":
        return _BASE_JP
    return f"https://api.{region}.xdr.trendmicro.com/"


def _client(region: str | None = None, api_key: Any = None) -> httpx.AsyncClient:
    """Build a per-call V1 client.

    region / api_key override the global settings so a multi-tenant caller can
    resolve credentials per customer (ADR-0005 / ADR-0003 seam). Both default to
    the global settings, so existing callers (`_client()`) are unaffected.
    """
    key = api_key if api_key is not None else settings.v1_api_key
    if not key:
        raise VisionOneError(0, "V1_API_KEY not configured")
    secret = key.get_secret_value() if hasattr(key, "get_secret_value") else str(key)
    # Note: Content-Type is NOT set here — only added per-request on POST/PUT/PATCH
    # because V1 rejects GET requests that carry a Content-Type header.
    return httpx.AsyncClient(
        base_url=_base_url(region or settings.v1_region),
        headers={"Authorization": f"Bearer {secret}"},
        timeout=30.0,
    )


async def _raise_for(resp: httpx.Response) -> dict:
    if resp.is_success:
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()
    try:
        body = resp.json()
        msg = body.get("message") or body.get("error") or str(body)
    except Exception:
        msg = resp.text[:300]
    logger.warning("v1.api_error", status=resp.status_code, msg=msg)
    raise VisionOneError(resp.status_code, msg)


# ── Suspicious Objects / Block List ──────────────────────────────────────


async def add_to_blocklist(
    ioc_type: str,
    value: str,
    description: str = "",
    scan_action: str = "block",
    risk_level: str = "high",
    *,
    region: str | None = None,
    api_key: Any = None,
) -> dict:
    """Add one IOC to the Suspicious Object (block) list.

    ioc_type: "ip" | "domain" | "url" | "fileSha1" | "fileSha256" | "senderMailAddress"
    scan_action: "block" | "log"
    risk_level: "high" | "medium" | "low"
    """
    obj: dict[str, Any] = {
        ioc_type: value,
        "scanAction": scan_action,
        "riskLevel": risk_level,
    }
    if description:
        obj["description"] = description

    async with _client(region=region, api_key=api_key) as c:
        resp = await c.post(
            "v3.0/threatintel/suspiciousObjects",
            json=[obj],
            headers={"Content-Type": "application/json;charset=utf-8"},
        )
        return await _raise_for(resp)


# ── Endpoint enrichment ───────────────────────────────────────────────────


async def search_endpoints(
    filter_expr: str = "", top: int = 20, *, region: str | None = None, api_key: Any = None
) -> list[dict]:
    """Search endpoints. filter_expr uses OData-style syntax sent via TMV1-Filter header.
    Example: "endpointName eq 'DESKTOP-ABC'" or "contains(endpointName,'CSV')"
    Returns list of endpoint objects. V1 does not accept a 'top' query param here.
    """
    headers: dict[str, str] = {}
    if filter_expr:
        headers["TMV1-Filter"] = filter_expr

    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get("v3.0/endpointSecurity/endpoints", headers=headers)
        data = await _raise_for(resp)
        items = data.get("items", [])
        return items[:top]


async def get_endpoint(endpoint_id: str, *, region: str | None = None, api_key: Any = None) -> dict:
    """Get detailed profile for a single endpoint by agentGuid."""
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get(f"v3.0/endpointSecurity/endpoints/{endpoint_id}")
        return await _raise_for(resp)


# ── Response actions ──────────────────────────────────────────────────────


async def isolate_endpoint(
    endpoint_name: str, description: str = "", *, region: str | None = None, api_key: Any = None
) -> dict:
    """Isolate an endpoint from the network. Returns task object."""
    _ct = {"Content-Type": "application/json;charset=utf-8"}
    body = [{"endpointName": endpoint_name, "description": description}]
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.post("v3.0/response/endpoints/isolate", json=body, headers=_ct)
        return await _raise_for(resp)


async def restore_endpoint(
    endpoint_name: str, description: str = "", *, region: str | None = None, api_key: Any = None
) -> dict:
    """Restore an isolated endpoint's network connection. Returns task object."""
    _ct = {"Content-Type": "application/json;charset=utf-8"}
    body = [{"endpointName": endpoint_name, "description": description}]
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.post("v3.0/response/endpoints/restore", json=body, headers=_ct)
        return await _raise_for(resp)


async def collect_file(
    endpoint_name: str | None = None,
    file_path: str = "",
    description: str = "",
    *,
    agent_guid: str | None = None,
    region: str | None = None,
    api_key: Any = None,
) -> dict:
    """Collect a file from an endpoint for forensic analysis. Returns task object.

    Identify the target endpoint by **`agent_guid`** (the installed agent's GUID —
    the identifier required on FedRAMP tenants) or by `endpoint_name` (computer
    name). The V1 API accepts exactly ONE of them per entry, so `agent_guid` wins
    when both are given. `file_path` is required.
    """
    if not (file_path or "").strip().strip("\\/"):
        # Rejects empty, whitespace, and slash-only paths (e.g. "\\") that a model
        # can emit — V1 would 400 on them anyway.
        raise VisionOneError(0, "collect_file requires a real file_path")
    if not (agent_guid or endpoint_name):
        raise VisionOneError(0, "collect_file requires agent_guid or endpoint_name")

    _ct = {"Content-Type": "application/json;charset=utf-8"}
    entry: dict[str, Any] = {"filePath": file_path}
    if agent_guid:
        entry["agentGuid"] = agent_guid
    else:
        entry["endpointName"] = endpoint_name
    if description:
        entry["description"] = description
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.post("v3.0/response/endpoints/collectFile", json=[entry], headers=_ct)
        return await _raise_for(resp)


def parse_response_task(result: Any) -> dict:
    """Interpret a Vision One response-action result (the HTTP 207 Multi-Status body).

    These endpoints (isolate/restore/collectFile/blocklist) return 2xx overall even
    when the single batch item FAILED — the real outcome is the item's own `status`
    plus, on success, an `Operation-Location` header pointing at the response task.

    Returns {ok, item_status, task_id, task_url, error}. `ok` defaults True when no
    per-item status is present (unknown shape → don't invent a failure).
    """
    item: dict = {}
    if isinstance(result, list) and result:
        item = result[0] if isinstance(result[0], dict) else {}
    elif isinstance(result, dict):
        item = result
    status = item.get("status")
    task_url = None
    for h in item.get("headers") or []:
        if str(h.get("name", "")).lower() == "operation-location":
            task_url = h.get("value")
            break
    task_id = task_url.rstrip("/").split("/")[-1] if task_url else None
    error = None
    body = item.get("body")
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        err = body["error"]
        error = err.get("message") or err.get("code")
    ok = True if not isinstance(status, int) else 200 <= status < 300
    return {
        "ok": ok,
        "item_status": status,
        "task_id": task_id,
        "task_url": task_url,
        "error": error,
    }


async def get_response_task(
    task_id: str, *, region: str | None = None, api_key: Any = None
) -> dict:
    """Poll a response-action task (isolate/restore/collectFile).

    On a completed collectFile the body carries `resourceLocation` — a time-limited
    URL to download the collected file as a password-protected archive.
    """
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get(f"v3.0/response/tasks/{task_id}")
        return await _raise_for(resp)


# ── Workbench / OAT read-only enrichment (ADR-0005) ────────────────────────
# Live-verified 2026-06-22. Both are GETs (no Content-Type). Region must be
# resolved by the caller (the JWT carries no region) — see _client().


async def get_workbench_alert(
    alert_id: str, *, region: str | None = None, api_key: Any = None
) -> dict:
    """GET the full Workbench alert detail for `alert_id` (e.g. WB-...-00001).

    Returns the alert object: model/score/severity, impactScope.entities[],
    matchedRules[] (with mitreTechniqueIds), and indicators[] carrying the actual
    objectCmd/processCmd/parentCmd command lines + hashes + paths.
    """
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get(f"v3.0/workbench/alerts/{alert_id}")
        return await _raise_for(resp)


# Verdict -> (status, investigationResult) title-case enums (ADR-0005, live-verified casing).
# FP/benign -> Closed so V1 stops accruing tenant threat score from the alert.
_V1_STATUS_MAP: dict[str, tuple[str, str]] = {
    "tp": ("In Progress", "True Positive"),
    "fp": ("Closed", "False Positive"),
    "benign": ("Closed", "Benign True Positive"),
    "inconclusive": ("In Progress", "Noteworthy"),
}


async def patch_alert_status(
    alert_id: str,
    status: str,
    investigation_result: str,
    *,
    region: str | None = None,
    api_key: Any = None,
) -> dict:
    """PATCH a Workbench alert's status + investigationResult (read-modify-write, ADR-0005).

    The v3.0 API uses optimistic concurrency, so we GET the alert first to read its ETag and
    send it back as `If-Match`. Returns {} on the 204. This is a WRITE — callers must gate it
    (flag + V1-customer + fail-soft); see `mirror_verdict_to_v1`.
    """
    async with _client(region=region, api_key=api_key) as c:
        get_resp = await c.get(f"v3.0/workbench/alerts/{alert_id}")
        if not get_resp.is_success:
            raise VisionOneError(get_resp.status_code, get_resp.text[:300])
        etag = get_resp.headers.get("ETag") or get_resp.headers.get("etag")
        headers = {"Content-Type": "application/json;charset=utf-8"}
        if etag:
            headers["If-Match"] = etag
        body = {"status": status, "investigationResult": investigation_result}
        resp = await c.patch(f"v3.0/workbench/alerts/{alert_id}", json=body, headers=headers)
        return await _raise_for(resp)


def verdict_to_v1_status(verdict: Any) -> tuple[str, str] | None:
    """Pure: map an ISOC verdict (enum or str) to (status, investigationResult), or None."""
    key = str(getattr(verdict, "value", verdict) or "").strip().lower()
    return _V1_STATUS_MAP.get(key)


async def mirror_verdict_to_v1(incident: Any, verdict: Any) -> None:
    """Mirror an analyst/auto verdict back to the V1 Workbench alert (fail-soft, flag-gated).

    Closes the alert / sets investigationResult so V1 stops accruing the customer's threat score.
    No-op unless `v1_status_writeback_enabled` AND the incident is a V1 alert (source visionone +
    a workbench id) with resolvable V1 creds. In a multi-tenant setup (v1_customers configured) the
    customer must be a known V1 customer, so a shared key can't PATCH the wrong tenant. NEVER raises
    — a write-back failure must not break the verdict commit / gate.
    """
    if not settings.v1_status_writeback_enabled:
        return
    norm = getattr(incident, "normalized", None) or {}
    if norm.get("source_product") != "visionone":
        return
    wb_id = norm.get("v1_workbench_id")
    mapped = verdict_to_v1_status(verdict)
    if not wb_id or mapped is None:
        return
    customer = getattr(incident, "customer", None)
    # Cross-tenant safety: only enforce the customer allow-list when it's actually configured
    # (a single global-key deployment has an empty v1_customers and one tenant).
    if v1_customers() and not is_v1_customer(customer):
        return
    try:
        from .integration_store import get_creds

        creds = await get_creds("vision_one", customer)
        if creds is None:
            return
        await patch_alert_status(
            str(wb_id), mapped[0], mapped[1], region=creds.region, api_key=creds.api_key
        )
        logger.info("v1.status_writeback", wb=str(wb_id), status=mapped[0], result=mapped[1])
    except Exception as exc:  # never break the gate
        logger.warning("v1.status_writeback_failed", wb=str(wb_id), error=str(exc))


async def list_workbench_alerts(
    *,
    start: str,
    end: str | None = None,
    region: str | None = None,
    api_key: Any = None,
    top: int = 100,
    max_records: int = 100,
) -> list[dict]:
    """List Workbench alerts created since `start` (RFC3339 `Z`), newest included.

    Read-only. Follows `nextLink` pagination (same shape as
    `get_endpoint_activity`) until exhausted or `max_records` is reached. Always
    pass a bounded `start`; with none V1 applies its own default window.

    Params (startDateTime/endDateTime/dateTimeTarget/orderBy/top + nextLink + items[]) are
    verified against the current v3.0 API (Trend tm-v1-api-cookbook + the v3 reference, 2026-07).
    Field filtering (investigationStatus/severity/model) would go in a TMV1-Filter header; the
    pull sends none by design (pull-everything-since-start). The list item is the FULL alert
    (indicators + impactScope + matchedRules), so no per-alert detail fetch is needed to enrich.
    """
    params: dict[str, Any] = {
        "startDateTime": start,
        "dateTimeTarget": "createdDateTime",
        "orderBy": "createdDateTime asc",
        "top": top,
    }
    if end:
        params["endDateTime"] = end

    items: list[dict] = []
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get("v3.0/workbench/alerts", params=params)
        data = await _raise_for(resp)
        items.extend(data.get("items", []) if isinstance(data, dict) else [])
        next_link = data.get("nextLink") if isinstance(data, dict) else None
        while next_link and len(items) < max_records:
            resp = await c.get(next_link)
            data = await _raise_for(resp)
            items.extend(data.get("items", []) if isinstance(data, dict) else [])
            next_link = data.get("nextLink") if isinstance(data, dict) else None
    return items[:max_records]


async def get_oat_detections(
    *,
    start: str,
    end: str,
    endpoint: str | None = None,
    region: str | None = None,
    api_key: Any = None,
    top: int = 50,
) -> list[dict]:
    """GET Observed Attack Techniques between `start` and `end` (RFC3339 `Z`).

    When `endpoint` is given, scope to that host via the verified
    `TMV1-Filter: endpointName eq '<host>'` header (prevents whole-tenant pulls).
    Always pass dates — with none, V1 returns an empty result, not an error.
    riskLevel filtering is done by the caller (header risk syntax is unverified).

    NOTE: `detectedStartDateTime`/`detectedEndDateTime` window on *detection* time; the API also
    supports `ingestionStartDateTime`/`ingestionEndDateTime` (when V1 received the detection) —
    choose deliberately so late-ingested detections aren't missed on a tight window.
    """
    params: dict[str, Any] = {
        "detectedStartDateTime": start,
        "detectedEndDateTime": end,
        "top": top,
    }
    headers: dict[str, str] = {}
    if endpoint:
        headers["TMV1-Filter"] = f"endpointName eq '{endpoint}'"
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get("v3.0/oat/detections", params=params, headers=headers or None)
        data = await _raise_for(resp)
        items = data.get("items", []) if isinstance(data, dict) else []
        return items[:top]


async def get_endpoint_details(
    endpoint_name: str,
    *,
    region: str | None = None,
    api_key: Any = None,
    top: int = 10,
) -> list[dict]:
    """GET Endpoint Inventory records for a host (v3.0 `/eiqs/endpoints`), scoped by the
    `TMV1-Query: endpointName eq '<host>'` header. Returns `items[]` (usually one).

    NOTE: this collection carries NO device risk/criticality/exposure score, unlike
    Microsoft Defender's machine object (riskScore / exposureLevel / deviceValue). Trend's
    per-device risk lives in ASRM / CREM, a separate API surface. Only status/coverage
    signals (eppAgent / edrSensor status, isolationStatus, last-connected) are here, so
    the caller documents a reduced surface rather than faking a criticality.
    """
    headers = {"TMV1-Query": f"endpointName eq '{endpoint_name}'"}
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get("v3.0/eiqs/endpoints", params={"top": top}, headers=headers)
        data = await _raise_for(resp)
        return data.get("items", []) if isinstance(data, dict) else []


async def get_endpoint_activity(
    tmv1_query: str,
    *,
    start: str | None = None,
    end: str | None = None,
    top: int = 50,
    select: str | None = None,
    mode: str = "default",
    region: str | None = None,
    api_key: Any = None,
    max_records: int = 200,
) -> list[dict]:
    """Search the Endpoint Activity Data source (read-only telemetry).

    `tmv1_query` is the TMV1-Query filter carried in the header (e.g.
    `objectFileHashSha256:<sha256>` or `endpointHostName:HOST`, with and/or/not).
    Follows `nextLink` pagination until exhausted or `max_records` is reached.
    Always pass a bounded window — with none, V1 defaults to the last 24h. Needs
    the API key's "Agentic SIEM and XDR → XDR Data Explorer" role.
    """
    if not tmv1_query:
        raise VisionOneError(0, "get_endpoint_activity requires a TMV1-Query filter")

    params: dict[str, Any] = {"top": top, "mode": mode}
    if start:
        params["startDateTime"] = start
    if end:
        params["endDateTime"] = end
    if select:
        params["select"] = select
    headers = {"TMV1-Query": tmv1_query}

    items: list[dict] = []
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get("v3.0/search/endpointActivities", params=params, headers=headers)
        data = await _raise_for(resp)
        items.extend(data.get("items", []) if isinstance(data, dict) else [])
        next_link = data.get("nextLink") if isinstance(data, dict) else None
        # nextLink is an absolute URL that already encodes the continuation; the
        # TMV1-Query header must be re-sent on each page.
        while next_link and len(items) < max_records:
            resp = await c.get(next_link, headers=headers)
            data = await _raise_for(resp)
            items.extend(data.get("items", []) if isinstance(data, dict) else [])
            next_link = data.get("nextLink") if isinstance(data, dict) else None
    return items[:max_records]


def is_configured() -> bool:
    return bool(settings.v1_api_key)


def v1_customers() -> dict[str, str]:
    """Return {customer_name: tenant_id} mapping from settings."""
    result: dict[str, str] = {}
    for pair in (settings.v1_customers or "").split(","):
        pair = pair.strip()
        if ":" in pair:
            k, v = pair.split(":", 1)
            result[k.strip()] = v.strip()
        elif pair:
            result[pair] = pair
    return result


def is_v1_customer(customer: str | None) -> bool:
    """True if this customer maps to a V1 tenant."""
    if not customer:
        return False
    return customer.strip().lower() in {k.lower() for k in v1_customers()}
