"""Microsoft 365 Defender REST API adapter (Graph Security + Defender for Endpoint).

Read paths are read-only; the containment actions at the bottom (isolate / unisolate / scan)
are WRITE and fire only from an authenticated, justification-bearing analyst request.

Thin async httpx wrapper. OAuth2 client-credentials against Azure AD (the customer's tenant),
then the Microsoft Graph Security ``alerts_v2`` endpoint. Credentials (client_id + client_secret
+ oauth_tenant_id) come from the per-customer Integration store; Graph + login hosts are fixed.

Auth: ``POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` -> bearer.
The token audience is selected by ``scope`` (``_token``): Graph for alerts + hunting,
``_MDE_SCOPE`` for the Defender for Endpoint API (machine / file / IP detail).
Alerts: ``GET https://graph.microsoft.com/v1.0/security/alerts_v2`` (paginated via @odata.nextLink).
Read tools: ``runHuntingQuery`` (Graph) + ``machines`` / ``files`` / ``ips`` stats (MDE API).

NOTE: the endpoints, client-credentials auth, ``createdDateTime`` $filter, @odata.nextLink paging,
and fields are schema-verified against the public Graph Security + Defender for Endpoint v1.0 docs
(learn.microsoft.com, 2026-07) but not yet exercised against a live tenant. Permissions: alerts need
``SecurityAlert.Read.All`` (Graph); hunting ``ThreatHunting.Read.All`` (Graph); machine/file/IP
detail ``Machine.Read.All`` / ``File.Read.All`` / ``Ip.Read.All`` (WindowsDefenderATP). Auth/endpoint
failures surface via ``test_connection`` / the cron.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..logging_config import get_logger

logger = get_logger("isoc.defender")

_GRAPH = "https://graph.microsoft.com/v1.0"
_LOGIN = "https://login.microsoftonline.com"
# Read tools split across two Microsoft resources with distinct token audiences:
# Graph (alerts_v2 + advanced hunting) vs the Defender for Endpoint API (machine /
# file / IP stats). `_token` picks the audience via `scope`.
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_MDE = "https://api.securitycenter.microsoft.com/api"
_MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"


class DefenderError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _secret(value: Any) -> str:
    return value.get_secret_value() if hasattr(value, "get_secret_value") else str(value or "")


async def _token(
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    scope: str = _GRAPH_SCOPE,
) -> str:
    """Azure AD client-credentials -> bearer token for ``scope``. Any non-2xx raises.

    ``scope`` selects the resource: the Graph default (alerts + hunting) or
    ``_MDE_SCOPE`` for the Defender for Endpoint API (machine / file / IP stats).
    """
    if not tenant_id:
        raise DefenderError(0, "Defender oauth_tenant_id (Azure AD tenant) not configured")
    cid, sec = _secret(client_id), _secret(client_secret)
    if not cid or not sec:
        raise DefenderError(0, "Defender client_id/client_secret not configured")
    async with httpx.AsyncClient(timeout=30.0) as c:
        resp = await c.post(
            f"{_LOGIN}/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": cid,
                "client_secret": sec,
                "scope": scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not resp.is_success:
            logger.warning("defender.token_error", status=resp.status_code)
            raise DefenderError(resp.status_code, resp.text[:300])
        token = (resp.json() or {}).get("access_token")
        if not token:
            raise DefenderError(resp.status_code, "no access_token in token response")
        return str(token)


async def list_alerts(
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    since: str,
    top: int = 100,
    max_records: int = 100,
) -> list[dict]:
    """List Graph Security alerts created since ``since`` (RFC3339 `Z`), oldest first.

    Read-only. Follows ``@odata.nextLink`` pagination until exhausted or ``max_records`` reached.
    """
    token = await _token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}
    items: list[dict] = []
    url: str | None = f"{_GRAPH}/security/alerts_v2"
    # NOTE: List alerts_v2 does NOT support $orderby (would 400 / be ignored); default order is
    # newest-first. The createdDateTime $filter + max_records cap bound the pull.
    params: dict[str, Any] | None = {
        "$filter": f"createdDateTime gt {since}",
        "$top": min(max(int(top), 1), 1000),
    }
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as c:
        while url and len(items) < max_records:
            resp = await c.get(url, params=params)
            params = None  # nextLink already carries the query
            if not resp.is_success:
                raise DefenderError(resp.status_code, resp.text[:300])
            body = resp.json() or {}
            items.extend(body.get("value") or [])
            url = body.get("@odata.nextLink")
    return items[:max_records]


async def ping(*, tenant_id: str | None, client_id: Any, client_secret: Any) -> None:
    """Minimal read-only auth check — a successful token fetch means the creds authenticate."""
    await _token(tenant_id, client_id, client_secret)


# ── Read-only enrichment / hunting (for the deep-tier LLM tools) ──────────────
# Graph runs advanced hunting; the Defender for Endpoint API serves machine / file
# / IP detail. All read-only. Each raises DefenderError on a non-2xx so the tool
# handler can degrade to an {"error": ...} result.


async def run_hunting_query(
    kql: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    max_records: int = 100,
) -> list[dict]:
    """Run an advanced-hunting KQL query via Graph (``POST /security/runHuntingQuery``).

    Read-only. Returns the result rows (capped at ``max_records`` to bound context).
    """
    token = await _token(tenant_id, client_id, client_secret)  # Graph scope default
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30.0) as c:
        resp = await c.post(f"{_GRAPH}/security/runHuntingQuery", json={"Query": kql})
    if not resp.is_success:
        raise DefenderError(resp.status_code, resp.text[:300])
    results = (resp.json() or {}).get("results") or []
    return results[:max_records]


async def _mde_get(
    path: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    params: dict[str, Any] | None = None,
) -> dict:
    """Authenticated GET against the Defender for Endpoint API. Non-2xx raises."""
    token = await _token(tenant_id, client_id, client_secret, scope=_MDE_SCOPE)
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30.0) as c:
        resp = await c.get(f"{_MDE}/{path}", params=params)
    if not resp.is_success:
        raise DefenderError(resp.status_code, resp.text[:300])
    return resp.json() or {}


async def get_machine(
    machine_id: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Machine record: risk/exposure score, business value, OS, health, last seen, IPs."""
    return await _mde_get(
        f"machines/{machine_id}",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def get_file_stats(
    sha1: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Org prevalence + global first/last seen for a file (keyed by SHA-1)."""
    return await _mde_get(
        f"files/{sha1}/stats",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def get_ip_stats(
    ip: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Org-level stats for an IP address (sightings across the tenant)."""
    return await _mde_get(
        f"ips/{ip}/stats",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def get_file_info(
    file_id: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """File profile + Microsoft's OWN verdict for a SHA-1/SHA-256: determinationType/
    determinationValue, signer/issuer, isValidCertificate, filePublisher, global
    prevalence. Complements get_file_stats (org prevalence). File.Read.All."""
    return await _mde_get(
        f"files/{file_id}",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def get_domain_stats(
    domain: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Organisation prevalence + first/last seen for a domain. Url.Read.All. MDE has
    no /api/urls endpoint; a "URL profile" IS the domain stats."""
    return await _mde_get(
        f"domains/{domain}/stats",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def check_custom_indicator(
    value: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Whether an indicator value is on the tenant's OWN custom allow/block list (Ti
    custom indicators). Returns {"matches": [...]} (each with action=Allowed/Block/
    Warn/...). A decisive LOCAL reputation check: "already Allowed" is a strong FP
    signal, "on the blocklist" a strong TP signal. Ti.ReadWrite covers the read."""
    body = await _mde_get(
        "indicators",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        params={"$filter": f"indicatorValue eq '{value}'"},
    )
    return {"matches": body.get("value") or []}


# ── Response actions (Defender for Endpoint API) — ANALYST-GATED, not auto-run ─
# WRITE / containment actions. These are NEVER exposed as auto-run LLM tools; they
# fire only from an authenticated, justification-bearing analyst request (see
# routes/defenderactions.py). Each returns the created machineAction object.


async def _mde_post(
    path: str, *, tenant_id: str | None, client_id: Any, client_secret: Any, body: dict
) -> dict:
    """Authenticated POST against the Defender for Endpoint API. Non-2xx raises."""
    token = await _token(tenant_id, client_id, client_secret, scope=_MDE_SCOPE)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as c:
        resp = await c.post(f"{_MDE}/{path}", json=body)
    if not resp.is_success:
        raise DefenderError(resp.status_code, resp.text[:300])
    return resp.json() or {}


async def isolate_machine(
    machine_id: str,
    comment: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    isolation_type: str = "Full",
) -> dict:
    """Isolate a device (DESTRUCTIVE — cuts its network). ``Machine.Isolate`` perm."""
    return await _mde_post(
        f"machines/{machine_id}/isolate",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        body={"Comment": comment, "IsolationType": isolation_type},
    )


async def unisolate_machine(
    machine_id: str, comment: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Release a device from isolation. ``Machine.Isolate`` perm covers this too."""
    return await _mde_post(
        f"machines/{machine_id}/unisolate",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        body={"Comment": comment},
    )


async def run_av_scan(
    machine_id: str,
    comment: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    scan_type: str = "Quick",
) -> dict:
    """Run an antivirus scan on a device. ``Machine.Scan`` perm."""
    return await _mde_post(
        f"machines/{machine_id}/runAntiVirusScan",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        body={"Comment": comment, "ScanType": scan_type},
    )


async def add_indicator(
    indicator_value: str,
    indicator_type: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    action: str = "Block",
    title: str = "",
    severity: str = "Medium",
    description: str = "",
) -> dict:
    """Create a custom indicator (blocklist entry). ``Ti.ReadWrite`` perm. POST /api/indicators.

    ``indicator_type`` is the Defender enum (IpAddress / DomainName / Url / FileSha256 /
    FileSha1); ``action`` is Block / Alert / AlertAndBlock / Audit / Allowed.
    """
    return await _mde_post(
        "indicators",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        body={
            "indicatorValue": indicator_value,
            "indicatorType": indicator_type,
            "action": action,
            "title": title or f"ISOC block {indicator_value}",
            "severity": severity,
            "description": description or title or "Blocked by ISOC",
        },
    )


# ── Alert write-back (Graph Security) — verdict / analyst-gated WRITE ──────────
# Graph ``SecurityAlert.ReadWrite.All``. Mirrors the analyst verdict back to the
# Defender alert so it stops accruing the tenant's exposure (parallels the V1
# ``mirror_verdict_to_v1``).

_DEFENDER_STATUS_MAP: dict[str, tuple[str, str]] = {
    "tp": ("resolved", "truePositive"),
    "fp": ("resolved", "falsePositive"),
    "benign": ("resolved", "informationalExpectedActivity"),
}


def verdict_to_defender_status(verdict: Any) -> tuple[str, str] | None:
    """Pure: map an ISOC verdict (enum or str) to (status, classification), or None."""
    key = str(getattr(verdict, "value", verdict) or "").strip().lower()
    return _DEFENDER_STATUS_MAP.get(key)


async def update_alert(
    alert_id: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    status: str | None = None,
    classification: str | None = None,
    determination: str | None = None,
) -> dict:
    """PATCH a Graph Security alert's status/classification/determination (WRITE).

    ``SecurityAlert.ReadWrite.All`` (Graph). Returns the updated alert (or {} on a 204).
    """
    token = await _token(tenant_id, client_id, client_secret)  # Graph audience
    body = {
        k: v
        for k, v in {
            "status": status,
            "classification": classification,
            "determination": determination,
        }.items()
        if v is not None
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as c:
        resp = await c.patch(f"{_GRAPH}/security/alerts_v2/{alert_id}", json=body)
    if not resp.is_success:
        raise DefenderError(resp.status_code, resp.text[:300])
    return resp.json() if resp.content else {}


async def set_user_enabled(
    user_id: str,
    enabled: bool,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
) -> dict:
    """Enable/disable an Entra user account (WRITE). Graph ``User.EnableDisableAccount.All``.

    ``PATCH /users/{id}`` with ``accountEnabled``; ``user_id`` is the object id or UPN.
    Identity containment — analyst-gated. Returns {} on the 204.
    """
    token = await _token(tenant_id, client_id, client_secret)  # Graph audience
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as c:
        resp = await c.patch(f"{_GRAPH}/users/{user_id}", json={"accountEnabled": enabled})
    if not resp.is_success:
        raise DefenderError(resp.status_code, resp.text[:300])
    return resp.json() if resp.content else {}


async def mirror_verdict_to_defender(incident: Any, verdict: Any) -> None:
    """Mirror an analyst/auto verdict back to the Defender alert (fail-soft, flag-gated).

    No-op unless ``defender_status_writeback_enabled`` AND the incident is a Defender alert
    (source microsoft_defender + a Graph alert id) with resolvable creds. NEVER raises — a
    write-back failure must not break the verdict commit / gate.
    """
    from ..settings import settings

    if not settings.defender_status_writeback_enabled:
        return
    norm = getattr(incident, "normalized", None) or {}
    if norm.get("source_product") != "microsoft_defender":
        return
    alert_id = norm.get("alert_id")
    mapped = verdict_to_defender_status(verdict)
    if not alert_id or mapped is None:
        return
    try:
        from .integration_store import get_creds

        creds = await get_creds("microsoft_defender", getattr(incident, "customer", None))
        if creds is None:
            return
        await update_alert(
            str(alert_id),
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            status=mapped[0],
            classification=mapped[1],
        )
        logger.info("defender.status_writeback", alert=str(alert_id), status=mapped[0])
    except Exception as exc:  # never break the gate
        logger.warning("defender.status_writeback_failed", alert=str(alert_id), error=str(exc))
