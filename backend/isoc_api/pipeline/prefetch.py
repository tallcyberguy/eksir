"""ADR-0009 PR-1: deterministic pre-L2 Microsoft entity enrichment.

Runs just before the deep (L2) call, for ESCALATED alerts only (short-circuited
alerts never reach the call site), and only when ``ms_autoenrich_enabled`` plus a
Microsoft Defender integration for the incident's customer are present. It fetches
read-only reputation/prevalence for the alert's IOCs (file hash, domain, IP)
concurrently and fail-soft, and writes a compact summary under
``incident.enrichment["ms"]["reputation"]`` for the briefing.

Read-only by construction: only the GET adapter functions are called; there is no
path here to any Defender write. Fail-soft by construction: nothing raised here
propagates, so a dead token or a throttled API never blocks L2.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..adapters import defender_adapter, integration_store
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.pipeline.prefetch")

# Truncate oversized string values so a wide profile can't bloat the L2 prompt.
_STR_TRUNC = 500
# Cap IOCs looked up per type so a noisy multi-IOC alert can't fan out into dozens
# of live API calls (Defender/Graph throttling).
_MAX_PER_TYPE = 6

_HASH_TYPES = {"sha256", "sha1", "md5"}
_DOMAIN_TYPES = {"domain"}
_IP_TYPES = {"ipv4", "ipv6", "ip"}


def _slim(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj[:_STR_TRUNC] + "…" if len(obj) > _STR_TRUNC else obj
    if isinstance(obj, dict):
        return {k: _slim(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_slim(v) for v in obj]
    return obj


def _iocs_by_type(enrichment: dict[str, Any]) -> dict[str, list[str]]:
    """Collect deduped IOC values by coarse type from the triage rows."""
    out: dict[str, list[str]] = {"hash": [], "domain": [], "ip": []}
    seen: set[str] = set()
    for r in enrichment.get("triage") or []:
        q = r.get("query") or {}
        ioc = (q.get("ioc") if isinstance(q, dict) else None) or r.get("ioc")
        typ = ((q.get("type") if isinstance(q, dict) else None) or r.get("type") or "").lower()
        if not ioc or ioc in seen:
            continue
        if typ in _HASH_TYPES:
            bucket = "hash"
        elif typ in _DOMAIN_TYPES:
            bucket = "domain"
        elif typ in _IP_TYPES:
            bucket = "ip"
        else:
            continue
        if len(out[bucket]) >= _MAX_PER_TYPE:
            continue
        out[bucket].append(str(ioc))
        seen.add(ioc)
    return out


def _creds_kw(creds: Any) -> dict[str, Any]:
    return {
        "tenant_id": getattr(creds, "oauth_tenant_id", None),
        "client_id": getattr(creds, "client_id", None),
        "client_secret": getattr(creds, "client_secret", None),
    }


async def _reputation(creds: Any, iocs: dict[str, list[str]]) -> dict[str, Any]:
    """Fetch reputation for every IOC concurrently. Each read is guarded, so one
    403/404/throttle drops a single field, never the whole record or the batch."""
    kw = _creds_kw(creds)

    async def _guard(kind: str, value: str, reads: dict[str, Any]) -> dict[str, Any]:
        rec: dict[str, Any] = {"kind": kind, "value": value}
        for key, coro in reads.items():
            try:
                rec[key] = _slim(await coro)
            except Exception as exc:  # fail-soft per read
                rec.setdefault("errors", {})[key] = str(exc)[:200]
        return rec

    tasks: list[Any] = []
    for sha in iocs["hash"]:
        tasks.append(
            _guard(
                "file",
                sha,
                {
                    "info": defender_adapter.get_file_info(sha, **kw),
                    "stats": defender_adapter.get_file_stats(sha, **kw),
                    "custom_indicator": defender_adapter.check_custom_indicator(sha, **kw),
                },
            )
        )
    for dom in iocs["domain"]:
        tasks.append(
            _guard(
                "domain",
                dom,
                {
                    "stats": defender_adapter.get_domain_stats(dom, **kw),
                    "custom_indicator": defender_adapter.check_custom_indicator(dom, **kw),
                },
            )
        )
    for ip in iocs["ip"]:
        tasks.append(
            _guard(
                "ip",
                ip,
                {
                    "stats": defender_adapter.get_ip_stats(ip, **kw),
                    "custom_indicator": defender_adapter.check_custom_indicator(ip, **kw),
                },
            )
        )

    records = await asyncio.gather(*tasks, return_exceptions=True)
    reputation: dict[str, list[dict]] = {"files": [], "domains": [], "ips": []}
    routing = {"file": "files", "domain": "domains", "ip": "ips"}
    for rec in records:
        if isinstance(rec, BaseException) or not isinstance(rec, dict):
            continue  # a whole-IOC failure; skip (fail-soft)
        reputation[routing[rec.pop("kind")]].append(rec)
    return reputation


async def prefetch_ms_enrichment(incident: Any) -> dict | None:
    """Deterministic pre-L2 Microsoft reputation enrichment for one incident.

    Returns the reputation summary (also written to ``incident.enrichment["ms"]
    ["reputation"]``) or None when the step is skipped (flag off, no creds, or no
    usable IOCs). Never raises.
    """
    if not settings.ms_autoenrich_enabled:
        return None
    try:
        creds = await integration_store.get_creds("microsoft_defender", incident.customer)
    except Exception:
        creds = None
    if creds is None:
        return None

    enrichment = incident.enrichment or {}
    iocs = _iocs_by_type(enrichment)
    if not any(iocs.values()):
        return None

    try:
        reputation = await _reputation(creds, iocs)
    except Exception as exc:  # belt-and-suspenders; _reputation is already guarded
        logger.warning(
            "prefetch.reputation_failed", incident=str(getattr(incident, "id", "?")), error=str(exc)
        )
        return None

    ms = dict(enrichment.get("ms") or {})
    ms["reputation"] = reputation
    enrichment["ms"] = ms
    incident.enrichment = enrichment  # reassign so SQLAlchemy flags the JSON dirty
    return reputation
