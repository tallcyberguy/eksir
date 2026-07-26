"""ADR-0009 PR-1/2/3: deterministic pre-L2 Microsoft entity enrichment.

Runs just before the deep (L2) call, for ESCALATED alerts only (short-circuited
alerts never reach the call site), and only when ``ms_autoenrich_enabled`` plus the
relevant integration creds are present. Three slices run concurrently and fail-soft,
each writing under ``incident.enrichment["ms"]``:

- ``reputation`` (PR-1) — Defender file/domain/IP prevalence + verdict + the tenant's
  own custom allow/block list, for the alert's IOCs.
- ``endpoint`` (PR-2) — the impacted host's detail. Defender ``get_machine``
  (riskScore / exposureLevel / deviceValue) for a Defender alert; Vision One
  ``get_endpoint_details`` for a V1 alert (no risk score exists there, so the
  reduced surface is surfaced honestly).
- ``identity`` (PR-3) — tenant-keyed Entra/Graph read (profile + manager + risky-user
  state + risk detections + MFA registration + recent sign-ins) for ANY incident that
  names a user, resolved via the Defender app's Graph creds.

Read-only + GET-only by construction; there is no path here to any write. Fail-soft
by construction: nothing raised here propagates, so a dead token or a throttled API
never blocks L2.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..adapters import (
    defender_adapter,
    graph_identity_adapter,
    integration_store,
    ocsf_defender,
    v1_adapter,
)
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


# ── shared helpers ───────────────────────────────────────────────────────────
def _slim(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj[:_STR_TRUNC] + "…" if len(obj) > _STR_TRUNC else obj
    if isinstance(obj, dict):
        return {k: _slim(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_slim(v) for v in obj]
    return obj


def _creds_kw(creds: Any) -> dict[str, Any]:
    return {
        "tenant_id": getattr(creds, "oauth_tenant_id", None),
        "client_id": getattr(creds, "client_id", None),
        "client_secret": getattr(creds, "client_secret", None),
    }


async def _get_creds(provider: str, customer: Any) -> Any:
    try:
        return await integration_store.get_creds(provider, customer)
    except Exception:
        return None


async def _gather_reads(reads: dict[str, Any]) -> tuple[dict, dict]:
    """Await a name->coroutine map concurrently. Returns (results, errors); a failing
    read lands in errors keyed by name, never sinking the batch. Results are slimmed."""
    keys = list(reads)
    done = await asyncio.gather(*reads.values(), return_exceptions=True)
    out: dict[str, Any] = {}
    errs: dict[str, str] = {}
    for k, v in zip(keys, done, strict=True):
        if isinstance(v, BaseException):
            errs[k] = str(v)[:200]
        else:
            out[k] = _slim(v)
    return out, errs


# ── reputation slice (PR-1) ──────────────────────────────────────────────────
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


async def _reputation(creds: Any, iocs: dict[str, list[str]]) -> dict[str, Any]:
    kw = _creds_kw(creds)

    async def _guard(kind: str, value: str, reads: dict[str, Any]) -> dict[str, Any]:
        out, errs = await _gather_reads(reads)
        rec: dict[str, Any] = {"kind": kind, "value": value, **out}
        if errs:
            rec["errors"] = errs
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
            continue
        reputation[routing[rec.pop("kind")]].append(rec)
    return reputation


async def _reputation_slice(enrichment: dict, def_creds: Any) -> dict | None:
    if def_creds is None:
        return None
    iocs = _iocs_by_type(enrichment)
    if not any(iocs.values()):
        return None
    try:
        return {"reputation": await _reputation(def_creds, iocs)}
    except Exception as exc:  # belt-and-suspenders; _reputation is already guarded
        logger.warning("prefetch.reputation_failed", error=str(exc))
        return None


# ── endpoint slice (PR-2) ────────────────────────────────────────────────────
def _normalize_defender_machine(m: dict) -> dict:
    return {
        "provider": "microsoft_defender",
        "hostname": m.get("computerDnsName"),
        "os": m.get("osPlatform"),
        "os_version": m.get("version"),  # Defender uses `version`, not osVersion
        "last_seen": m.get("lastSeen"),
        "last_ip": m.get("lastIpAddress"),
        "risk_score": m.get("riskScore"),  # None/Informational/Low/Medium/High
        "exposure_level": m.get("exposureLevel"),  # None/Low/Medium/High
        "device_value": m.get("deviceValue"),  # business criticality: Normal/Low/High
        "health": m.get("healthStatus"),
        "tags": m.get("machineTags"),
    }


def _normalize_v1_endpoint(items: list) -> dict | None:
    if not items:
        return None
    e = items[0]
    os = e.get("os") or {}
    epp = e.get("eppAgent") or {}
    edr = e.get("edrSensor") or {}
    return {
        "provider": "vision_one",
        "hostname": e.get("endpointName"),
        "agent_guid": e.get("agentGuid"),
        "os": os.get("name") or os.get("platform"),
        "os_version": os.get("version"),
        "last_ip": e.get("lastUsedIp"),
        "last_user": e.get("lastLoggedOnUser"),
        "isolation_status": e.get("isolationStatus"),
        "epp_status": epp.get("status"),
        "edr_connectivity": edr.get("connectivity"),
        "last_connected": epp.get("lastConnectedDateTime") or edr.get("lastConnectedDateTime"),
        # Vision One eiqs/endpoints exposes NO device risk score (ASRM/CREM only).
        "criticality": None,
    }


async def _endpoint_slice(normalized: dict, def_creds: Any, v1_creds: Any) -> dict | None:
    source = (normalized.get("source_product") or "").lower()
    try:
        if source == "microsoft_defender" and def_creds is not None:
            device_id = ocsf_defender.mde_device_id(normalized.get("raw"))
            if not device_id:
                return None
            machine = await defender_adapter.get_machine(device_id, **_creds_kw(def_creds))
            return {"endpoint": _normalize_defender_machine(_slim(machine))}
        if source in ("visionone", "vision_one") and v1_creds is not None:
            host = normalized.get("hostname") or normalized.get("endpoint_name")
            if not host:
                return None
            items = await v1_adapter.get_endpoint_details(
                str(host),
                region=getattr(v1_creds, "region", None),
                api_key=getattr(v1_creds, "api_key", None),
            )
            norm = _normalize_v1_endpoint([_slim(i) for i in items])
            return {"endpoint": norm} if norm else None
    except Exception as exc:
        logger.warning("prefetch.endpoint_failed", error=str(exc))
    return None


# ── identity slice (PR-3) ────────────────────────────────────────────────────
def _resolve_user(normalized: dict) -> str | None:
    """A Graph-addressable user id / UPN for the impacted principal, or None."""
    if (normalized.get("source_product") or "").lower() == "microsoft_defender":
        uid = ocsf_defender.entra_user_id(normalized.get("raw"))
        if uid:
            return uid
    for k in ("upn", "user_principal_name", "username", "user_name", "user"):
        v = normalized.get(k)
        if v and "@" in str(v):  # a UPN/email is Graph-addressable; a bare name is not
            return str(v)
    return None


async def _identity_slice(normalized: dict, def_creds: Any) -> dict | None:
    if def_creds is None:  # Entra reads use the Defender app's Graph creds
        return None
    user = _resolve_user(normalized)
    if not user:
        return None
    kw = _creds_kw(def_creds)
    # Resolve the object id from the profile FIRST: riskyUsers / riskDetections /
    # userRegistrationDetails / signIns all key on the object GUID, not the UPN.
    try:
        profile = _slim(await graph_identity_adapter.get_user_profile(user, **kw))
    except Exception as exc:
        logger.warning("prefetch.identity_profile_failed", error=str(exc))
        return None
    oid = profile.get("id") or user
    out, errs = await _gather_reads(
        {
            "risk": graph_identity_adapter.get_risky_user(oid, **kw),
            "risk_detections": graph_identity_adapter.get_risk_detections(oid, **kw),
            "mfa": graph_identity_adapter.get_registration_details(oid, **kw),
            "sign_ins": graph_identity_adapter.get_sign_ins(oid, **kw),
        }
    )
    identity: dict[str, Any] = {
        "user": user,
        "profile": profile,
        "risk": out.get("risk") or {},
        "risk_detections": (out.get("risk_detections") or {}).get("detections") or [],
        "mfa": out.get("mfa") or {},
        "sign_ins": (out.get("sign_ins") or {}).get("sign_ins") or [],
    }
    if errs:
        identity["errors"] = errs
    return {"identity": identity}


# ── orchestrator ─────────────────────────────────────────────────────────────
async def prefetch_ms_enrichment(incident: Any) -> dict | None:
    """Run the reputation + endpoint + identity slices concurrently and merge them
    under ``incident.enrichment["ms"]``. Returns the merged ``ms`` dict, or None when
    nothing ran (flag off, no creds, or no usable entities). Never raises.
    """
    if not settings.ms_autoenrich_enabled:
        return None
    customer = getattr(incident, "customer", None)
    def_creds = await _get_creds("microsoft_defender", customer)  # Defender + Graph identity
    v1_creds = await _get_creds("vision_one", customer)  # V1 endpoint
    if def_creds is None and v1_creds is None:
        return None

    enrichment = incident.enrichment or {}
    normalized = incident.normalized or {}

    slices = await asyncio.gather(
        _reputation_slice(enrichment, def_creds),
        _endpoint_slice(normalized, def_creds, v1_creds),
        _identity_slice(normalized, def_creds),
        return_exceptions=True,
    )
    ms = dict(enrichment.get("ms") or {})
    for sl in slices:
        if isinstance(sl, dict):
            ms.update(sl)
    if not ms:
        return None
    enrichment["ms"] = ms
    incident.enrichment = enrichment  # reassign so SQLAlchemy flags the JSON dirty
    return ms
