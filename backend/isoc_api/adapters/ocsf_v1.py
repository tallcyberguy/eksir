"""Native OCSF-first parser for Trend Micro Vision One Workbench alerts (v3.0 API).

Ports the workbench-JSON path of the retiring vendored ``visionone`` parser onto
the isoc_api side, so the ``vision_one`` PULL CONNECTOR normalizes natively
(OCSF-first) instead of through the vendored parser. ``pipeline/ocsf.py`` then
derives OCSF entities plus a Detection Finding from the NormalizedAlert.

The connector always hands us the full Workbench alert dict (the v3.0 list
endpoint returns the whole alert), so this parser mines it fully: description,
structured MITRE from ``matchedRules[]``, indicators (hashes, path, dst_ip, url),
the impact blast-radius, and Trend's own verdict/status/incident context.

A non-dict input (a manually pasted V1 email, the retired forward format) is
delegated to the vendored text parser until that path is dropped too.

Defensive by design: every field is optional, a missing or garbled section is
left None, and the parser never raises. Behaviour-preserving vs the vendored
parser on the dict path (see tests/test_ocsf_v1.py golden-equivalence check).
"""

from __future__ import annotations

import json
import re
from typing import Any

# Vision One severity word -> Wazuh-style 1-15 int so finalize() derives the shared
# severity_label (low/medium/high/critical) consistently with the other products.
V1_SEVERITY_MAP = {
    "info": 1,
    "informational": 1,
    "low": 3,
    "medium": 6,
    "high": 9,
    "critical": 14,
}

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CONSOLE_RE = re.compile(r"https?://([\w.-]*xdr\.trendmicro\.com)", re.IGNORECASE)
_REGION_RE = re.compile(r"portal\.([a-z0-9-]+)\.xdr\.trendmicro\.com", re.IGNORECASE)


def _region_from_console(host: str | None) -> str | None:
    """portal.sg.xdr.trendmicro.com -> 'sg'; portal.xdr.trendmicro.com -> 'us'."""
    if not host:
        return None
    m = _REGION_RE.search(host)
    if m:
        return m.group(1).lower()
    # No region segment (portal.xdr.trendmicro.com / api.xdr.trendmicro.com) means US.
    if re.search(r"\bportal\.xdr\.trendmicro\.com\b", host, re.IGNORECASE):
        return "us"
    return None


def _wb_entities(data: dict) -> tuple[str | None, str | None, str | None]:
    """First host, account, and host-IP from a Workbench alert's impactScope."""
    scope = data.get("impactScope") or {}
    ents = scope.get("entities") or []
    host = user = src_ip = None
    for e in ents:
        if not isinstance(e, dict):
            continue
        etype = str(e.get("entityType") or "").lower()
        val = e.get("entityValue")
        name = val.get("name") if isinstance(val, dict) else val
        if etype in ("host", "endpoint") and host is None:
            host = str(name) if name is not None else None
            if isinstance(val, dict):
                ips = val.get("ips") or val.get("ip") or []
                if isinstance(ips, str):
                    ips = [ips]
                if ips:
                    src_ip = str(ips[0])
        elif etype in ("account", "user", "useraccount", "emailaddress") and user is None:
            user = str(name) if name is not None else None
    return host, user, src_ip


def _impact_summary(data: dict) -> str:
    """Compact blast-radius line from impactScope counts (e.g. '2 servers, 1 account')."""
    scope = data.get("impactScope") or {}
    parts = []
    for key, label in (
        ("desktopCount", "desktops"),
        ("serverCount", "servers"),
        ("accountCount", "accounts"),
        ("emailAddressCount", "emails"),
        ("containerCount", "containers"),
        ("cloudIdentityCount", "cloud-identities"),
    ):
        n = scope.get(key)
        if isinstance(n, int) and n > 0:
            parts.append(f"{n} {label}")
    return ", ".join(parts)


def _wb_matched_rules(data: dict) -> tuple[list[str], list[str], str | None]:
    """Structured MITRE technique + tactic ids and the first matched-rule name.

    Authoritative MITRE source: matchedRules[].matchedFilters[].mitreTechniqueIds /
    mitreTacticIds.
    """
    techs: list[str] = []
    tactics: list[str] = []
    rule_name = None
    for rule in data.get("matchedRules") or []:
        if not isinstance(rule, dict):
            continue
        if rule_name is None and rule.get("name"):
            rule_name = str(rule["name"])
        for mf in rule.get("matchedFilters") or []:
            if not isinstance(mf, dict):
                continue
            for t in mf.get("mitreTechniqueIds") or []:
                s = str(t)
                if _TECHNIQUE_RE.fullmatch(s) and s not in techs:
                    techs.append(s)
            for ta in mf.get("mitreTacticIds") or []:
                s = str(ta)
                if re.fullmatch(r"TA\d{4}", s) and s not in tactics:
                    tactics.append(s)
    return techs, tactics, rule_name


def _wb_indicators(data: dict) -> dict:
    """Collect IOCs from indicators[] by (type|field), keeping every high-value slot.

    Vision One indicators carry the semantic in ``type`` (newer enum: file_sha256,
    command_line, ip, url, ...) or ``field`` (older shape: objectCmd /
    objectFileHashSha256 / processFilePath / ...), so switch on a lowercased blend
    of both. Returns first-of-each plus all command lines.
    """
    out: dict = {
        "sha256": None,
        "sha1": None,
        "file_path": None,
        "dst_ip": None,
        "url": None,
        "cmds": [],
    }
    for ind in data.get("indicators") or []:
        if not isinstance(ind, dict):
            continue
        itype = str(ind.get("type") or ind.get("field") or "").lower()
        val = ind.get("value")
        if val is None:
            continue
        val = str(val)
        if "sha256" in itype and out["sha256"] is None and re.fullmatch(r"[0-9a-fA-F]{64}", val):
            out["sha256"] = val.lower()
        elif "sha1" in itype and out["sha1"] is None and re.fullmatch(r"[0-9a-fA-F]{40}", val):
            out["sha1"] = val.lower()
        elif "command" in itype or itype.endswith("cmd"):
            out["cmds"].append(val)
        elif ("fullpath" in itype or "filepath" in itype or "filename" in itype) and out[
            "file_path"
        ] is None:
            out["file_path"] = val
        elif (itype == "ip" or "objectip" in itype) and out["dst_ip"] is None:
            out["dst_ip"] = val
        elif ("url" in itype or "domain" in itype) and out["url"] is None:
            out["url"] = val
    return out


def _parse_workbench_json(data: dict, customer: str | None = None) -> Any:
    """Map a Vision One Workbench alert JSON (v3.0 API) to a finalized NormalizedAlert."""
    from normalizer import NormalizedAlert  # type: ignore[import-not-found]

    alert = NormalizedAlert()
    alert.source_product = "visionone"
    alert.customer = customer
    alert.raw = json.dumps(data, ensure_ascii=False, default=str)

    wb = data.get("id")
    if wb:
        alert.v1_workbench_id = str(wb)
        alert.rule_id = str(wb)

    # Console host + region from the workbench link, when present.
    link = data.get("workbenchLink") or data.get("alertProviderLink") or ""
    cm = _CONSOLE_RE.search(str(link))
    if cm:
        alert.v1_console_host = cm.group(1)
        alert.v1_region = _region_from_console(cm.group(1))

    model = data.get("model")
    if model:
        alert.rule_name = str(model)
        alert.event_name = str(model)

    sev_word = str(data.get("severity") or "").lower()
    alert.severity = V1_SEVERITY_MAP.get(sev_word, 6)

    # description is the richest natural-language summary.
    if data.get("description"):
        alert.event_description = str(data["description"])

    # Structured MITRE + the specific matched-rule name (sharper than the model name).
    techs, tactics, rule_name = _wb_matched_rules(data)
    if techs:
        alert.mitre_technique = techs[0]
    else:
        tm = _TECHNIQUE_RE.search(alert.raw)
        if tm:
            alert.mitre_technique = tm.group(0)
    if tactics:
        alert.mitre_tactic = tactics[0]
    if rule_name:
        alert.threat_category = rule_name

    # alertProvider (SAE / TI / ...) is the detection engine that fired.
    provider = data.get("alertProvider")
    if provider:
        alert.event_category = str(provider)

    created = data.get("createdDateTime") or data.get("firstInvestigatedDateTime")
    if created:
        alert.timestamp = str(created)

    host, user, src_ip = _wb_entities(data)
    alert.hostname = host
    alert.username = user
    alert.src_ip = src_ip

    ind = _wb_indicators(data)
    if ind["sha256"]:
        alert.file_hash_sha256 = ind["sha256"]
    if ind["sha1"]:
        alert.file_hash_sha1 = ind["sha1"]
    if ind["file_path"]:
        alert.file_path = ind["file_path"]
    if ind["dst_ip"]:
        alert.dst_ip = ind["dst_ip"]
    if ind["url"]:
        alert.url = ind["url"]

    # Fold high-signal context the NormalizedAlert has no dedicated slot for into the
    # description: vendor score, Trend's own verdict/status, the incident correlation
    # id, blast radius, extra MITRE techniques, and the process command lines.
    ctx: list[str] = []
    score = data.get("score")
    if score is not None:
        ctx.append(f"V1 score {score}")
        try:
            alert.vendor_score = int(score)  # feeds pipeline/scoring.py inherent threat
        except (TypeError, ValueError):
            pass
    if data.get("investigationResult"):
        ctx.append(f"Trend verdict: {data['investigationResult']}")
    status = data.get("status") or data.get("investigationStatus")
    if status:
        ctx.append(f"status: {status}")
    if data.get("incidentId"):
        ctx.append(f"incident: {data['incidentId']}")
    impact = _impact_summary(data)
    if impact:
        ctx.append(f"impact: {impact}")
    if len(techs) > 1:
        ctx.append("MITRE: " + ", ".join(techs))
    for c in ind["cmds"][:3]:
        ctx.append(f"cmdline: {c[:500]}")
    if ctx:
        base = (alert.event_description or "").rstrip()
        alert.event_description = (base + "\n" + "\n".join(ctx)).strip()

    return alert.finalize()


def parse(raw: Any, customer: str | None = None) -> Any:
    """Map a Vision One Workbench alert to a finalized NormalizedAlert.

    The pull connector always hands us the v3.0 Workbench JSON dict, parsed
    natively here. A non-dict input (a manually pasted V1 email, the retired
    forward format) delegates to the vendored text parser until that path is
    dropped too.
    """
    if isinstance(raw, dict):
        return _parse_workbench_json(raw, customer)
    from parsers import visionone as _vendored  # type: ignore[import-not-found]

    return _vendored.parse(raw, customer)
