"""
Trend Micro Vision One (Workbench) email-notification parser.

Vision One Workbench alerts arrive as information-poor emails: a Workbench ID,
model name, score, impact-scope counts, a few highlighted process commands, and
a technique id. This parser pulls those fields and — crucially — the Workbench
ID + console region, so the ISOC backend can later fetch the full alert detail
(and OAT) via the v3.0 API (region resolved from the console host).

Defensive by design: every section is optional. A missing/garbled field is left
None; the parser never raises (the dispatcher's fallback handles total misses).

Example subject/body markers it keys on:
    "| Workbench |"  "TrendAI Vision One"  "Workbench ID: WB-..."  "Model severity:"
    "Techniques:"    "https://portal.<region>.xdr.trendmicro.com/...workbench/alerts/..."
"""

import json
import re
from datetime import datetime
from typing import Optional

from normalizer import NormalizedAlert

# Vision One severity word -> Wazuh-style 1-15 int so finalize() can derive the
# shared severity_label (low/medium/high/critical) consistently with other products.
V1_SEVERITY_MAP = {
    "info": 1,
    "informational": 1,
    "low": 3,
    "medium": 6,
    "high": 9,
    "critical": 14,
}

_WB_ID_RE = re.compile(r"\bWB-\d+-\d{8}-\d+\b")
# File-hash scans — anchored to a "*hash" label (objectHash/fileHash/hash), best
# effort only. The Vision One email is hash-poor; the real malicious hash comes
# from the v3 API enrichment. Requiring a hash label keeps TLS cert fingerprints,
# WB-ids, trace ids and GUIDs from being mis-slotted. Hex captured in group(1).
_SHA256_TEXT_RE = re.compile(r"(?i)[a-z0-9_]*hash\b[^0-9a-f]{0,20}([0-9a-fA-F]{64})")
_SHA1_TEXT_RE = re.compile(r"(?i)[a-z0-9_]*hash\b[^0-9a-f]{0,20}([0-9a-fA-F]{40})")
_CONSOLE_RE = re.compile(r"https?://([\w.-]*xdr\.trendmicro\.com)", re.IGNORECASE)
_REGION_RE = re.compile(r"portal\.([a-z0-9-]+)\.xdr\.trendmicro\.com", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _first(pattern: str, text: str, flags=re.IGNORECASE) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def _region_from_console(host: Optional[str]) -> Optional[str]:
    """portal.sg.xdr.trendmicro.com -> 'sg'; portal.xdr.trendmicro.com -> 'us'."""
    if not host:
        return None
    m = _REGION_RE.search(host)
    if m:
        return m.group(1).lower()
    # No region segment (portal.xdr.trendmicro.com / api.xdr.trendmicro.com) == US.
    if re.search(r"\bportal\.xdr\.trendmicro\.com\b", host, re.IGNORECASE):
        return "us"
    return None


def _scope_value(text: str, header: str) -> Optional[str]:
    """Grab the first indented value line under an Impact-Scope header, e.g.
        'Endpoint - Servers: 1\n   UNOEXCSRV01'  -> 'UNOEXCSRV01'
        'User accounts: 1\n   UNMAS_WG\\furkan'   -> 'UNMAS_WG\\furkan'
    """
    m = re.search(rf"{header}[^\n]*:\s*\d+\s*\n\s*([^\s][^\n]*)", text, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _parse_created(text: str) -> Optional[str]:
    """'Created: 2026-06-21 20:47:56' -> ISO 8601 (naive — no tz in the email)."""
    raw = _first(r"Created:\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", text)
    if not raw:
        return None
    try:
        return datetime.strptime(raw.replace("T", " "), "%Y-%m-%d %H:%M:%S").isoformat()
    except ValueError:
        return raw


def _wb_entities(data: dict):
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


def _wb_matched_rules(data: dict):
    """Structured MITRE technique + tactic ids and the first matched-rule name from matchedRules[].

    The authoritative MITRE source (matchedRules[].matchedFilters[].mitreTechniqueIds /
    mitreTacticIds) — replaces the old whole-blob T-code regex, and populates mitre_tactic.
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

    Vision One indicators carry the semantic in `type` (newer enum: file_sha256, command_line,
    ip, url, ...) or `field` (older shape: objectCmd/objectFileHashSha256/processFilePath/...),
    so we switch on a lowercased blend of both. Returns first-of-each plus all command lines.
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
        elif (
            "fullpath" in itype or "filepath" in itype or "filename" in itype
        ) and out["file_path"] is None:
            out["file_path"] = val
        elif (itype == "ip" or "objectip" in itype) and out["dst_ip"] is None:
            out["dst_ip"] = val
        elif ("url" in itype or "domain" in itype) and out["url"] is None:
            out["url"] = val
    return out


def _parse_workbench_json(data: dict, customer: str = None) -> NormalizedAlert:
    """Map a Vision One Workbench alert JSON (v3.0 API) to a NormalizedAlert.

    The list endpoint returns the FULL alert, so we mine it fully: description, structured MITRE
    from matchedRules[], all high-value indicators (hashes, path, dst_ip, url), the impact
    blast-radius, and Trend's own verdict/status/incident context. Defensive — every field is
    optional; a garbled section is left None rather than raising.
    """
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

    # description is the richest natural-language summary (was dropped entirely before).
    if data.get("description"):
        alert.event_description = str(data["description"])

    # Structured MITRE + the specific matched-rule name (sharper "what fired" than the model).
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

    # Fold high-signal context the NormalizedAlert has no dedicated slot for into the description:
    # vendor score, Trend's own verdict/status, the incident correlation id, blast radius, extra
    # MITRE techniques, and the process command lines (the core behavioral evidence).
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


def parse(raw_text, customer: str = None) -> NormalizedAlert:
    # v3.0 API pull hands us the raw Workbench alert dict — richer than the email.
    if isinstance(raw_text, dict):
        return _parse_workbench_json(raw_text, customer)
    text = raw_text if isinstance(raw_text, str) else str(raw_text)

    alert = NormalizedAlert()
    alert.source_product = "visionone"
    alert.customer = customer
    alert.raw = text

    # Workbench ID — from "Workbench ID:" line or anywhere in the subject/body.
    wb = _first(r"Workbench ID:\s*(WB-\d+-\d{8}-\d+)", text)
    if not wb:
        m = _WB_ID_RE.search(text)
        wb = m.group(0) if m else None
    alert.v1_workbench_id = wb
    alert.rule_id = wb  # surface the WB id in the standard slot too

    # Console host + region (so the backend can target the right API base).
    cm = _CONSOLE_RE.search(text)
    if cm:
        alert.v1_console_host = cm.group(1)
        alert.v1_region = _region_from_console(cm.group(1))

    # Model -> rule_name. Anchor to a line start and exclude "Model severity:".
    model = _first(r"^[ \t]*Model:[ \t]*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    alert.rule_name = model

    # Severity: prefer "Model severity:", fall back to the subject "Alert Severity:".
    sev_word = _first(r"Model severity:\s*([A-Za-z]+)", text) or _first(
        r"Alert Severity:\s*([A-Za-z]+)", text
    )
    if sev_word:
        alert.severity = V1_SEVERITY_MAP.get(sev_word.lower(), 6)
    else:
        alert.severity = 6  # medium baseline if the email omitted it

    # Score (0-100) — stash in the vendor-category slot for visibility + feed scoring.
    score = _first(r"\bScore:\s*(\d+)", text)
    if score:
        alert.event_category = f"V1 score {score}"
        try:
            alert.vendor_score = int(score)
        except (TypeError, ValueError):
            pass

    alert.timestamp = _parse_created(text)

    # Impact scope — first endpoint + first account (keep the account verbatim,
    # domain-prefixed: 'UNMAS_WG\furkan.akkaya').
    alert.hostname = _scope_value(text, "Endpoint") or _scope_value(text, "Endpoints")
    alert.username = _scope_value(text, "User accounts") or _scope_value(text, "User account")

    # First MITRE technique (email gives the id only — no tactic).
    tm = _TECHNIQUE_RE.search(text)
    if tm:
        alert.mitre_technique = tm.group(0)

    # First highlighted process command -> file_path (best-effort).
    cmd = _first(r"\(processCmd\)\s*\"?([^\"\n]+)\"?", text)
    if cmd:
        alert.file_path = cmd.strip().rstrip('"')

    # Labeled file hash (best-effort) — only slot a hex run preceded by a "*hash"
    # label, so a cert fingerprint / WB-id / guid is never mis-slotted. Prefer a
    # full sha256; fall back to a sha1. Lowercased.
    hm = _SHA256_TEXT_RE.search(text)
    if hm:
        alert.file_hash_sha256 = hm.group(1).lower()
    else:
        hm = _SHA1_TEXT_RE.search(text)
        if hm:
            alert.file_hash_sha1 = hm.group(1).lower()

    # Model name is the strongest semantic discriminator for the embedder.
    if model:
        alert.event_name = model

    return alert.finalize()
