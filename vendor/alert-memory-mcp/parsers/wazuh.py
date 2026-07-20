"""
Wazuh alert parser.

Handles two main sub-formats:
  1. Suricata/network alerts  (data.src_ip, data.alert.*)
  2. Windows EventChannel     (data.win.system.*, data.win.eventdata.*)

Both come wrapped in the same Wazuh envelope with rule / agent fields.
"""

import json
import re
from typing import Optional, Union
from normalizer import NormalizedAlert, infer_category


CVE_RE = re.compile(r'CVE[_-]\d{4}[_-]\d+', re.IGNORECASE)

# Sysmon 'Hashes' blob: "SHA1=...,MD5=...,SHA256=..." (order/subset varies).
_SYSMON_HASH_RE = re.compile(
    r'\b(SHA256|SHA1|MD5)\s*=\s*([0-9a-fA-F]{32,64})', re.IGNORECASE
)


def _normalize_cve(raw: str) -> str:
    """CVE_2024_4577 → CVE-2024-4577"""
    return raw.replace("_", "-").upper()


def _slot_hash(value: str) -> tuple[Optional[str], Optional[str]]:
    """Length-gate + lowercase a hex hash. Returns (sha256, sha1); never MD5."""
    if not value:
        return None, None
    v = value.strip().lower()
    if not re.fullmatch(r'[0-9a-f]+', v):
        return None, None
    if len(v) == 64:
        return v, None
    if len(v) == 40:
        return None, v
    return None, None


def _extract_hashes(eventdata: dict) -> tuple[Optional[str], Optional[str]]:
    """Pull file hashes from Wazuh Windows eventdata.

    Reads split keys (sha256/sha1/md5, case-insensitive) AND the Sysmon
    'hashes'/'hash' blob "SHA1=..,MD5=..,SHA256=..". Returns (sha256, sha1),
    length-gated + lowercased. MD5 is intentionally not surfaced.
    """
    if not isinstance(eventdata, dict):
        return None, None

    sha256: Optional[str] = None
    sha1: Optional[str] = None

    # Case-insensitive split-key lookup.
    lower = {k.lower(): v for k, v in eventdata.items() if isinstance(k, str)}
    s256, _ = _slot_hash(str(lower.get("sha256", "") or ""))
    if s256:
        sha256 = s256
    _, s1 = _slot_hash(str(lower.get("sha1", "") or ""))
    if s1:
        sha1 = s1

    # Sysmon combined blob ('Hashes' or 'Hash').
    blob = lower.get("hashes") or lower.get("hash") or ""
    if isinstance(blob, str):
        for algo, digest in _SYSMON_HASH_RE.findall(blob):
            a = algo.upper()
            d = digest.lower()
            if a == "SHA256" and not sha256 and len(d) == 64:
                sha256 = d
            elif a == "SHA1" and not sha1 and len(d) == 40:
                sha1 = d
            # MD5 deliberately dropped — no dataclass field for it.

    return sha256, sha1


def _extract_cve(data: dict) -> Optional[str]:
    # Suricata metadata path
    try:
        cves = data["alert"]["metadata"]["cve"]
        if cves:
            return _normalize_cve(cves[0])
    except (KeyError, IndexError, TypeError):
        pass

    # Fallback: scan signature string
    sig = data.get("alert", {}).get("signature", "")
    match = CVE_RE.search(sig)
    if match:
        return _normalize_cve(match.group(0))
    return None


def _parse_suricata(data: dict, alert: NormalizedAlert) -> NormalizedAlert:
    """Fill alert from Wazuh-wrapped Suricata event."""
    alert.src_ip = data.get("src_ip")
    alert.dst_ip = data.get("dest_ip")
    alert.dst_port = data.get("dest_port")
    alert.protocol = data.get("proto")

    suricata_alert = data.get("alert", {})
    alert.rule_name = suricata_alert.get("signature", alert.rule_name)
    alert.cve = _extract_cve(data)

    # MITRE from Suricata metadata
    meta = suricata_alert.get("metadata", {})
    tactics = meta.get("mitre_tactic_id", [])
    techniques = meta.get("mitre_technique_id", [])
    if tactics:
        alert.mitre_tactic = tactics[0]
    if techniques:
        alert.mitre_technique = techniques[0]

    # HTTP context
    http = data.get("http", {})
    if http:
        alert.hostname = http.get("hostname")

    return alert


def _parse_winevent(win: dict, alert: NormalizedAlert) -> NormalizedAlert:
    """Fill alert from Wazuh-wrapped Windows Security Event."""
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    alert.hostname = system.get("computer")

    # Username — prefer targetUserName, fall back to subjectUserName
    target_user = eventdata.get("targetUserName")
    subject_user = eventdata.get("subjectUserName")

    # Filter out machine accounts and NULL SIDs
    def is_real_user(u: Optional[str]) -> bool:
        if not u:
            return False
        if u.endswith("$"):         # machine account
            return False
        if u == "-":
            return False
        return True

    if is_real_user(target_user):
        alert.username = target_user
    elif is_real_user(subject_user):
        alert.username = subject_user

    # File hashes (Sysmon EventID 1/6/7/etc. carry a 'Hashes' blob; other
    # events may split them into sha256/sha1/md5 keys). Length-gated inside.
    sha256, sha1 = _extract_hashes(eventdata)
    if sha256:
        alert.file_hash_sha256 = sha256
    if sha1:
        alert.file_hash_sha1 = sha1

    # Network
    ip = eventdata.get("ipAddress")
    if ip and ip not in ("::1", "127.0.0.1", "-"):
        alert.src_ip = ip
    alert.dst_port = eventdata.get("logonType")  # not a port but useful context

    # Event-specific enrichment
    event_id = system.get("eventID")
    if event_id == "4625":
        status = eventdata.get("status", "")
        sub_status = eventdata.get("subStatus", "")
        alert.rule_name = (
            f"{alert.rule_name} | EventID:4625 "
            f"Status:{status} SubStatus:{sub_status}"
        )

    return alert


def _detect_wazuh_subtype(data: dict) -> str:
    """Detect whether the Wazuh alert data is Suricata, WinEvent, or other."""
    if "src_ip" in data and "alert" in data:
        return "suricata"
    if "win" in data:
        return "winevent"
    if "srcip" in data or "dstip" in data:
        return "generic_network"
    return "unknown"


_NOTIFICATION_HDR_RE = re.compile(r'Wazuh\s+Notification', re.IGNORECASE)
_NOTIFICATION_RULE_RE = re.compile(
    r'Rule:\s*(?P<id>\d+)\s*fired\s*\(level\s*(?P<level>\d+)\)\s*->\s*"(?P<desc>[^"]+)"',
    re.IGNORECASE,
)
# Handles both formats:
#   Received From: (hostname) ip        ← original ossec format
#   Received From: hostname->ip         ← newer Wazuh notification format
_NOTIFICATION_AGENT_RE = re.compile(
    r'Received\s+From:\s*'
    r'(?:'
        r'\((?P<host1>[^)]+)\)\s*(?P<ip1>[\d.]+)'   # (hostname) ip
        r'|'
        r'(?P<host2>\S+?)->(?P<ip2>[\d.]+)'          # hostname->ip
    r')',
    re.IGNORECASE,
)
_NOTIFICATION_TS_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+\-]\d{2}:?\d{2})?Z?)',
    re.MULTILINE,
)


_KV_SIMPLE_RE = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')
_FORTIGATE_BODY_RE = re.compile(r'Portion of the log\(s\):(.*?)(?:--END OF NOTIFICATION|$)', re.DOTALL | re.IGNORECASE)

# Vendor-owned reference domains — IPs/URLs pointing here are infrastructure
# noise (vendor knowledge-base links, signature references), not attacker IOCs.
_VENDOR_REF_DOMAINS = frozenset({
    "fortinet.com", "fortigate.com",
    "microsoft.com", "msdn.com",
    "mitre.org", "cve.org",
    "iana.org", "ripe.net",
    "symantec.com", "broadcom.com",
    "trendmicro.com",
})


def _is_vendor_ref_url(url: str) -> bool:
    try:
        host = url.split("//", 1)[1].split("/")[0].lower().lstrip("www.")
        return any(host == d or host.endswith("." + d) for d in _VENDOR_REF_DOMAINS)
    except (IndexError, AttributeError):
        return False


def _try_parse_fortigate_kv_body(raw: str, alert: NormalizedAlert) -> None:
    """Extract FortiGate key=value fields from the 'Portion of the log' section."""
    m = _FORTIGATE_BODY_RE.search(raw)
    if not m:
        return
    body = m.group(1).strip()

    # Must look like a FortiGate log (has srcip= or dstip= or logid=)
    if not re.search(r'\b(?:srcip|dstip|logid|devid)\s*=', body):
        return

    kv: dict[str, str] = {}
    for match in _KV_SIMPLE_RE.finditer(body):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        kv[key] = val

    # Network fields
    for field in ("srcip", "remip", "clientip"):
        if v := kv.get(field):
            alert.src_ip = v
            break
    for field in ("dstip", "destip"):
        if v := kv.get(field):
            alert.dst_ip = v
            break
    for field in ("dstport", "destport"):
        if v := kv.get(field, "").strip():
            if v.isdigit():
                alert.dst_port = int(v)
            break

    alert.protocol = kv.get("proto") or alert.protocol
    alert.action   = kv.get("action") or alert.action

    # File hashes from an embedded FortiGate AV/UTM line (length-gated; the
    # 8-hex 'checksum' CRC is never slotted as a real hash by _slot_hash).
    for field in ("filehash", "filehashsrc", "checksum", "hash"):
        v = kv.get(field, "")
        if not v or v in ("-", "N/A"):
            continue
        s256, s1 = _slot_hash(v)
        if s256 and not alert.file_hash_sha256:
            alert.file_hash_sha256 = s256
        elif s1 and not alert.file_hash_sha1:
            alert.file_hash_sha1 = s1

    # Target domain + URL path → reconstruct full URL as an IOC
    target_host = kv.get("hostname")
    url_path    = kv.get("url")
    service     = kv.get("service", "").upper()
    if target_host and not _is_vendor_ref_url(f"https://{target_host}/"):
        scheme = "https" if service in ("HTTPS", "443") or (alert.dst_port or 443) == 443 else "http"
        if url_path:
            alert.url = f"{scheme}://{target_host}{url_path}"
        else:
            alert.url = f"{scheme}://{target_host}"

    # CVE in attack/msg fields
    for field in ("attack", "msg", "cve"):
        if v := kv.get(field, ""):
            match = CVE_RE.search(v)
            if match:
                alert.cve = _normalize_cve(match.group(0))
                break

    # IPS attack name → use as extra rule context if not already set
    if attack := kv.get("attack"):
        if alert.rule_name and attack.lower() not in alert.rule_name.lower():
            alert.rule_name = f"{alert.rule_name} | {attack}"


def _parse_notification_text(raw: str, customer: str | None) -> NormalizedAlert:
    """Parse the ossec-monitord email notification format:
        Wazuh Notification.
        <ISO timestamp>

        Received From: (<host>) <ip>-><source>
        Rule: <id> fired (level <N>) -> "<description>"
        Portion of the log(s):

        <embedded JSON line>

         --END OF NOTIFICATION
    """
    alert = NormalizedAlert()
    alert.source_product = "wazuh"
    alert.customer = customer
    alert.raw = raw

    # Header fields
    if m := _NOTIFICATION_TS_RE.search(raw):
        alert.timestamp = m.group("ts")
    if m := _NOTIFICATION_RULE_RE.search(raw):
        alert.rule_id   = m.group("id")
        alert.rule_name = m.group("desc").strip()
        try:
            alert.severity = int(m.group("level"))
        except (ValueError, TypeError):
            pass
    if m := _NOTIFICATION_AGENT_RE.search(raw):
        host = m.group("host1") or m.group("host2") or ""
        ip   = m.group("ip1")   or m.group("ip2")   or ""
        alert.hostname = host.strip() or None
        alert.agent_ip = ip.strip()   or None

    # Try to extract the embedded JSON object (greedy from first '{' to last '}')
    start = raw.find("{")
    end   = raw.rfind("}")
    embedded = None
    if start != -1 and end > start:
        snippet = raw[start:end + 1]
        try:
            embedded = json.loads(snippet)
        except json.JSONDecodeError:
            embedded = None
        if isinstance(embedded, dict):
            # Wazuh winevent embedded format: {"win": {...}}
            if "win" in embedded:
                alert = _parse_winevent(embedded["win"], alert)
            # Generic Wazuh data envelope possible too
            elif "data" in embedded and isinstance(embedded["data"], dict):
                data = embedded["data"]
                sub = _detect_wazuh_subtype(data)
                if sub == "suricata":   alert = _parse_suricata(data, alert)
                elif sub == "winevent": alert = _parse_winevent(data.get("win", {}), alert)

    # If no JSON was found/parsed, try FortiGate key=value format embedded in
    # the "Portion of the log(s):" section.
    if embedded is None:
        _try_parse_fortigate_kv_body(raw, alert)

    # Category inference
    combined = f"{alert.rule_name or ''} {alert.cve or ''} {alert.mitre_tactic or ''}"
    alert.threat_category = infer_category(combined)
    return alert.finalize()


def parse(raw: Union[str, dict], customer: str = None) -> NormalizedAlert:
    # Email-notification text format — different shape, no top-level JSON envelope.
    if isinstance(raw, str) and _NOTIFICATION_HDR_RE.search(raw):
        return _parse_notification_text(raw, customer)

    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("Wazuh parser: input must be valid JSON or notification text")
    else:
        payload = raw

    alert = NormalizedAlert()
    alert.source_product = "wazuh"
    alert.customer = customer
    alert.raw = json.dumps(payload) if isinstance(payload, dict) else raw

    # --- Wazuh envelope ---
    alert.timestamp = payload.get("timestamp")

    rule = payload.get("rule", {})
    alert.rule_id = rule.get("id")
    alert.rule_name = rule.get("description")
    alert.severity = int(rule.get("level", 0))

    mitre = rule.get("mitre", {})
    mitre_ids = mitre.get("id", [])
    mitre_tactics = mitre.get("tactic", [])
    if mitre_ids:
        alert.mitre_technique = mitre_ids[0]
    if mitre_tactics:
        alert.mitre_tactic = mitre_tactics[0]

    agent = payload.get("agent", {})
    alert.agent_ip = agent.get("ip")
    if not alert.hostname:
        alert.hostname = agent.get("name")

    # --- Sub-format routing ---
    data = payload.get("data", {})
    subtype = _detect_wazuh_subtype(data)

    if subtype == "suricata":
        alert = _parse_suricata(data, alert)
    elif subtype == "winevent":
        alert = _parse_winevent(data.get("win", {}), alert)

    # Infer category from combined text
    combined = f"{alert.rule_name or ''} {alert.cve or ''} {alert.mitre_tactic or ''}"
    alert.threat_category = infer_category(combined)

    return alert.finalize()
