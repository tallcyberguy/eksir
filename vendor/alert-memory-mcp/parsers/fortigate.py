"""
FortiGate log parser.

Handles FortiOS key=value log format:
    logver=704092829 timestamp=1776884496 devname=FW-IZM-Master devid=FG9H0... \
    type=event subtype=vpn level=information logdesc="SSL VPN tunnel up" \
    action=tunnel-up remip=1.2.3.4 user=someone@corp.com ...

Supported subtypes: vpn, system, iam, traffic, utm, webfilter, antivirus, ips
"""

import re
import shlex
from datetime import datetime, timezone
from typing import Optional, Union
from normalizer import NormalizedAlert, infer_category


# FortiGate severity level → 1-15 scale
LEVEL_MAP = {
    "emergency":    15,
    "alert":        13,
    "critical":     12,
    "error":        10,
    "warning":      7,
    "notification": 5,
    "information":  3,
    "debug":        1,
}

# type+subtype combos → MITRE-ish category hints
SUBTYPE_CATEGORY_MAP = {
    "vpn":        "lateral",
    "ips":        "exploit",
    "webfilter":  "recon",
    "antivirus":  "malware",
    "dlp":        "unknown",
    "app-ctrl":   "unknown",
    "dns":        "recon",
    "anomaly":    "exploit",
}

CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
TECHNIQUE_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')


def _parse_kv(raw: str) -> dict:
    """
    Parse FortiGate key=value log line into a dict.
    Handles quoted values: key="value with spaces"
    """
    result = {}
    # Use shlex to respect quoted strings
    try:
        tokens = shlex.split(raw)
    except ValueError:
        # Fallback: simple split on space, may lose quoted values
        tokens = raw.split()

    for token in tokens:
        if "=" in token:
            key, _, value = token.partition("=")
            result[key.strip()] = value.strip()
    return result


def _build_timestamp(kv: dict) -> Optional[str]:
    """
    Try to build an ISO timestamp from FortiGate log fields.
    Prefers date+time, falls back to epoch timestamp field.
    """
    date_str = kv.get("date")
    time_str = kv.get("time")
    if date_str and time_str:
        try:
            dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            pass

    epoch = kv.get("timestamp")
    if epoch and epoch.isdigit():
        try:
            dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OSError):
            pass

    return None


def _infer_rule_name(kv: dict) -> str:
    """
    Construct a descriptive rule name from FortiGate fields.
    Priority: logdesc > action+subtype > type+subtype
    """
    logdesc = kv.get("logdesc", "").strip()
    action  = kv.get("action", "").strip()
    subtype = kv.get("subtype", "").strip()
    fgtype  = kv.get("type", "").strip()

    if logdesc:
        if action and action.lower() not in logdesc.lower():
            return f"{logdesc} ({action})"
        return logdesc

    if action and subtype:
        return f"FortiGate {subtype} {action}"

    if fgtype and subtype:
        return f"FortiGate {fgtype}/{subtype}"

    return "FortiGate alert"


def _extract_src_ip(kv: dict) -> Optional[str]:
    """FortiGate uses different src IP field names by log type."""
    for field in ("srcip", "remip", "src_ip", "clientip", "sourceip"):
        val = kv.get(field)
        if val and val not in ("-", "N/A", "0.0.0.0"):
            return val
    return None


def _extract_dst_ip(kv: dict) -> Optional[str]:
    for field in ("dstip", "dst_ip", "tunnelip", "destip"):
        val = kv.get(field)
        if val and val not in ("-", "N/A", "0.0.0.0"):
            return val
    return None


def _extract_dst_port(kv: dict) -> Optional[int]:
    for field in ("dstport", "dst_port", "destport"):
        val = kv.get(field)
        if val and val.isdigit():
            return int(val)
    return None


def _extract_username(kv: dict) -> Optional[str]:
    for field in ("user", "unauthuser", "srcuser", "username"):
        val = kv.get(field)
        if val and val not in ("-", "N/A"):
            return val
    return None


def _extract_hostname(kv: dict) -> Optional[str]:
    for field in ("devname", "hostname", "srcname"):
        val = kv.get(field)
        if val and val not in ("-", "N/A"):
            return val
    return None


_SHA256_FULL_RE = re.compile(r'^[0-9a-fA-F]{64}$')
_SHA1_FULL_RE = re.compile(r'^[0-9a-fA-F]{40}$')


def _extract_file_hash(kv: dict) -> tuple[Optional[str], Optional[str]]:
    """Return (sha256, sha1) from FortiGate AV/UTM hash fields.

    Classifies strictly by length (64 = sha256, 40 = sha1) and lowercases.
    A short CRC like the 8-hex 'checksum' is never slotted as a real hash.
    """
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    for field in ("filehash", "filehashsrc", "checksum", "hash"):
        val = kv.get(field)
        if not val or val in ("-", "N/A"):
            continue
        v = val.strip().lower()
        if not sha256 and _SHA256_FULL_RE.fullmatch(v):
            sha256 = v
        elif not sha1 and _SHA1_FULL_RE.fullmatch(v):
            sha1 = v
    return sha256, sha1


def _extract_cve(kv: dict) -> Optional[str]:
    # IPS alerts sometimes put CVE in 'cve' or 'attack' fields
    for field in ("cve", "attack", "logdesc", "msg"):
        val = kv.get(field, "")
        match = CVE_RE.search(val)
        if match:
            return match.group(0).upper()
    return None


def _extract_mitre(kv: dict) -> tuple[Optional[str], Optional[str]]:
    """Return (tactic, technique) if present in IPS/UTM metadata."""
    for field in ("attack", "logdesc", "msg", "cve"):
        val = kv.get(field, "")
        match = TECHNIQUE_RE.search(val)
        if match:
            return None, match.group(1)
    return None, None


def parse(raw: Union[str, dict], customer: str = None) -> NormalizedAlert:
    """
    Parse a FortiGate key=value log line into NormalizedAlert.

    Args:
        raw:      Log line as string, or pre-parsed dict, or an envelope dict
                  with a 'raw_alert' key containing the actual log line.
        customer: Customer identifier.
    """
    # Accept envelope dict (e.g. from pending_index.jsonl)
    if isinstance(raw, dict) and "raw_alert" in raw:
        kv = _parse_kv(raw["raw_alert"])
        # Prefer envelope-level metadata when richer than log fields
        envelope = raw
    elif isinstance(raw, dict):
        kv = raw
        envelope = {}
    else:
        kv = _parse_kv(raw)
        envelope = {}

    alert = NormalizedAlert()
    alert.source_product = "fortigate"
    alert.customer = customer or envelope.get("customer")
    alert.raw = raw if isinstance(raw, str) else str(raw)

    alert.timestamp = _build_timestamp(kv) or envelope.get("timestamp")

    alert.rule_name = (
        envelope.get("rule_name")
        or _infer_rule_name(kv)
    )

    level_str = kv.get("level", "information").lower()
    alert.severity = LEVEL_MAP.get(level_str, 3)

    alert.src_ip = envelope.get("src_ip") or _extract_src_ip(kv)
    alert.dst_ip = _extract_dst_ip(kv)
    alert.dst_port = _extract_dst_port(kv)
    alert.protocol = kv.get("proto") or kv.get("tunneltype")

    alert.username = envelope.get("user") or _extract_username(kv)
    alert.hostname = _extract_hostname(kv)
    alert.agent_ip = kv.get("tunnelip") or kv.get("srcip")

    alert.cve = _extract_cve(kv)
    alert.file_hash_sha256, alert.file_hash_sha1 = _extract_file_hash(kv)
    alert.mitre_tactic, alert.mitre_technique = _extract_mitre(kv)

    subtype = kv.get("subtype", "")
    category_hint = SUBTYPE_CATEGORY_MAP.get(subtype, "unknown")
    combined = f"{alert.rule_name or ''} {subtype} {alert.cve or ''}"
    inferred = infer_category(combined)
    alert.threat_category = inferred if inferred != "unknown" else category_hint

    return alert.finalize()
