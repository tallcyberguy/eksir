"""CrowdStrike Falcon alert parser (Alerts API v2 JSON).

Maps a Falcon alert object (from POST /alerts/entities/alerts/v2) to a NormalizedAlert.
Defensive by design: every field is optional and a missing/garbled section is left None; the
parser never raises.

Field paths verified against the public Falcon Alerts v2 schema (FalconPy wiki + CrowdStrike
developer docs, 2026-07). Alert shape: {composite_id, created_timestamp, severity (0-100),
severity_name, tactic, tactic_id, technique, technique_id, objective, display_name, description,
cmdline, parent_details{cmdline,filename,sha256}, device{hostname, external_ip, local_ip,
user_name}, user_name, sha256, sha1, filename, filepath}.
"""

import json
import re

from normalizer import NormalizedAlert

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TACTIC_RE = re.compile(r"^TA\d{4}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# CrowdStrike severity (word or 0-100) -> Wazuh-style 1-15 int so finalize() derives the shared
# severity_label (low/medium/high/critical). Int bands match CrowdStrike's documented 0-100 scale
# (Critical >=80, High 60-79, Medium 40-59, Low/Info below).
_NAME_SEVERITY = {"critical": 14, "high": 10, "medium": 6, "low": 3, "informational": 1}


def _severity(alert: dict) -> int:
    name = str(alert.get("severity_name") or "").lower()
    if name in _NAME_SEVERITY:
        return _NAME_SEVERITY[name]
    sev = alert.get("severity")
    if isinstance(sev, (int, float)):
        if sev >= 80:
            return 14
        if sev >= 60:
            return 10
        if sev >= 40:
            return 6
        return 3
    return 3


def parse(raw, customer: str = None) -> NormalizedAlert:
    data = raw if isinstance(raw, dict) else {}
    device = data.get("device") or {}

    alert = NormalizedAlert()
    alert.source_product = "crowdstrike"
    alert.customer = customer
    alert.raw = json.dumps(data, ensure_ascii=False, default=str)

    cid = data.get("composite_id") or data.get("id")
    if cid:
        alert.rule_id = str(cid)

    name = data.get("display_name") or data.get("description")
    if name:
        alert.rule_name = str(name)
        alert.event_name = str(name)
    if data.get("description"):
        alert.event_description = str(data.get("description"))

    alert.severity = _severity(data)

    category = data.get("tactic") or data.get("technique")
    if category:
        alert.threat_category = str(category)
    # 'objective' (e.g. 'Falcon Detection Method') is CrowdStrike's own category label.
    objective = data.get("objective")
    if objective:
        alert.event_category = str(objective)

    alert.timestamp = data.get("created_timestamp") or data.get("timestamp")

    alert.hostname = device.get("hostname")
    alert.username = data.get("user_name") or device.get("user_name")
    alert.src_ip = device.get("external_ip") or device.get("local_ip")

    sha256 = data.get("sha256")
    if sha256 and _SHA256_RE.match(str(sha256)):
        alert.file_hash_sha256 = str(sha256).lower()
    sha1 = data.get("sha1")
    if sha1 and _SHA1_RE.match(str(sha1)):
        alert.file_hash_sha1 = str(sha1).lower()

    file_path = data.get("filepath") or data.get("filename")
    if file_path:
        alert.file_path = str(file_path)

    tech_id = data.get("technique_id")
    if tech_id and _TECHNIQUE_RE.match(str(tech_id)):
        alert.mitre_technique = str(tech_id)
    else:
        m = _TECHNIQUE_RE.search(alert.raw)
        if m:
            alert.mitre_technique = m.group(0)
    tactic_id = data.get("tactic_id")
    if tactic_id and _TACTIC_RE.match(str(tactic_id)):
        alert.mitre_tactic = str(tactic_id)

    # Fold decision-relevant process context into the description (no dedicated NormalizedAlert
    # field for command lines / parent process).
    extra: list[str] = []
    if data.get("cmdline"):
        extra.append(f"cmdline: {str(data['cmdline'])[:500]}")
    parent = data.get("parent_details") or {}
    if isinstance(parent, dict) and parent.get("cmdline"):
        extra.append(f"parent cmdline: {str(parent['cmdline'])[:500]}")
    if extra:
        base = (alert.event_description or "").rstrip()
        alert.event_description = (base + "\n" + "\n".join(extra)).strip()

    return alert.finalize()
