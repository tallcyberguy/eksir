"""SentinelOne threat parser (v2.1 API JSON).

Maps a SentinelOne threat object (from GET /web/api/v2.1/threats) to a
NormalizedAlert. Defensive by design: every field is optional and a missing or
garbled section is left None; the parser never raises.

Threat shape (nested): threatInfo{threatName, classification, confidenceLevel,
sha1/sha256, filePath, processUser, createdAt}, agentRealtimeInfo{
agentComputerName, agentOsName}, agentDetectionInfo{agentIpV4,
agentLastLoggedInUserName}, indicators[].tactics[].techniques[].name.
"""

import json
import re

from normalizer import NormalizedAlert

# SentinelOne confidenceLevel -> Wazuh-style 1-15 int so finalize() derives the
# shared severity_label (low/medium/high/critical) consistently with other products.
_S1_CONFIDENCE_SEVERITY = {
    "malicious": 10,
    "suspicious": 6,
    "n/a": 3,
}

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def severity_word(threat: dict) -> str | None:
    """The raw severity band ('high'/'medium'/…) for the ingest min-severity floor."""
    info = threat.get("threatInfo") or {}
    conf = str(info.get("confidenceLevel") or "").lower()
    if conf == "malicious":
        return "high"
    if conf == "suspicious":
        return "medium"
    return None


def _first_technique(raw_json: str) -> str | None:
    m = _TECHNIQUE_RE.search(raw_json)
    return m.group(0) if m else None


def parse(raw, customer: str = None) -> NormalizedAlert:
    data = raw if isinstance(raw, dict) else {}
    info = data.get("threatInfo") or {}
    agent = data.get("agentRealtimeInfo") or {}
    detect = data.get("agentDetectionInfo") or {}

    alert = NormalizedAlert()
    alert.source_product = "sentinelone"
    alert.customer = customer
    alert.raw = json.dumps(data, ensure_ascii=False, default=str)

    threat_id = data.get("id")
    if threat_id:
        alert.rule_id = str(threat_id)

    name = info.get("threatName") or info.get("classification")
    if name:
        alert.rule_name = str(name)
        alert.event_name = str(name)

    conf = str(info.get("confidenceLevel") or "").lower()
    alert.severity = _S1_CONFIDENCE_SEVERITY.get(conf, 3)

    classification = info.get("classification")
    if classification:
        alert.threat_category = str(classification)
        alert.event_category = f"S1 {classification}"

    alert.timestamp = info.get("createdAt") or info.get("identifiedAt")

    alert.hostname = agent.get("agentComputerName") or detect.get("agentComputerNameAtIngest")
    alert.username = info.get("processUser") or detect.get("agentLastLoggedInUserName")
    alert.src_ip = detect.get("agentIpV4") or detect.get("externalIp")

    sha256 = info.get("sha256")
    sha1 = info.get("sha1")
    if sha256 and _SHA256_RE.match(str(sha256)):
        alert.file_hash_sha256 = str(sha256).lower()
    if sha1 and _SHA1_RE.match(str(sha1)):
        alert.file_hash_sha1 = str(sha1).lower()

    file_path = info.get("filePath")
    if file_path:
        alert.file_path = str(file_path)

    tech = _first_technique(alert.raw)
    if tech:
        alert.mitre_technique = tech

    return alert.finalize()
