"""Microsoft 365 Defender alert parser (Graph Security alerts_v2 JSON).

Maps a Graph Security alert (from GET /security/alerts_v2) to a NormalizedAlert. Defensive by
design: every field is optional and a missing/garbled section is left None; the parser never
raises. Host/IP/user/file/URL/process are pulled from the polymorphic ``evidence[]`` array.

Field paths verified against the public Graph Security v1.0 ``alert`` + ``alertEvidence`` schema
(learn.microsoft.com, 2026-07). Alert shape: {id, title, severity, categories[], createdDateTime,
description, mitreTechniques[], evidence[{@odata.type, deviceEvidence{deviceDnsName, hostName},
ipEvidence{ipAddress}, userEvidence{userAccount{accountName,userPrincipalName}},
fileEvidence{fileDetails{sha256,sha1,filePath,fileName}}, processEvidence{imageFile{...},
processCommandLine, userAccount}, urlEvidence{url}}]}.
"""

import json
import re

from normalizer import NormalizedAlert

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# Graph severity word -> Wazuh-style 1-15 int (finalize derives the shared label).
_SEVERITY = {"high": 10, "medium": 6, "low": 3, "informational": 1, "unknown": 3}


def _severity(alert: dict) -> int:
    return _SEVERITY.get(str(alert.get("severity") or "").lower(), 3)


def _evidence_type(ev: dict) -> str:
    return str(ev.get("@odata.type") or "").lower()


def _take_hashes_and_path(alert: NormalizedAlert, details: dict) -> None:
    """Fill file hash/path from a fileDetails-shaped object (first occurrence wins)."""
    sha256 = details.get("sha256")
    sha1 = details.get("sha1")
    if sha256 and _SHA256_RE.match(str(sha256)) and not alert.file_hash_sha256:
        alert.file_hash_sha256 = str(sha256).lower()
    if sha1 and _SHA1_RE.match(str(sha1)) and not alert.file_hash_sha1:
        alert.file_hash_sha1 = str(sha1).lower()
    if not alert.file_path:
        alert.file_path = details.get("filePath") or details.get("fileName")


def parse(raw, customer: str = None) -> NormalizedAlert:
    data = raw if isinstance(raw, dict) else {}
    evidence = data.get("evidence") if isinstance(data.get("evidence"), list) else []

    alert = NormalizedAlert()
    alert.source_product = "microsoft_defender"
    alert.customer = customer
    alert.raw = json.dumps(data, ensure_ascii=False, default=str)

    if data.get("id"):
        alert.rule_id = str(data.get("id"))

    title = data.get("title")
    if title:
        alert.rule_name = str(title)
        alert.event_name = str(title)
    if data.get("description"):
        alert.event_description = str(data.get("description"))
    # `categories` (String collection) is the current field; `category` is deprecated but still
    # populated on live alerts, so keep it as a fallback.
    categories = data.get("categories")
    category = (
        categories[0] if isinstance(categories, list) and categories else None
    ) or data.get("category")
    if category:
        alert.threat_category = str(category)

    alert.severity = _severity(data)
    alert.timestamp = data.get("createdDateTime")

    # Walk the polymorphic evidence array; first occurrence of each wins.
    process_cmds: list[str] = []
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        etype = _evidence_type(ev)
        if "deviceevidence" in etype and not alert.hostname:
            alert.hostname = ev.get("deviceDnsName") or ev.get("hostName")
        elif "ipevidence" in etype and not alert.src_ip:
            alert.src_ip = ev.get("ipAddress")
        elif "userevidence" in etype and not alert.username:
            acct = ev.get("userAccount") or {}
            alert.username = acct.get("accountName") or acct.get("userPrincipalName")
        elif "fileevidence" in etype:
            _take_hashes_and_path(alert, ev.get("fileDetails") or {})
        elif "processevidence" in etype:
            # The primary executable hash + command line often live here, not in fileEvidence.
            _take_hashes_and_path(alert, ev.get("imageFile") or {})
            if ev.get("processCommandLine"):
                process_cmds.append(str(ev["processCommandLine"])[:500])
            if not alert.username:
                acct = ev.get("userAccount") or {}
                alert.username = acct.get("accountName") or acct.get("userPrincipalName")
        elif "urlevidence" in etype and not alert.url:
            alert.url = ev.get("url")

    if process_cmds:
        base = (alert.event_description or "").rstrip()
        cmds = "\n".join(f"cmdline: {c}" for c in process_cmds[:3])
        alert.event_description = (base + "\n" + cmds).strip()

    techniques = data.get("mitreTechniques")
    if isinstance(techniques, list):
        for t in techniques:
            if _TECHNIQUE_RE.match(str(t)):
                alert.mitre_technique = str(t)
                break
    if not alert.mitre_technique:
        m = _TECHNIQUE_RE.search(alert.raw)
        if m:
            alert.mitre_technique = m.group(0)

    return alert.finalize()
