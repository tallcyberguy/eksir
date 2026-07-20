"""
QRadar email notification parser.

Expected format:
    Rule Name:       ...
    Source IP:       ...
    Destination IP:  ...
    Payload:         ...
"""

import re
from datetime import datetime
from typing import Optional
from normalizer import NormalizedAlert, infer_category


# QRadar severity is not always in the email — map by keyword heuristics
QRADAR_SEVERITY_MAP = {
    "critical": 14,
    "high":     10,
    "medium":   6,
    "low":      3,
}

# MITRE tactic tags sometimes embedded in rule names like [TA0007]
TACTIC_ID_RE = re.compile(r'\[TA\d{4}\]')
TECHNIQUE_ID_RE = re.compile(r'\[T\d{4}(?:\.\d{3})?\]')
CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
SHA256_FULL_RE = re.compile(r'^[0-9a-fA-F]{64}$')
SHA1_FULL_RE = re.compile(r'^[0-9a-fA-F]{40}$')
# Free-text hash fallbacks — anchored to a "*hash" label (fileHash, sha256Hash,
# objectHash, hash) so a bare cert fingerprint / session id / correlation id in
# the payload is never mis-slotted as a file hash. The hex is captured in group(1).
SHA256_TEXT_RE = re.compile(r'(?i)[a-z0-9_]*hash\b[^0-9a-f]{0,20}([0-9a-fA-F]{64})\b')
SHA1_TEXT_RE = re.compile(r'(?i)[a-z0-9_]*hash\b[^0-9a-f]{0,20}([0-9a-fA-F]{40})\b')


def _extract_field(text: str, field_name: str) -> Optional[str]:
    """Extract value after 'Field Name:' allowing variable whitespace."""
    pattern = rf'{re.escape(field_name)}\s*:\s*(.+)'
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        value = match.group(1).strip()
        return value if value and value.upper() != 'N/A' else None
    return None


def _extract_mitre_tactic(rule_name: str) -> Optional[str]:
    match = TACTIC_ID_RE.search(rule_name)
    if match:
        return match.group(0).strip("[]")
    return None


def _extract_mitre_technique(rule_name: str) -> Optional[str]:
    match = TECHNIQUE_ID_RE.search(rule_name)
    if match:
        return match.group(0).strip("[]")
    return None


def _extract_cve(text: str) -> Optional[str]:
    match = CVE_RE.search(text)
    return match.group(0).upper() if match else None


def _infer_severity(rule_name: str, category: str) -> int:
    """
    QRadar email doesn't always include numeric severity.
    Infer from rule name keywords and category.
    """
    combined = f"{rule_name} {category}".lower()
    for label, value in QRADAR_SEVERITY_MAP.items():
        if label in combined:
            return value
    # Default: medium-high for alerted rules
    return 8


def _parse_timestamp(text: str) -> Optional[str]:
    """Try to extract timestamp from QRadar email header."""
    # e.g. "Apr 22, 2026 5:52:06 PM TRT"
    pattern = r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M'
    match = re.search(pattern, text)
    if match:
        try:
            dt = datetime.strptime(match.group(0), "%b %d, %Y %I:%M:%S %p")
            return dt.isoformat()
        except ValueError:
            return match.group(0)
    return None


def parse(raw_text: str, customer: str = None) -> NormalizedAlert:
    alert = NormalizedAlert()
    alert.source_product = "qradar"
    alert.customer = customer
    alert.raw = raw_text

    # Timestamp
    alert.timestamp = _parse_timestamp(raw_text)

    # Rule fields
    rule_name = _extract_field(raw_text, "Rule Name")
    alert.rule_name = rule_name
    alert.rule_id = _extract_field(raw_text, "QID")

    # Network
    alert.src_ip = _extract_field(raw_text, "Source IP")
    alert.dst_ip = _extract_field(raw_text, "Destination IP")
    dst_port_str = _extract_field(raw_text, "Destination Port")
    if dst_port_str and dst_port_str.isdigit():
        alert.dst_port = int(dst_port_str)

    protocol_raw = _extract_field(raw_text, "Protocol")
    if protocol_raw:
        # "other(255)" → "other"
        alert.protocol = protocol_raw.split("(")[0].strip()

    # Identity
    src_user = _extract_field(raw_text, "Source Username (from event)")
    # SID is not a username — skip if it looks like a SID
    if src_user and not src_user.startswith("S-1-"):
        alert.username = src_user

    log_source = _extract_field(raw_text, "Log Source Name")
    if log_source:
        # "WEBSRV02 @ 10.0.2.226" → hostname
        alert.hostname = log_source.split("@")[0].strip()
        # agent_ip from log source IP if present
        parts = log_source.split("@")
        if len(parts) > 1:
            alert.agent_ip = parts[1].strip()

    # Threat intel from rule name
    if rule_name:
        alert.mitre_tactic = _extract_mitre_tactic(rule_name)
        alert.mitre_technique = _extract_mitre_technique(rule_name)
        alert.cve = _extract_cve(rule_name)

    # Also check payload for CVE if not found in rule name
    payload = _extract_field(raw_text, "Payload")
    if payload and not alert.cve:
        alert.cve = _extract_cve(payload)

    # ── LEEF payload extraction (Palo Alto / Forcepoint / etc.) ─────────
    # The vendor payload after "Payload:" is a pipe-delimited LEEF record
    # with key=value pairs. Pull network zones, app-id, http context, action.
    if payload:
        leef = _parse_leef_fields(payload)
        # Case-insensitive lookup helper
        def L(name: str) -> Optional[str]:
            for k, v in leef.items():
                if k.lower() == name.lower():
                    return v
            return None

        # Application (PAN-OS App-ID, Forcepoint application, …)
        app = L("Application") or L("application") or L("app")
        if app and app.lower() not in ("", "not-applicable"):
            alert.application = app
        elif app and app.lower() == "not-applicable":
            alert.application = "not-applicable"   # explicit signal: parser saw it

        # Zones
        alert.src_zone = L("SourceZone") or L("srcZone") or L("src_zone")
        alert.dst_zone = L("DestinationZone") or L("dstZone") or L("dst_zone")

        # Firewall action (allow / deny / drop / alert)
        act = L("action") or L("Action")
        if act:
            alert.action = act.lower()

        # URL category (PAN-OS URLCategory, Forcepoint cat)
        alert.url_category = L("URLCategory") or L("urlcategory") or L("url_category")

        # HTTP context (Forcepoint, Wazuh-via-QRadar, etc.)
        url = L("url") or L("URL") or L("request") or L("Request")
        if url:
            alert.url = url
        meth = L("httpMethod") or L("method") or L("requestMethod")
        if meth:
            alert.http_method = meth.upper()
        status_raw = L("httpResponseCode") or L("status") or L("responseCode")
        if status_raw and status_raw.isdigit():
            alert.http_status = int(status_raw)
        ua = L("userAgent") or L("user-agent") or L("ua")
        if ua:
            alert.user_agent = ua

        # File hashes (LEEF keyed) — length-gated fullmatch so a short field
        # value can never be mis-slotted as a real hash.
        h256 = L("sha256Hash") or L("sha256") or L("SHA256")
        if h256 and SHA256_FULL_RE.fullmatch(h256.strip()):
            alert.file_hash_sha256 = h256.strip().lower()
        h1 = L("sha1Hash") or L("sha1") or L("SHA1")
        if h1 and SHA1_FULL_RE.fullmatch(h1.strip()):
            alert.file_hash_sha1 = h1.strip().lower()

        # Sometimes the firewall rule name in the LEEF body is more specific
        # than the QRadar rule name (e.g. INTERNAL_TO_WAN_TREATH_IP).
        # Keep both: prepend in raw, leave alert.rule_name as the QRadar one.

    # Severity and category
    category = _extract_field(raw_text, "Category") or ""
    event_name = _extract_field(raw_text, "Event Name") or ""
    event_description = _extract_field(raw_text, "Event Description") or ""
    alert.severity = _infer_severity(rule_name or "", category)
    alert.threat_category = infer_category(
        f"{rule_name or ''} {category} {event_name}"
    )

    # Preserve the event-level content on the alert (Phase-RAG-B). These
    # carry the strongest discriminative signal for the embedder when many
    # rules share the same rule_name template.
    if event_name:
        alert.event_name = event_name
    if event_description:
        alert.event_description = event_description
    if category:
        alert.event_category = category

    # ── W3C IIS log fields embedded in QRadar Payload ──────────────────
    # When QRadar wraps an IIS event the LEEF body is actually W3C key=value
    # space-separated (cs-uri-stem, cs-host, sc-status, …). LEEF parser
    # missed these. Pull the strongest discriminators if present.
    if payload and not alert.url:
        w3c = _parse_w3c_iis_fields(payload)
        host = w3c.get("cs-host")
        stem = w3c.get("cs-uri-stem")
        if host or stem:
            # Reconstruct a representative URL for embed_text.
            url_bits = []
            if host:
                url_bits.append(f"https://{host}")
            if stem:
                url_bits.append(stem if stem.startswith("/") else "/" + stem)
            if url_bits:
                alert.url = "".join(url_bits)
        if w3c.get("cs-method") and not alert.http_method:
            alert.http_method = w3c["cs-method"].upper()
        if w3c.get("sc-status") and w3c["sc-status"].isdigit() and not alert.http_status:
            alert.http_status = int(w3c["sc-status"])
        if w3c.get("cs(User-Agent)") and not alert.user_agent:
            alert.user_agent = w3c["cs(User-Agent)"].replace("+", " ")

    # ── Microsoft Exchange message-tracking (MSGTRK) inside QRadar Payload ──
    # QRadar maps Exchange recipients into "Source Username (from event)", which
    # makes sender/recipient look swapped. Parse the native Exchange KV fields
    # so sender/recipient/subject/origin-IP are labeled correctly.
    if payload and ("AgentDevice=MicrosoftExchange" in payload or "AgentLogFormat=MSGTRK" in payload):
        ex = _parse_exchange_msgtrk(payload)
        sender = ex.get("sender-address") or ex.get("return-path")
        recipient = ex.get("recipient-address")
        subject = ex.get("message-subject")
        origin_ip = ex.get("original-client-ip") or ex.get("client-ip")

        if sender:
            alert.sender = sender
            # The rule concerns the SENDER; QRadar's Source Username holds the
            # recipient list, so override it with the true sender.
            alert.username = sender
        if recipient:
            alert.recipient = recipient
        if subject:
            alert.subject = subject
            # Fold the subject into event_description so it reaches the embedder.
            if alert.event_description:
                alert.event_description = f"Subject: {subject} | {alert.event_description}"
            else:
                alert.event_description = f"Subject: {subject}"
        if origin_ip:
            # original-client-ip is the true originating host (vs the Exchange
            # server IP QRadar put in Source/Destination IP).
            alert.src_ip = origin_ip

    # Payload free-text hash fallback — only when the keyed LEEF value was
    # absent (mirrors the CVE-from-payload fallback above). The regex requires a
    # "*hash" label before the hex, so a cert fingerprint / session id in the
    # payload is not mis-slotted as a file hash.
    if payload:
        if not alert.file_hash_sha256:
            m = SHA256_TEXT_RE.search(payload)
            if m:
                alert.file_hash_sha256 = m.group(1).lower()
        if not alert.file_hash_sha1:
            m = SHA1_TEXT_RE.search(payload)
            if m:
                alert.file_hash_sha1 = m.group(1).lower()

    return alert.finalize()


def _parse_w3c_iis_fields(payload: str) -> dict[str, str]:
    """Parse the W3C IIS log fragment embedded in QRadar's Payload field.

    Format: `date=2026-05-24 time=15:55:38 s-sitename=W3SVC5 ...`
    Pieces separated by tabs or runs of spaces. Returns {} on no matches.
    """
    out: dict[str, str] = {}
    # Tab-delimited first (W3C standard) — fall through to space if needed.
    chunks = re.split(r"\t+|\s{2,}", payload)
    for chunk in chunks:
        m = re.match(r"([a-zA-Z][a-zA-Z0-9_\-()]*)=([^\s]+)", chunk.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


_EXCHANGE_KV_RE = re.compile(r"([A-Za-z][\w-]*)=(.*?)(?=\s+[A-Za-z][\w-]*=|$)")


def _parse_exchange_msgtrk(payload: str) -> dict[str, str]:
    """Parse a Microsoft Exchange message-tracking (MSGTRK) record embedded in
    QRadar's Payload field.

    Format: space-delimited `key=value` pairs, but some values contain spaces
    (e.g. `message-subject=ORHAN BILIR - Tahsilat ...`) and some contain `=`
    (e.g. `custom-data=S:Guid=...`). We therefore capture each value up to the
    next ` key=` boundary rather than splitting on whitespace. Surrounding
    double-quotes are stripped. Returns {} on no matches.
    """
    out: dict[str, str] = {}
    for m in _EXCHANGE_KV_RE.finditer(payload):
        key = m.group(1).strip().lower()
        val = m.group(2).strip().strip('"').strip()
        if key and val:
            out[key] = val
    return out


def _parse_leef_fields(payload: str) -> dict:
    """Parse a LEEF-style pipe-delimited payload into a dict of key=value pairs.

    Handles both LEEF 1.0 and 2.0. The header pipes (vendor|product|version) are
    skipped; only the key=value extension part is returned.
    """
    out: dict[str, str] = {}
    # Split on literal pipes — works because LEEF mandates pipe-escaping for any
    # value containing a pipe, and PAN-OS payloads observed never contain raw pipes.
    parts = payload.split("|")
    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out
