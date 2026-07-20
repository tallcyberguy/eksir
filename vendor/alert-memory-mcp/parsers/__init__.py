"""
Auto-detect parser based on alert format and route accordingly.
"""

import re
import json
from typing import Union
from normalizer import NormalizedAlert
from parsers import qradar, wazuh, fortigate, syslog, visionone, sentinelone, crowdstrike, microsoft_defender


def _looks_like_v1_workbench(raw: dict) -> bool:
    """True for a Trend Micro Vision One Workbench alert JSON (v3.0 API shape)."""
    if str(raw.get("id", "")).startswith("WB-"):
        return True
    keys = raw.keys()
    return "impactScope" in keys and ("matchedRules" in keys or "model" in keys)


def _looks_like_sentinelone(raw: dict) -> bool:
    """True for a SentinelOne threat JSON (v2.1 API shape)."""
    keys = raw.keys()
    return "threatInfo" in keys and ("agentRealtimeInfo" in keys or "agentDetectionInfo" in keys)


def detect_source(raw: Union[str, dict]) -> str:
    """Heuristically detect the alert source product."""
    if isinstance(raw, dict):
        text = json.dumps(raw)
    else:
        text = raw

    # Wazuh JSON envelope has 'rule.id' and 'agent' keys
    if isinstance(raw, dict) and "rule" in raw and "agent" in raw:
        return "wazuh"

    # FortiGate envelope dict (pending_index.jsonl style)
    if isinstance(raw, dict) and "raw_alert" in raw:
        inner = raw["raw_alert"]
        if "logver=" in inner or "devid=FG" in inner:
            return "fortigate"

    # Vision One Workbench alert JSON (v3.0 API pull) — a dict with a WB- id and
    # the workbench shape. Checked before the text markers so the JSON path wins.
    if isinstance(raw, dict) and _looks_like_v1_workbench(raw):
        return "visionone"

    # SentinelOne threat JSON (v2.1 API pull).
    if isinstance(raw, dict) and _looks_like_sentinelone(raw):
        return "sentinelone"

    # QRadar email notifications have this header
    if "QRadar event custom rules engine" in text:
        return "qradar"
    if "Rule Name:" in text and "QID:" in text:
        return "qradar"

    # Wazuh as raw string (e.g. from email notification)
    if '"rule"' in text and '"agent"' in text:
        return "wazuh"

    # Wazuh email-notification format — the ossec-monitord template:
    #   "Wazuh Notification." header, "Rule: <id> fired (level N) -> "<desc>""
    #   followed by an embedded JSON snippet.
    if "Wazuh Notification" in text and re.search(r'Rule:\s*\d+\s*fired', text):
        return "wazuh"

    # FortiGate key=value log line
    if "logver=" in text or ("devid=FG" in text and "type=" in text):
        return "fortigate"

    # Syslog RFC 3164: starts with optional <pri> then month abbreviation
    if re.match(r'^(?:<\d+>)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d', text.strip()):
        return "syslog"

    # Syslog RFC 5424: <pri>version ISO-timestamp
    if re.match(r'^<\d+>\d+\s+\d{4}-\d{2}-\d{2}T', text.strip()):
        return "syslog"

    # Trend Micro Vision One Workbench email — LAST product branch so it can't
    # shadow the others; requires >=2 distinctive markers to avoid false
    # positives on a forwarded email that merely quotes a V1 console link.
    v1_markers = (
        "trendai vision one" in text.lower(),
        "vision one" in text.lower(),
        "workbench id:" in text.lower(),
        bool(re.search(r'\bWB-\d+-\d{8}-\d+\b', text)),
        "xdr.trendmicro.com" in text.lower(),
        "| workbench |" in text.lower(),
        "model severity:" in text.lower(),
    )
    if sum(1 for m in v1_markers if m) >= 2:
        return "visionone"

    return "unknown"


def parse(raw: Union[str, dict], customer: str = None) -> NormalizedAlert:
    """
    Parse any supported alert format into NormalizedAlert.

    Args:
        raw:      Alert as string (QRadar email text, Wazuh JSON string)
                  or dict (pre-parsed Wazuh JSON).
        customer: Customer identifier for multi-tenant isolation.

    Returns:
        NormalizedAlert with embed_text ready for vector indexing.
    """
    source = detect_source(raw)

    if source == "qradar":
        return qradar.parse(raw, customer=customer)
    elif source == "wazuh":
        return wazuh.parse(raw, customer=customer)
    elif source == "fortigate":
        return fortigate.parse(raw, customer=customer)
    elif source == "syslog":
        return syslog.parse(raw, customer=customer)
    elif source == "visionone":
        return visionone.parse(raw, customer=customer)
    elif source == "sentinelone":
        return sentinelone.parse(raw, customer=customer)
    else:
        raise ValueError(
            "Unknown alert format. Supported: qradar, wazuh, fortigate, syslog, "
            f"visionone, sentinelone. Got snippet: {str(raw)[:200]}"
        )
