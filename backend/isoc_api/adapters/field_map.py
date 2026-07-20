"""Config-driven field mapping for sources without a bespoke parser.

A source's ``field_map`` (JSONB on ``ingest_sources``) maps NormalizedAlert field
names to dotted paths into the raw alert dict, so onboarding a new source (a SIEM,
a custom feed, another EDR) is a configuration change instead of a hand-written
parser + image rebuild. ``normalize_severity`` coerces arbitrary severity
words/numbers to the canonical Wazuh 1-15 scale the pipeline expects.

Example field_map:
    {"rule_name": "rule.name", "severity": "event.severity",
     "src_ip": "source.ip", "hostname": "host.name", "timestamp": "@timestamp"}
"""

from __future__ import annotations

import importlib
import json
from typing import Any

# NormalizedAlert attributes a map may target (guards against setting junk).
_MAPPABLE = frozenset(
    {
        "rule_name",
        "event_name",
        "rule_id",
        "severity",
        "threat_category",
        "timestamp",
        "hostname",
        "username",
        "src_ip",
        "dst_ip",
        "file_path",
        "file_hash_sha256",
        "file_hash_sha1",
        "url",
        "sender",
        "recipient",
        "subject",
        "mitre_technique",
        "event_description",
    }
)

# Words/numbers -> Wazuh-style 1-15 severity (mirrors the vendored parsers).
_SEVERITY_WORDS = {
    "critical": 14,
    "crit": 14,
    "emergency": 14,
    "high": 9,
    "error": 9,
    "medium": 6,
    "med": 6,
    "moderate": 6,
    "warning": 6,
    "warn": 6,
    "low": 3,
    "notice": 3,
    "info": 1,
    "informational": 1,
    "debug": 1,
}


def normalize_severity(value: Any) -> int:
    """Coerce an arbitrary severity word/number to the Wazuh 1-15 scale."""
    if value is None:
        return 6
    if isinstance(value, bool):
        return 6
    if isinstance(value, (int, float)):
        n = float(value)
        if n > 15:  # a 0-100 style scale
            if n >= 80:
                return 14
            if n >= 60:
                return 9
            if n >= 40:
                return 6
            return 3
        return max(1, min(15, int(round(n))))  # already an ordinal
    return _SEVERITY_WORDS.get(str(value).strip().lower(), 6)


def dig(raw: Any, path: str) -> Any:
    """Extract a dotted path from nested dict/list, e.g. ``a.b.0.c``. None if absent."""
    cur = raw
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def apply_field_map(
    raw: dict,
    field_map: dict,
    *,
    source_product: str | None = None,
    customer: str | None = None,
) -> dict:
    """Build a normalized-alert dict from ``raw`` using ``field_map``.

    ``field_map`` maps NormalizedAlert field name -> dotted path into ``raw``.
    Unknown target fields are ignored; ``severity`` is coerced via
    ``normalize_severity``. Returns the finalized ``to_dict()`` (embed_text ready).
    """
    normalizer = importlib.import_module("normalizer")
    alert = normalizer.NormalizedAlert(source_product=source_product or "custom", customer=customer)
    alert.raw = (
        json.dumps(raw, ensure_ascii=False, default=str) if isinstance(raw, dict) else str(raw)
    )

    for field, path in (field_map or {}).items():
        if field not in _MAPPABLE:
            continue
        val = dig(raw, path)
        if val is None:
            continue
        if field == "severity":
            alert.severity = normalize_severity(val)
        else:
            setattr(alert, field, val if isinstance(val, str) else str(val))

    return alert.finalize().to_dict()
