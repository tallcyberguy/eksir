"""Feature 5 — parse inbound STIX 2.x indicators into local feed IOCs.

The reverse of `export.stix_pattern` (feature 4): given STIX Indicator objects
pulled from a TAXII collection, extract `(IocKind, value)` tuples for the
existing `threat_iocs` upsert. The feed store is coarse-grained
(`IocKind` = ip/domain/url/hash), so email-addr / file:name / other object paths
have no home and are skipped.

Pure + unit-tested — no network. The TAXII fetch that supplies the objects lives
in `sync.py`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .classifier import IocKind

# One STIX equality comparison: `object-type:property = 'value'`. `finditer`
# pulls every comparison out of a pattern, so a compound
# `[a:b='x' OR c:d='y']` yields both. The value group tolerates STIX escapes
# (\' and \\) so a quote inside the value doesn't end it early.
_COMPARISON = re.compile(
    r"([a-z0-9][a-z0-9-]*)\s*:\s*([^\s=]+)\s*=\s*'((?:[^'\\]|\\.)*)'",
    re.IGNORECASE,
)


def _unescape(value: str) -> str:
    """Reverse STIX string-literal escaping (backslash last)."""
    return value.replace("\\'", "'").replace("\\\\", "\\")


def _kind(object_type: str, prop: str) -> IocKind | None:
    """Map a STIX (object-type, property) to a coarse feed IocKind, or None."""
    object_type = object_type.lower()
    if object_type in ("ipv4-addr", "ipv6-addr"):
        return "ip"
    if object_type == "domain-name":
        return "domain"
    if object_type == "url":
        return "url"
    if object_type == "file" and prop.lower().startswith("hashes"):
        return "hash"
    return None  # email-addr, file:name, mutex, windows-registry-key, … → no feed kind


def stix_pattern_to_iocs(pattern: str) -> list[tuple[IocKind, str]]:
    """Extract `(kind, value)` from a STIX pattern (deduped, order-preserving)."""
    if not pattern:
        return []
    out: list[tuple[IocKind, str]] = []
    seen: set[tuple[IocKind, str]] = set()
    for m in _COMPARISON.finditer(pattern):
        kind = _kind(m.group(1), m.group(2))
        if kind is None:
            continue
        key = (kind, _unescape(m.group(3)))
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def indicators_to_iocs(objects: Iterable[dict]) -> list[tuple[IocKind, str]]:
    """From a bag of STIX objects, take the STIX-pattern Indicators and flatten
    them to deduped `(kind, value)` tuples ready for the feed upsert."""
    out: list[tuple[IocKind, str]] = []
    seen: set[tuple[IocKind, str]] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        # STIX 2.0 indicators omit pattern_type (implicitly "stix"); 2.1 sets it.
        if obj.get("pattern_type", "stix") != "stix":
            continue
        for key in stix_pattern_to_iocs(obj.get("pattern", "")):
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out
