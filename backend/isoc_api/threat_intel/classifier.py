"""Decide what kind of IOC a raw line is.

The classifier is deliberately strict: anything that doesn't cleanly look
like an IP / URL / domain / hash is dropped. Threat feeds occasionally
carry header lines, comments, or empty rows — we'd rather skip junk than
store it.

`hash` covers md5 / sha1 / sha256 by length (32 / 40 / 64 hex chars).
We store all three under one type because lookups are exact-string
matches and the length implicitly disambiguates.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

IocKind = Literal["ip", "domain", "url", "hash"]

# Hostname segment (LDH per RFC 1035, generous on length).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)" r"(?:(?!-)[A-Za-z0-9-_]{1,63}(?<!-)\.)+" r"[A-Za-z]{2,63}$"
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
# md5=32, sha1=40, sha256=64. Anything else isn't a known hash family.
_HASH_LENGTHS = {32, 40, 64}


def classify(raw: str, kind_hint: str | None = None) -> tuple[IocKind, str] | None:
    """Return (kind, normalized_value) or None if the line should be dropped.

    `kind_hint` ("ip"/"domain"/"url"/"hash"/"auto"/None) lets a feed
    short-circuit detection. We still validate the value matches the hinted
    kind — a bad line in a "domain" feed is dropped, not coerced.

    Values are normalized: domains lowercased, hashes lowercased, IPs and
    URLs preserved as-is.
    """
    line = raw.strip().strip(",;'\"")
    if not line or line.startswith("#"):
        return None

    hint = (kind_hint or "auto").lower()

    if hint == "auto":
        if line.lower().startswith(("http://", "https://")):
            return ("url", line) if len(line) <= 2048 else None
        if _is_ip(line):
            return ("ip", line)
        if _is_hash(line):
            return ("hash", line.lower())
        if _is_domain(line):
            return ("domain", line.lower())
        return None

    if hint == "url":
        return (
            ("url", line)
            if (line.lower().startswith(("http://", "https://")) and len(line) <= 2048)
            else None
        )
    if hint == "ip":
        return ("ip", line) if _is_ip(line) else None
    if hint == "domain":
        return ("domain", line.lower()) if _is_domain(line) else None
    if hint == "hash":
        return ("hash", line.lower()) if _is_hash(line) else None

    return None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_domain(s: str) -> bool:
    # A bare IP would also match a permissive domain regex, so check IP first.
    return not _is_ip(s) and bool(_DOMAIN_RE.match(s))


def _is_hash(s: str) -> bool:
    return len(s) in _HASH_LENGTHS and bool(_HEX_RE.match(s))
