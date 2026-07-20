"""IOC extraction from a normalized alert.

Public IPs trigger triage. RFC 1918 / link-local / loopback are skipped.
Hashes (MD5/SHA1/SHA256) and domains/URLs are collected if present in normalized payload.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from ..db.enums import IOCType

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_URL_RE = re.compile(r"https?://[^\s\"<>]+")
_IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Normalized fields the parsers may carry an email address in (sender + recipient).
# We extract BOTH; the customer/recipient side is suppressed downstream by the
# shared exclusion DB (add the customer domain once — it covers the domain and
# every address at that domain). See exclusions/filter.py.
_EMAIL_FIELDS = (
    "sender",
    "from",
    "from_addr",
    "from_email",
    "mail_from",
    "return_path",
    "envelope_from",
    "recipient",
    "to",
    "rcpt_to",
    "to_email",
)

# Vendor knowledge-base / signature reference domains — not attacker infrastructure.
_VENDOR_REF_DOMAINS = frozenset(
    {
        "fortinet.com",
        "fortigate.com",
        "microsoft.com",
        "msdn.com",
        "mitre.org",
        "cve.org",
        "iana.org",
        "ripe.net",
        "symantec.com",
        "broadcom.com",
        "trendmicro.com",
    }
)


def _is_vendor_ref_url(url: str) -> bool:
    try:
        host = url.split("//", 1)[1].split("/")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        return any(host == d or host.endswith("." + d) for d in _VENDOR_REF_DOMAINS)
    except (IndexError, AttributeError):
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
        return True
    # IPv6
    return ip.is_global


def _safe(value) -> str:
    return value if isinstance(value, str) else ""


def _is_message_id_local(local: str) -> bool:
    """Message-ID local parts look like `20260603134456.A6C298F632879D90` — all
    hex/digits/dots and long. Real mailbox local parts are short and word-like,
    so we skip these to avoid emitting a Message-ID as a sender address."""
    return len(local) > 20 and bool(re.fullmatch(r"[0-9a-fA-F.]+", local))


# Token that, immediately before a dotted-quad, marks it as a software version
# rather than an IP — e.g. `Version=3.0.0.0`, `ver: 1.2.3.4`, `v10.0.0.1`.
_VERSION_PREFIX_RE = re.compile(r"(?i)(?:\b(?:version|ver|rev|build|assembly)\b|\bv)\s*[=:]?\s*$")


def _looks_like_version(text: str, start: int, end: int) -> bool:
    """True when the dotted-quad at text[start:end] is a software version string,
    not an IP. Used only by the RAW IP fallback — parser-provided src/dst IPs are
    structured and never routed through here.

    Three signals:
      * preceded by a version/build token (`Version=`, `ver:`, `v`, …)
      * part of a longer dotted sequence (`1.2.3.4.5` — a leading/trailing `.digit`)
      * inside the .NET assembly pattern (`Version=…, Culture=…, PublicKeyToken=…`)
    """
    before = text[max(0, start - 16) : start]
    after = text[end : end + 24]

    # Longer dotted sequence on either side → not a 4-octet IP.
    if before.endswith(".") and before[:-1][-1:].isdigit():
        return True
    if after[:1] == "." and after[1:2].isdigit():
        return True

    if _VERSION_PREFIX_RE.search(before):
        return True

    # .NET assembly identifier: "…, Culture=…" / "PublicKeyToken=" trailing context.
    if re.match(r"(?i)\s*,\s*culture\s*=", after) or "publickeytoken" in after.lower():
        return True

    return False


def _domain_of_email(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(".")


def _domain_of_url(url: str) -> str | None:
    """Lowercase host of a URL, or None if it doesn't look like one."""
    try:
        after = url.split("://", 1)[1] if "://" in url else url
        host = after.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split("@", 1)[-1].split(":", 1)[0].lower()
        return host or None
    except (IndexError, AttributeError):
        return None


def extract(normalized: dict, raw: str) -> list[tuple[IOCType, str]]:
    out: list[tuple[IOCType, str]] = []

    src_ip = _safe(normalized.get("src_ip")).strip()
    dst_ip = _safe(normalized.get("dst_ip")).strip()
    for ip in (src_ip, dst_ip):
        if ip and is_public_ip(ip):
            out.append((IOCType.IPV4, ip))

    url = _safe(normalized.get("url")).strip()
    if url:
        out.append((IOCType.URL, url))

    # Domain (if explicit field)
    dom = _safe(normalized.get("domain")).strip()
    if dom:
        out.append((IOCType.DOMAIN, dom))

    text = raw or ""

    # ── Email addresses (sender + recipient) and their domains ──────────
    # Prefer structured fields if a parser captured them; always also scan raw
    # so we don't miss the From / Return-Path. Both sender and recipient are
    # extracted; the recipient/customer side is filtered downstream by the
    # shared exclusion DB (a single domain exclusion covers the domain AND any
    # address at it — see exclusions/filter.py).
    email_candidates: list[str] = []
    for f in _EMAIL_FIELDS:
        fv = _safe(normalized.get(f)).strip()
        if fv:
            email_candidates.extend(_EMAIL_RE.findall(fv))
    email_candidates.extend(_EMAIL_RE.findall(text))

    derived_domains: list[str] = []
    for addr in email_candidates:
        local = addr.rsplit("@", 1)[0]
        if _is_message_id_local(local):
            continue  # Message-ID, not a real mailbox
        out.append((IOCType.EMAIL_ADDR, addr.lower()))
        d = _domain_of_email(addr)
        if d:
            derived_domains.append(d)

    # Domains derived from the explicit url field, any raw URLs, and emails.
    for u in ([url] if url else []) + (_URL_RE.findall(text) if text else []):
        h = _domain_of_url(u)
        if h:
            derived_domains.append(h)
    for d in derived_domains:
        if "." in d and not _is_vendor_ref_url("http://" + d):
            out.append((IOCType.DOMAIN, d))

    # File hashes from raw (SHA256/SHA1/MD5 are unambiguous patterns)
    for h in _SHA256_RE.findall(text):
        out.append((IOCType.SHA256, h.lower()))
    for h in _SHA1_RE.findall(text):
        out.append((IOCType.SHA1, h.lower()))
    for h in _MD5_RE.findall(text):
        out.append((IOCType.MD5, h.lower()))

    # File hashes from the STRUCTURED normalized fields. A parser may have slotted
    # a hash that never appears verbatim in `raw` (e.g. a Vision One API detail or
    # a split Sysmon key), so read them directly. file_hash_md5 rides only as an
    # optional passthrough key (no dataclass field), hence the .get() guard. The
    # final dedupe pass below collapses any overlap with the raw scan.
    for field, ioc_type in (
        ("file_hash_sha256", IOCType.SHA256),
        ("file_hash_sha1", IOCType.SHA1),
        ("file_hash_md5", IOCType.MD5),
    ):
        hv = _safe(normalized.get(field)).strip().lower()
        if hv:
            out.append((ioc_type, hv))

    # URLs from raw — only when the normalized url field is empty, and skip
    # vendor reference links (e.g. fortinet.com/ids/VID*) which are not IOCs.
    if not url:
        for u in _URL_RE.findall(text):
            # Trim trailing punctuation/quotes the regex over-captures. Quotes
            # matter for deobfuscated payloads where a URL is wrapped in '...'
            # (e.g. DownloadString('http://c2/x') → trailing ' left attached).
            u = u.rstrip(".,);'\"")
            if not _is_vendor_ref_url(u):
                out.append((IOCType.URL, u))

    # IP fallback: scan raw when the parser produced no src/dst IPs.
    # Catches embedded logs (e.g. FortiGate KV inside Wazuh notification) where
    # normalizer fields are null due to an unrecognised sub-format.
    if not src_ip and not dst_ip:
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
            ip_str = m.group(1)
            # Skip dotted-quads that are actually software versions, not IPs
            # (e.g. ".NET assembly `Version=3.0.0.0`"). See _looks_like_version.
            if _looks_like_version(text, m.start(1), m.end(1)):
                continue
            if is_public_ip(ip_str):
                out.append((IOCType.IPV4, ip_str))

    # Deduplicate while preserving order
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[IOCType, str]] = []
    for t, v in out:
        key = (t.value, v.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append((t, v))
    return unique


def to_triage_args(iocs: Iterable[tuple[IOCType, str]]) -> list[tuple[str, str]]:
    """Convert IOCRecords → (value, triage_type) tuples."""
    type_map = {
        IOCType.IPV4: "ip",
        IOCType.IPV6: "ip",
        IOCType.SHA256: "hash",
        IOCType.SHA1: "hash",
        IOCType.MD5: "hash",
        IOCType.DOMAIN: "domain",
        IOCType.URL: "url",
    }
    return [(value, type_map[t]) for t, value in iocs if t in type_map]
