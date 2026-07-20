"""SSRF / URL-safety guard for admin-supplied URLs.

ISOC lets admins configure URLs the backend then dials (EDR/XDR console
`base_url`s, the LLM endpoint, BYOK endpoints). Without a guard those become an
SSRF pivot into the internal docker network (Postgres/Redis/Qdrant/LiteLLM are
internal-only) or the cloud metadata service (169.254.169.254 → credential
theft). This module validates such URLs before they are stored/dialed.

Two modes, because the trust model differs:

- ``assert_public_url`` — for connector/EDR consoles (SentinelOne, CrowdStrike,
  …). These are always PUBLIC hosts, so ANY resolution to a loopback / private /
  link-local / multicast / reserved / metadata address is an SSRF attempt and is
  blocked.
- ``assert_endpoint_url`` — for LLM endpoints (admin LLM config, BYOK). ISOC
  routes the deep tier through LiteLLM on the PRIVATE docker network, so private
  and loopback are legitimate here; only the cloud metadata address is always
  blocked, plus bad scheme / userinfo / fragment.

Both resolve the host and inspect every resolved IP so a hostname can't smuggle a
blocked address past the check. DNS runs in a threadpool so the event loop never
blocks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

# AWS/GCP/Azure link-local metadata endpoints — never a legitimate target.
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})


class UrlSafetyError(ValueError):
    """Raised when a URL fails safety validation."""


@dataclass(frozen=True)
class SafeUrl:
    """A validated URL. ``sanitized`` has userinfo, query, and fragment stripped
    (append fixed paths onto it, never onto the raw input)."""

    sanitized: str
    host: str
    port: int
    scheme: str


def _ip_block_reason(ip_str: str, *, metadata_only: bool) -> str | None:
    """Reason this IP is disallowed, or None if allowed."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"unparseable IP: {ip_str}"
    if str(ip) in _METADATA_IPS:
        return "cloud metadata address"
    if metadata_only:
        return None
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_unspecified:
        return "unspecified address"
    return None


def _resolve(host: str) -> list[str]:
    """Resolve a hostname to its IPs (may raise socket.gaierror)."""
    seen: list[str] = []
    for info in socket.getaddrinfo(host, None):
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def _validate(url: str, *, metadata_only: bool) -> SafeUrl:
    if not url or not isinstance(url, str):
        raise UrlSafetyError("url is required")

    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise UrlSafetyError(f"scheme not allowed: {parsed.scheme or '(missing)'}")
    if not parsed.hostname:
        raise UrlSafetyError("url is missing a host")
    if parsed.username or parsed.password:
        raise UrlSafetyError("url must not include userinfo")
    if parsed.fragment:
        raise UrlSafetyError("url must not include a fragment")

    host = parsed.hostname.lower()
    # IP literal → check directly (no DNS). Hostname → resolve every address.
    try:
        addrs: list[str] = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            addrs = _resolve(host)
        except socket.gaierror as exc:
            if metadata_only:
                # Endpoint mode: an internal name (e.g. `litellm`) may only
                # resolve at runtime. Scheme/userinfo/fragment were already
                # checked; allow and let the dial fail loudly if the host is bad.
                addrs = []
            else:
                raise UrlSafetyError(f"could not resolve host: {host}") from exc

    for addr in addrs:
        reason = _ip_block_reason(addr, metadata_only=metadata_only)
        if reason:
            raise UrlSafetyError(f"resolved address {addr} is disallowed: {reason}")

    sanitized = urlunparse(
        (
            parsed.scheme,
            parsed.netloc.split("@")[-1],  # drop userinfo if anything slipped through
            parsed.path or "",
            "",  # params
            "",  # query
            "",  # fragment
        )
    )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return SafeUrl(sanitized=sanitized, host=host, port=port, scheme=parsed.scheme)


def validate_public_url(url: str) -> SafeUrl:
    """Full SSRF guard for a PUBLIC console URL (EDR/connector base_url)."""
    return _validate(url, metadata_only=False)


def validate_endpoint_url(url: str) -> SafeUrl:
    """Guard for an LLM endpoint that MAY be internal (LiteLLM/BYOK): blocks the
    cloud metadata address + bad scheme/userinfo/fragment, allows private/loopback."""
    return _validate(url, metadata_only=True)


async def assert_public_url(url: str) -> SafeUrl:
    """Async: validate a public console URL off the event loop (DNS in a thread)."""
    return await asyncio.to_thread(validate_public_url, url)


async def assert_endpoint_url(url: str) -> SafeUrl:
    """Async: validate an LLM/BYOK endpoint URL off the event loop."""
    return await asyncio.to_thread(validate_endpoint_url, url)
