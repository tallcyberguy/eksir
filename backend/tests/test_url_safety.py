"""SSRF / url-safety guard: public-console mode vs internal-endpoint mode.

Pure unit tests. IP-literal cases need no DNS; the hostname-resolution path is
exercised by monkeypatching the resolver.
"""

from __future__ import annotations

import socket

import pytest

from isoc_api.security import url_safety as us


# ── public mode (EDR/connector consoles — must be public hosts) ─────────
def test_public_allows_public_ip_and_strips_query():
    r = us.validate_public_url("https://1.1.1.1/foo?proof=/models")
    assert r.sanitized == "https://1.1.1.1/foo"  # query stripped
    assert r.host == "1.1.1.1"
    assert r.port == 443
    assert r.scheme == "https"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",  # loopback
        "http://10.0.0.5:9200",  # private
        "http://192.168.1.1",  # private
        "http://169.254.169.254/latest/meta-data",  # cloud metadata
        "http://169.254.1.1",  # link-local
        "http://[::1]",  # ipv6 loopback
    ],
)
def test_public_blocks_internal_targets(url):
    with pytest.raises(us.UrlSafetyError):
        us.validate_public_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://1.1.1.1",  # scheme
        "file:///etc/passwd",  # scheme
        "http://user:pass@1.1.1.1",  # userinfo  # pragma: allowlist secret
        "http://1.1.1.1/x#frag",  # fragment
        "http:///nohost",  # missing host
        "",  # empty
    ],
)
def test_public_rejects_malformed(url):
    with pytest.raises(us.UrlSafetyError):
        us.validate_public_url(url)


def test_public_blocks_hostname_resolving_to_private(monkeypatch):
    monkeypatch.setattr(us, "_resolve", lambda host: ["10.1.2.3"])
    with pytest.raises(us.UrlSafetyError):
        us.validate_public_url("https://evil.example.com")


def test_public_allows_hostname_resolving_to_public(monkeypatch):
    monkeypatch.setattr(us, "_resolve", lambda host: ["93.184.216.34"])
    assert us.validate_public_url("https://example.com/x").host == "example.com"


def test_public_unresolvable_host_is_blocked(monkeypatch):
    def _boom(host):
        raise socket.gaierror("nope")

    monkeypatch.setattr(us, "_resolve", _boom)
    with pytest.raises(us.UrlSafetyError):
        us.validate_public_url("https://does-not-resolve.invalid")


# ── endpoint mode (LLM/BYOK — may be internal LiteLLM) ──────────────────
def test_endpoint_allows_private_and_loopback():
    assert us.validate_endpoint_url("http://10.0.0.2:4000/v1").host == "10.0.0.2"
    assert us.validate_endpoint_url("http://127.0.0.1:4000/v1").host == "127.0.0.1"


def test_endpoint_allows_unresolvable_internal_name(monkeypatch):
    # An internal service name (e.g. `litellm`) may only resolve at runtime.
    def _boom(host):
        raise socket.gaierror("nope")

    monkeypatch.setattr(us, "_resolve", _boom)
    assert us.validate_endpoint_url("http://litellm:4000").scheme == "http"


def test_endpoint_still_blocks_cloud_metadata():
    with pytest.raises(us.UrlSafetyError):
        us.validate_endpoint_url("http://169.254.169.254/latest/meta-data")


def test_endpoint_rejects_userinfo_and_scheme():
    with pytest.raises(us.UrlSafetyError):
        us.validate_endpoint_url("http://u:p@10.0.0.2")  # pragma: allowlist secret
    with pytest.raises(us.UrlSafetyError):
        us.validate_endpoint_url("gopher://10.0.0.2")
