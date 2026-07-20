"""Unit tests for store._domain_from_url — the domain extraction used when
indexing IOCs into iocs_v2 (so lookup_ioc_history can cover domains, not just
IPs and hashes).

Run:  cd vendor/alert-memory-mcp && python -m pytest tests/test_iocs_domain.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import store  # noqa: E402


def test_full_url():
    assert store._domain_from_url(
        "http://malicious-c2.evil.example/stage2.ps1"
    ) == "malicious-c2.evil.example"


def test_https_with_port_strips_port():
    assert store._domain_from_url("https://bad.example:8443/x") == "bad.example"


def test_bare_domain_no_scheme():
    assert store._domain_from_url("evil.com/path") == "evil.com"


def test_uppercase_is_lowercased():
    assert store._domain_from_url("http://EVIL.COM/x") == "evil.com"


def test_ipv4_literal_skipped():
    assert store._domain_from_url("http://1.2.3.4/x") is None


def test_ipv6_literal_skipped():
    assert store._domain_from_url("http://[2001:db8::1]/x") is None


def test_empty_and_none():
    assert store._domain_from_url("") is None
    assert store._domain_from_url(None) is None
