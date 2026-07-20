"""Unit tests for Feature 5 — STIX/TAXII inbound feed.

Two layers, both offline:
  • pure STIX pattern -> (kind, value) extraction (stix_parse)
  • the TAXII 2.1 pager (_fetch_taxii) driven by an httpx MockTransport, so
    pagination + auth headers are exercised without a live TAXII server.
"""

from __future__ import annotations

import httpx
import pytest

from isoc_api.threat_intel import stix_parse
from isoc_api.threat_intel.sync import _fetch_taxii

_HASH = "a" * 64


# ── stix_parse.stix_pattern_to_iocs ─────────────────────────────────────────
@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("[ipv4-addr:value = '1.2.3.4']", [("ip", "1.2.3.4")]),
        ("[ipv6-addr:value = '2001:db8::1']", [("ip", "2001:db8::1")]),
        ("[domain-name:value = 'evil.example']", [("domain", "evil.example")]),
        ("[url:value = 'http://evil.example/x']", [("url", "http://evil.example/x")]),
        (f"[file:hashes.'SHA-256' = '{_HASH}']", [("hash", _HASH)]),
        ("[file:hashes.MD5 = '" + "b" * 32 + "']", [("hash", "b" * 32)]),
    ],
)
def test_pattern_to_iocs_per_type(pattern, expected):
    assert stix_parse.stix_pattern_to_iocs(pattern) == expected


def test_email_and_unmappable_are_skipped():
    assert stix_parse.stix_pattern_to_iocs("[email-addr:value = 'a@b.example']") == []
    assert stix_parse.stix_pattern_to_iocs("[mutex:name = 'Global\\Foo']") == []
    assert stix_parse.stix_pattern_to_iocs("[file:name = 'x.exe']") == []


def test_compound_pattern_yields_all_iocs():
    p = "[ipv4-addr:value = '1.1.1.1' OR domain-name:value = 'a.example']"
    assert stix_parse.stix_pattern_to_iocs(p) == [("ip", "1.1.1.1"), ("domain", "a.example")]


def test_url_with_equals_and_escaped_quote():
    # `=` inside the quoted value must not terminate parsing; \' unescapes.
    p = "[url:value = 'http://e/x?a=b&c=d\\'z']"
    assert stix_parse.stix_pattern_to_iocs(p) == [("url", "http://e/x?a=b&c=d'z")]


def test_dedupes_within_a_pattern():
    p = "[ipv4-addr:value = '9.9.9.9' OR ipv4-addr:value = '9.9.9.9']"
    assert stix_parse.stix_pattern_to_iocs(p) == [("ip", "9.9.9.9")]


# ── stix_parse.indicators_to_iocs ───────────────────────────────────────────
def test_indicators_to_iocs_filters_and_dedupes():
    objects = [
        {"type": "indicator", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
        {
            "type": "indicator",
            "pattern": "[domain-name:value = 'a.example']",
        },  # 2.0: no pattern_type
        {"type": "indicator", "pattern_type": "sigma", "pattern": "ignored"},  # non-stix → skip
        {"type": "malware", "name": "x"},  # not an indicator
        {
            "type": "indicator",
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        },  # dup
    ]
    assert stix_parse.indicators_to_iocs(objects) == [("ip", "1.2.3.4"), ("domain", "a.example")]


# ── _fetch_taxii: pagination + auth via MockTransport ───────────────────────
class _Feed:
    def __init__(self, url):
        self.url = url
        self.name = "test-taxii"


async def test_fetch_taxii_pages_and_sends_bearer_auth():
    seen_auth: list[str | None] = []
    seen_accept: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization"))
        seen_accept.append(request.headers.get("accept"))
        if request.url.params.get("next") == "PAGE2":
            return httpx.Response(
                200,
                json={
                    "objects": [
                        {
                            "type": "indicator",
                            "pattern_type": "stix",
                            "pattern": "[domain-name:value = 'evil.example']",
                        }
                    ],
                    "more": False,
                },
            )
        return httpx.Response(
            200,
            json={
                "objects": [
                    {
                        "type": "indicator",
                        "pattern_type": "stix",
                        "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    },
                    {
                        "type": "indicator",
                        "pattern_type": "stix",
                        "pattern": f"[file:hashes.'SHA-256' = '{_HASH}']",
                    },
                    {"type": "identity", "name": "vendor"},
                ],
                "more": True,
                "next": "PAGE2",
            },
        )

    config = {"format": "taxii", "auth": {"type": "token", "token": "SECRET-TOKEN"}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        iocs = await _fetch_taxii(client, _Feed("https://taxii.example/collections/abc/"), config)

    assert iocs == [("ip", "1.2.3.4"), ("hash", _HASH), ("domain", "evil.example")]
    assert seen_auth == ["Bearer SECRET-TOKEN", "Bearer SECRET-TOKEN"]  # both pages
    assert all(a and "version=2.1" in a for a in seen_accept)


async def test_fetch_taxii_basic_auth_and_single_page():
    def handler(request: httpx.Request) -> httpx.Response:
        # httpx encodes basic auth into the Authorization header.
        assert request.headers.get("authorization", "").startswith("Basic ")
        return httpx.Response(
            200,
            json={
                "objects": [
                    {
                        "type": "indicator",
                        "pattern_type": "stix",
                        "pattern": "[url:value = 'http://x.example/p']",
                    }
                ],
                "more": False,
            },
        )

    config = {"format": "taxii", "auth": {"type": "basic", "username": "u", "password": "p"}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        iocs = await _fetch_taxii(client, _Feed("https://taxii.example/collections/xyz"), config)
    assert iocs == [("url", "http://x.example/p")]
