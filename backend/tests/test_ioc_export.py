"""Unit tests for Feature 4 — confirmed-IOC export (STIX 2.1 / CSV).

Pure: exercises the dedupe + CSV + STIX pattern/bundle builders in
`threat_intel.export`. The tenant-scoped TP/excluded DB query lives in the route
and is covered by live verification.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

import pytest

from isoc_api.threat_intel import export as ex

_T = datetime(2026, 7, 1, tzinfo=timezone.utc)


# ── STIX pattern mapping ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "ioc_type,value,expected",
    [
        ("ipv4", "1.2.3.4", "[ipv4-addr:value = '1.2.3.4']"),
        ("ipv6", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
        ("url", "http://evil.example/x", "[url:value = 'http://evil.example/x']"),
        ("email", "a@evil.example", "[email-addr:value = 'a@evil.example']"),
        ("sha256", "a" * 64, f"[file:hashes.'SHA-256' = '{'a' * 64}']"),
        ("sha1", "b" * 40, f"[file:hashes.'SHA-1' = '{'b' * 40}']"),
        ("md5", "c" * 32, f"[file:hashes.MD5 = '{'c' * 32}']"),
    ],
)
def test_stix_pattern_per_type(ioc_type, value, expected):
    assert ex.stix_pattern(ioc_type, value) == expected


def test_stix_pattern_unknown_type_is_none():
    assert ex.stix_pattern("mutex", "whatever") is None


def test_stix_pattern_escapes_quotes_and_backslashes():
    # A value with a single quote / backslash must not break out of the literal.
    p = ex.stix_pattern("url", "http://e/x'y\\z")
    assert p == "[url:value = 'http://e/x\\'y\\\\z']"


# ── dedupe ──────────────────────────────────────────────────────────────────
def test_dedupe_collapses_and_aggregates():
    later = datetime(2026, 7, 5, tzinfo=timezone.utc)
    rows = ex.dedupe(
        [
            ("ipv4", "1.2.3.4", later, "INC-000200", "acme"),
            ("ipv4", "1.2.3.4", _T, "INC-000100", "acme"),  # earlier + different incident
            ("domain", "evil.example", None, "INC-000100", None),
        ]
    )
    assert len(rows) == 2
    ip = next(r for r in rows if r.ioc_type == "ipv4")
    assert ip.first_seen == _T  # earliest kept
    assert ip.incidents == ["INC-000100", "INC-000200"]  # sorted + unique
    assert ip.tenant == "acme"


def test_dedupe_is_deterministically_ordered():
    rows = ex.dedupe(
        [
            ("url", "http://b", _T, "INC-1", None),
            ("domain", "a.example", _T, "INC-1", None),
            ("url", "http://a", _T, "INC-1", None),
        ]
    )
    assert [(r.ioc_type, r.value) for r in rows] == [
        ("domain", "a.example"),
        ("url", "http://a"),
        ("url", "http://b"),
    ]


# ── CSV ─────────────────────────────────────────────────────────────────────
def test_to_csv_header_and_rows():
    rows = ex.dedupe([("ipv4", "1.2.3.4", _T, "INC-000100", "acme")])
    out = ex.to_csv(rows)
    parsed = list(csv.reader(io.StringIO(out)))
    assert parsed[0] == ["ioc_type", "value", "first_seen", "incident_count", "incidents", "tenant"]
    assert parsed[1][:2] == ["ipv4", "1.2.3.4"]
    assert parsed[1][3] == "1"
    assert parsed[1][4] == "INC-000100"
    assert parsed[1][5] == "acme"


def test_to_csv_quotes_special_chars():
    rows = ex.dedupe([("url", "http://e/x,y", _T, "INC-1", None)])
    # csv reader round-trips the comma-containing value intact (it was quoted).
    parsed = list(csv.reader(io.StringIO(ex.to_csv(rows))))
    assert parsed[1][1] == "http://e/x,y"


# ── STIX bundle ─────────────────────────────────────────────────────────────
def test_to_stix_bundle_is_valid_and_complete():
    stix2 = pytest.importorskip("stix2")
    rows = ex.dedupe(
        [
            ("ipv4", "1.2.3.4", _T, "INC-000100", "acme"),
            ("sha256", "a" * 64, _T, "INC-000101", "acme"),
        ]
    )
    bundle = stix2.parse(ex.to_stix_bundle(rows, _T))  # raises if invalid STIX
    assert bundle.type == "bundle"
    patterns = sorted(o.pattern for o in bundle.objects)
    assert patterns == sorted(
        ["[ipv4-addr:value = '1.2.3.4']", f"[file:hashes.'SHA-256' = '{'a' * 64}']"]
    )


def test_to_stix_bundle_ids_are_deterministic():
    stix2 = pytest.importorskip("stix2")
    rows = ex.dedupe([("ipv4", "1.2.3.4", _T, "INC-1", None)])
    id_a = stix2.parse(ex.to_stix_bundle(rows, _T)).objects[0].id
    id_b = stix2.parse(ex.to_stix_bundle(rows, _T)).objects[0].id
    assert id_a == id_b  # same indicator → same id across exports (consumer idempotency)


def test_to_stix_bundle_skips_unmappable_types():
    stix2 = pytest.importorskip("stix2")
    rows = ex.dedupe(
        [
            ("ipv4", "1.2.3.4", _T, "INC-1", None),
            ("mutex", "Global\\x", _T, "INC-1", None),  # no STIX mapping → skipped
        ]
    )
    objs = stix2.parse(ex.to_stix_bundle(rows, _T)).objects
    assert len(objs) == 1
    assert objs[0].pattern == "[ipv4-addr:value = '1.2.3.4']"


def test_to_stix_bundle_empty_is_wellformed():
    import json

    # Empty export → a well-formed bundle with an explicit empty objects array.
    bundle = json.loads(ex.to_stix_bundle([], _T))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"] == []
