"""Config-driven field mapping + the pull-path JSON-parsing fix.

Pure unit tests. The vendored normalizer/parsers load via sys.path.
"""

from __future__ import annotations

import json
import os
import sys

from isoc_api.adapters import field_map as fm


def _add_vendored_path() -> None:
    p = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
    )
    if p not in sys.path:
        sys.path.insert(0, p)


# ── normalize_severity ──────────────────────────────────────────────────
def test_normalize_severity_words_and_numbers():
    assert fm.normalize_severity("critical") == 14
    assert fm.normalize_severity("High") == 9
    assert fm.normalize_severity("medium") == 6
    assert fm.normalize_severity("low") == 3
    assert fm.normalize_severity("informational") == 1
    assert fm.normalize_severity(95) == 14  # 0-100 scale
    assert fm.normalize_severity(50) == 6
    assert fm.normalize_severity(9) == 9  # ordinal 1-15
    assert fm.normalize_severity(None) == 6
    assert fm.normalize_severity("weird") == 6  # unknown word -> medium default


# ── dotted-path dig ─────────────────────────────────────────────────────
def test_dig_nested_and_list():
    raw = {"a": {"b": [{"c": "v"}]}}
    assert fm.dig(raw, "a.b.0.c") == "v"
    assert fm.dig(raw, "a.b.9.c") is None
    assert fm.dig(raw, "a.x") is None


# ── apply_field_map ─────────────────────────────────────────────────────
def test_apply_field_map_maps_and_coerces():
    _add_vendored_path()
    raw = {
        "rule": {"name": "Bruteforce"},
        "event": {"sev": "high"},
        "source": {"ip": "1.2.3.4"},
        "host": {"name": "H1"},
    }
    fmap = {
        "rule_name": "rule.name",
        "severity": "event.sev",
        "src_ip": "source.ip",
        "hostname": "host.name",
        "junk_field": "rule.name",  # unknown target — ignored, no crash
    }
    d = fm.apply_field_map(raw, fmap, source_product="acme_siem", customer="acme")
    assert d["source_product"] == "acme_siem"
    assert d["customer"] == "acme"
    assert d["rule_name"] == "Bruteforce"
    assert d["severity"] == 9  # "high" coerced
    assert d["src_ip"] == "1.2.3.4"
    assert d["hostname"] == "H1"


# ── the pull-path fix: JSON string now hits the dict parser ─────────────
def test_json_string_now_routes_to_dict_parser():
    _add_vendored_path()
    from isoc_api.adapters import parser_adapter

    threat = {
        "threatInfo": {"threatName": "x", "confidenceLevel": "malicious"},
        "agentRealtimeInfo": {"agentComputerName": "H1"},
    }
    # Before the fix this parsed as "unknown"; the cron stores exactly this string.
    d = parser_adapter.parse_to_normalized(json.dumps(threat))
    assert d["source_product"] == "sentinelone"
    assert d["rule_name"] == "x"


def test_field_map_is_fallback_only_bespoke_parser_wins():
    _add_vendored_path()
    from isoc_api.adapters import parser_adapter

    threat = {
        "threatInfo": {"threatName": "real", "confidenceLevel": "malicious"},
        "agentRealtimeInfo": {"agentComputerName": "H1"},
    }
    # A field_map is present but SentinelOne has a bespoke parser -> it wins.
    d = parser_adapter.parse_to_normalized(
        json.dumps(threat), field_map={"rule_name": "threatInfo.threatName"}
    )
    assert d["source_product"] == "sentinelone"
    assert d["rule_name"] == "real"


def test_field_map_applied_when_no_bespoke_parser():
    _add_vendored_path()
    from isoc_api.adapters import parser_adapter

    raw = {"weird": {"name": "Custom Alert"}, "sev": "high"}  # no parser matches
    d = parser_adapter.parse_to_normalized(
        json.dumps(raw),
        source_hint="acme_siem",
        field_map={"rule_name": "weird.name", "severity": "sev"},
    )
    assert d["source_product"] == "acme_siem"
    assert d["rule_name"] == "Custom Alert"
    assert d["severity"] == 9


def test_unknown_without_field_map_degrades_cleanly():
    _add_vendored_path()
    from isoc_api.adapters import parser_adapter

    d = parser_adapter.parse_to_normalized(json.dumps({"weird": 1}), source_hint="acme")
    assert d["source_product"] == "acme"  # empty alert, analyst hand-edits
