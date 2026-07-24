"""Tests for the native OCSF-first Vision One parser (adapters/ocsf_v1.py).

The vision_one PULL connector hands the v3.0 Workbench alert dict; ocsf_v1 parses
it natively. These lock in (1) the field contract downstream depends on
(v1_workbench_id / v1_region / source_product, severity, MITRE, entities, IOCs,
vendor_score) and (2) golden equivalence with the vendored parser it supersedes on
the dict path, so the swap is behaviour-preserving. A non-dict input still routes
through the vendored text parser.

The parser builds a vendored NormalizedAlert; we put the vendored package on the
path here so the test runs on the host like the other pure tests.
"""

from __future__ import annotations

import os
import sys

_VENDOR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
)
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

from isoc_api.adapters import ocsf_v1  # noqa: E402

# Real Workbench v3.0 alert shape, synthetic values.
WORKBENCH_ALERT = {
    "id": "WB-30189-20260621-00042",
    "workbenchLink": (
        "https://portal.sg.xdr.trendmicro.com/index.html#/workbench/alerts/WB-30189-20260621-00042"
    ),
    "model": "Ransomware activity detected",
    "severity": "high",
    "score": 82,
    "description": "Multiple file-encryption behaviours observed on a server.",
    "alertProvider": "SAE",
    "createdDateTime": "2026-06-21T20:47:56Z",
    "status": "New",
    "investigationResult": "Malicious",
    "incidentId": "INC-555",
    "impactScope": {
        "serverCount": 2,
        "accountCount": 1,
        "entities": [
            {"entityType": "host", "entityValue": {"name": "UNOEXCSRV01", "ips": ["10.0.0.5"]}},
            {"entityType": "account", "entityValue": {"name": "UNMAS_WG\\furkan"}},
        ],
    },
    "matchedRules": [
        {
            "name": "Suspicious encryption tool",
            "matchedFilters": [
                {"mitreTechniqueIds": ["T1486", "T1490"], "mitreTacticIds": ["TA0040"]}
            ],
        }
    ],
    "indicators": [
        {"type": "file_sha256", "value": "a" * 64},
        {"type": "command_line", "value": "vssadmin delete shadows /all"},
        {"type": "ip", "value": "203.0.113.9"},
    ],
}

# Fields downstream (pipeline/orchestrator, scoring, briefing, ocsf) reads off a
# normalized V1 alert. Equivalence is asserted over exactly these.
_CONTRACT_FIELDS = (
    "source_product",
    "v1_workbench_id",
    "v1_region",
    "v1_console_host",
    "rule_id",
    "rule_name",
    "event_name",
    "severity",
    "severity_label",
    "mitre_technique",
    "mitre_tactic",
    "threat_category",
    "event_category",
    "timestamp",
    "hostname",
    "username",
    "src_ip",
    "dst_ip",
    "file_hash_sha256",
    "file_hash_sha1",
    "file_path",
    "url",
    "vendor_score",
    "event_description",
)


def test_workbench_dict_field_contract():
    a = ocsf_v1.parse(WORKBENCH_ALERT, customer="acme").to_dict()
    assert a["source_product"] == "visionone"
    assert a["v1_workbench_id"] == "WB-30189-20260621-00042"
    assert a["rule_id"] == "WB-30189-20260621-00042"
    assert a["v1_region"] == "sg"
    assert a["v1_console_host"] == "portal.sg.xdr.trendmicro.com"
    assert a["rule_name"] == "Ransomware activity detected"
    assert a["severity_label"] == "high"
    assert a["mitre_technique"] == "T1486"
    assert a["mitre_tactic"] == "TA0040"
    assert a["threat_category"] == "Suspicious encryption tool"
    assert a["hostname"] == "UNOEXCSRV01"
    assert a["src_ip"] == "10.0.0.5"
    assert "furkan" in (a["username"] or "")
    assert a["file_hash_sha256"] == "a" * 64
    assert a["dst_ip"] == "203.0.113.9"
    assert a["vendor_score"] == 82
    assert "cmdline: vssadmin delete shadows /all" in (a["event_description"] or "")
    assert "impact: 2 servers, 1 accounts" in (a["event_description"] or "")


def test_golden_equivalence_with_vendored_on_dict_path():
    """The native parser must be behaviour-preserving vs the vendored one it
    supersedes on the dict path, over every field downstream reads."""
    from parsers import visionone as vendored  # type: ignore[import-not-found]

    native = ocsf_v1.parse(WORKBENCH_ALERT, customer="acme").to_dict()
    legacy = vendored.parse(WORKBENCH_ALERT, customer="acme").to_dict()
    for f in _CONTRACT_FIELDS:
        msg = f"field {f} diverged: {native.get(f)!r} != {legacy.get(f)!r}"
        assert native.get(f) == legacy.get(f), msg


def test_non_dict_delegates_to_vendored_text_parser():
    """A pasted V1 email (text, the retired forward format) still parses via the
    vendored text fallback and keeps its workbench id for autofetch."""
    text = (
        "Subject: Acme | Workbench | Alert Severity: High\n"
        "Workbench ID: WB-1-20260101-1\n"
        "Model severity: High\n"
    )
    a = ocsf_v1.parse(text, customer="acme").to_dict()
    assert a["source_product"] == "visionone"
    assert a["v1_workbench_id"] == "WB-1-20260101-1"


def test_native_parser_wired_into_routing():
    """parser_adapter routes the visionone source to the native parser."""
    from isoc_api.adapters import ocsf_v1 as native
    from isoc_api.adapters import parser_adapter

    assert parser_adapter._native_parse_fn("visionone") is native.parse
