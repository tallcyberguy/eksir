"""Unit tests for the Trend Micro Vision One Workbench-alert JSON parser (full-alert extraction).

The vendored parser normally sits on PYTHONPATH (Docker image); we add that path here so it runs
on the host. Verifies the parser mines the full v3.0 alert object (description, structured MITRE
from matchedRules[], all indicators, blast radius, verdict/incident context) — not the ~1/3 it
extracted before.
"""

from __future__ import annotations

import os
import sys

_VENDOR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
)
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

import parsers  # noqa: E402  (vendored; must follow the sys.path insert above)

_WB_ALERT = {
    "id": "WB-1-20260713-00001",
    "workbenchLink": "https://portal.eu.xdr.trendmicro.com/index.html#/workbench/alerts/WB-1",
    "model": "Credential Dumping via Mimikatz",
    "score": 88,
    "severity": "high",
    "description": "Mimikatz-like credential access observed on the host.",
    "alertProvider": "SAE",
    "investigationResult": "True Positive",
    "status": "Open",
    "incidentId": "IC-14558-20260713",
    "createdDateTime": "2026-07-13T10:00:00Z",
    "impactScope": {
        "desktopCount": 0,
        "serverCount": 2,
        "accountCount": 1,
        "entities": [
            {"entityType": "host", "entityValue": {"name": "UNOEXCSRV01", "ips": ["10.0.0.5"]}},
            {"entityType": "account", "entityValue": {"name": "CORP\\admin"}},
        ],
    },
    "matchedRules": [
        {
            "name": "Credential Dumping",
            "matchedFilters": [
                {
                    "name": "Mimikatz",
                    "mitreTechniqueIds": ["T1003.001"],
                    "mitreTacticIds": ["TA0006"],
                }
            ],
        }
    ],
    "indicators": [
        {"type": "command_line", "value": "mimikatz.exe sekurlsa::logonpasswords"},
        {"type": "file_sha256", "value": "a" * 64},
        {"type": "fullpath", "value": "C:\\tools\\mimikatz.exe"},
        {"type": "ip", "value": "203.0.113.9"},
        {"type": "url", "value": "http://evil.example/c2"},
    ],
}


def test_visionone_json_extracts_core_and_structured_fields():
    n = parsers.visionone.parse(_WB_ALERT, customer="acme")
    assert n.source_product == "visionone"
    assert n.v1_workbench_id == "WB-1-20260713-00001"
    assert n.v1_region == "eu"
    assert n.rule_name == "Credential Dumping via Mimikatz"  # model
    assert n.threat_category == "Credential Dumping"  # first matched-rule name
    assert n.event_category == "SAE"  # alertProvider (not the old "V1 score N")
    assert n.severity_label == "high"
    # impactScope entities
    assert n.hostname == "UNOEXCSRV01"
    assert n.src_ip == "10.0.0.5"
    assert n.username == "CORP\\admin"
    # structured MITRE from matchedRules (technique AND tactic — tactic was never set before)
    assert n.mitre_technique == "T1003.001"
    assert n.mitre_tactic == "TA0006"
    # vendor score is now a structured field (feeds pipeline/scoring.py), not just text
    assert n.vendor_score == 88


def test_visionone_json_extracts_all_indicator_types():
    n = parsers.visionone.parse(_WB_ALERT)
    assert n.file_hash_sha256 == "a" * 64
    assert n.file_path == "C:\\tools\\mimikatz.exe"  # from fullpath, NOT the command line
    assert n.dst_ip == "203.0.113.9"  # network IOC (was dropped before)
    assert n.url == "http://evil.example/c2"  # url IOC (was dropped before)


def test_visionone_json_folds_context_into_description():
    n = parsers.visionone.parse(_WB_ALERT)
    desc = n.event_description or ""
    assert "Mimikatz-like credential access" in desc  # the description itself
    assert "V1 score 88" in desc
    assert "True Positive" in desc  # Trend's own verdict (FP/TP prior)
    assert "IC-14558-20260713" in desc  # incident correlation id
    assert "2 servers" in desc and "1 account" in desc  # blast radius
    assert (
        "mimikatz.exe sekurlsa" in desc
    )  # command line (folded here, not misfiled into file_path)


def test_visionone_json_defensive_on_empty():
    n = parsers.visionone.parse({}, customer=None)
    assert n.source_product == "visionone"  # never raises


def test_visionone_email_path_still_parses():
    # the email fallback path is unchanged and still works
    email = (
        "TrendAI Vision One | Workbench | Alert Severity: High\n"
        "Workbench ID: WB-2-20260713-00002\n"
        "Model: Suspicious Activity\n"
        "Model severity: High\n"
        "https://portal.sg.xdr.trendmicro.com/index.html#/workbench/alerts/WB-2\n"
        "Techniques: T1059\n"
    )
    n = parsers.visionone.parse(email)
    assert n.v1_workbench_id == "WB-2-20260713-00002"
    assert n.v1_region == "sg"
    assert n.mitre_technique == "T1059"
