"""Unit tests for the CrowdStrike + Microsoft Defender parsers and ingest severity mapping.

The vendored parsers/normalizer normally sit on PYTHONPATH (set in the Docker image); we add that
path here so the parser tests run on the host like the other pure tests.
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


# ── CrowdStrike parser ──────────────────────────────────────────────────
def test_crowdstrike_parser_maps_core_fields():
    alert = {
        "composite_id": "abc:ind:123",
        "created_timestamp": "2026-07-13T10:00:00Z",
        "severity": 90,
        "severity_name": "Critical",
        "display_name": "Malicious file execution",
        "description": "A known-bad binary ran",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059.001",
        "objective": "Falcon Detection Method",
        "cmdline": "powershell -enc SQBFAFgA",
        "device": {"hostname": "WIN-01", "external_ip": "203.0.113.5", "user_name": "alice"},
        "sha256": "a" * 64,
        "sha1": "c" * 40,
        "filepath": "C:\\bad.exe",
    }
    n = parsers.crowdstrike.parse(alert, customer="acme")
    assert n.source_product == "crowdstrike"
    assert n.rule_name == "Malicious file execution"
    assert n.severity_label == "critical"  # severity_name Critical -> 14 -> critical
    assert n.hostname == "WIN-01"
    assert n.username == "alice"
    assert n.src_ip == "203.0.113.5"
    assert n.file_hash_sha256 == "a" * 64
    assert n.file_hash_sha1 == "c" * 40  # sha1 now mapped
    assert n.mitre_technique == "T1059.001"
    assert n.mitre_tactic == "TA0002"  # tactic_id now mapped
    assert n.event_category == "Falcon Detection Method"  # objective -> event_category
    assert "powershell -enc" in (n.event_description or "")  # cmdline folded in


def test_crowdstrike_parser_severity_from_score_when_no_name():
    n = parsers.crowdstrike.parse({"severity": 50})
    assert n.severity_label == "medium"  # 40-59 -> 6 -> medium


def test_crowdstrike_parser_defensive_on_empty():
    n = parsers.crowdstrike.parse({}, customer=None)
    assert n.source_product == "crowdstrike"  # never raises


# ── Microsoft Defender parser ───────────────────────────────────────────
def test_defender_parser_maps_evidence_array():
    alert = {
        "id": "da-1",
        "title": "Suspicious PowerShell",
        "severity": "high",
        "categories": ["Execution"],  # current field (category is deprecated)
        "createdDateTime": "2026-07-13T09:00:00Z",
        "description": "Encoded command",
        "mitreTechniques": ["T1059.001"],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName": "host1.corp",
            },
            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "198.51.100.7"},
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {"accountName": "bob"},
            },
            {
                "@odata.type": "#microsoft.graph.security.fileEvidence",
                "fileDetails": {"sha256": "b" * 64, "fileName": "p.ps1"},
            },
        ],
    }
    n = parsers.microsoft_defender.parse(alert, customer="acme")
    assert n.source_product == "microsoft_defender"
    assert n.rule_name == "Suspicious PowerShell"
    assert n.severity_label == "high"  # high -> 10 -> high
    assert n.hostname == "host1.corp"
    assert n.src_ip == "198.51.100.7"
    assert n.username == "bob"
    assert n.file_hash_sha256 == "b" * 64
    assert n.mitre_technique == "T1059.001"
    assert n.threat_category == "Execution"  # from categories[0]


def test_defender_parser_process_evidence_and_hostname_fallback():
    # deviceEvidence with no deviceDnsName -> falls back to hostName (not the dead computerDnsName);
    # processEvidence.imageFile carries the primary hash + the command line.
    alert = {
        "id": "da-2",
        "title": "Malware",
        "severity": "medium",
        "createdDateTime": "2026-07-13T09:00:00Z",
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence", "hostName": "short01"},
            {
                "@odata.type": "#microsoft.graph.security.processEvidence",
                "imageFile": {"sha256": "d" * 64, "filePath": "C:\\evil.exe"},
                "processCommandLine": "evil.exe -run",
                "userAccount": {"accountName": "svc"},
            },
        ],
    }
    n = parsers.microsoft_defender.parse(alert)
    assert n.hostname == "short01"
    assert n.file_hash_sha256 == "d" * 64
    assert n.file_path == "C:\\evil.exe"
    assert n.username == "svc"
    assert "evil.exe -run" in (n.event_description or "")


def test_defender_parser_defensive_on_empty():
    n = parsers.microsoft_defender.parse({}, customer=None)
    assert n.source_product == "microsoft_defender"


# ── ingest severity floor helpers (pure) ────────────────────────────────
def test_ingest_severity_words():
    from isoc_api.adapters.ingest.crowdstrike import _severity_word as cs_sev
    from isoc_api.adapters.ingest.microsoft_defender import _severity_word as df_sev

    assert cs_sev({"severity_name": "High"}) == "high"
    assert cs_sev({"severity": 85}) == "critical"
    assert cs_sev({}) is None
    assert df_sev({"severity": "medium"}) == "medium"
    assert df_sev({"severity": "informational"}) == "low"
    assert df_sev({}) is None
