"""SentinelOne pull adapter + threat-JSON parser.

Pure unit tests. The vendored parsers live in alert-memory-mcp (stdlib-only); we
add its dir to sys.path the same way test_parser_hashes.py does.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace


def _add_vendored_path() -> None:
    p = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
    )
    if p not in sys.path:
        sys.path.insert(0, p)


_S1_THREAT = {
    "id": "1234567890",
    "threatInfo": {
        "threatName": "mimikatz.exe",
        "classification": "Malware",
        "confidenceLevel": "malicious",
        "createdAt": "2026-07-10T12:00:00.000000Z",
        "sha1": "b" * 40,
        "sha256": "a" * 64,
        "filePath": "C:\\Users\\jdoe\\mimikatz.exe",
        "processUser": "CORP\\jdoe",
    },
    "agentRealtimeInfo": {"agentComputerName": "WIN-EP01", "agentOsName": "Windows 10"},
    "agentDetectionInfo": {"agentIpV4": "10.0.0.9", "agentLastLoggedInUserName": "jdoe"},
    "indicators": [{"tactics": [{"name": "Credential Access", "techniques": [{"name": "T1003"}]}]}],
}


# ── parser ──────────────────────────────────────────────────────────────
def test_detect_source_routes_s1_threat_json():
    _add_vendored_path()
    import parsers

    assert parsers.detect_source(_S1_THREAT) == "sentinelone"
    # A Vision One workbench dict still routes to visionone (no regression).
    assert parsers.detect_source({"id": "WB-1", "impactScope": {}, "model": "x"}) == "visionone"


def test_s1_threat_parses_to_normalized_alert():
    _add_vendored_path()
    import parsers

    d = parsers.parse(_S1_THREAT).to_dict()
    assert d["source_product"] == "sentinelone"
    assert d["rule_name"] == "mimikatz.exe"
    assert d["severity"] == 10  # confidenceLevel "malicious"
    assert d["threat_category"] == "Malware"
    assert d["hostname"] == "WIN-EP01"
    assert "jdoe" in (d["username"] or "")
    assert d["src_ip"] == "10.0.0.9"
    assert d["file_hash_sha256"] == "a" * 64
    assert d["file_hash_sha1"] == "b" * 40
    assert d["mitre_technique"] == "T1003"


# ── ingest adapter ──────────────────────────────────────────────────────
async def test_s1_adapter_maps_threats(monkeypatch):
    from isoc_api.adapters.ingest import sentinelone as s1i

    sample = [
        {
            "id": "t1",
            "threatInfo": {
                "confidenceLevel": "suspicious",
                "createdAt": "2026-07-10T00:00:00.000000Z",
            },
        },
    ]
    captured: dict = {}

    async def fake_list(**kwargs):
        captured.update(kwargs)
        return sample

    monkeypatch.setattr(s1i.sentinelone_adapter, "list_threats", fake_list)

    creds = SimpleNamespace(base_url="https://c.sentinelone.net", api_key="tok")
    res = await s1i.SentinelOneIngestAdapter().fetch(creds=creds, cursor={}, max_items=50)

    assert len(res.alerts) == 1
    a = res.alerts[0]
    assert a["external_id"] == "t1"
    assert a["source_hint"] == "sentinelone"
    assert a["severity"] == "medium"  # suspicious -> medium
    assert captured["base_url"] == "https://c.sentinelone.net"
    assert captured["api_key"] == "tok"  # pragma: allowlist secret
    assert "since" in captured
    assert "last_poll_at" in res.cursor


def test_s1_severity_word():
    from isoc_api.adapters.ingest import sentinelone as s1i

    assert s1i._severity_word({"threatInfo": {"confidenceLevel": "malicious"}}) == "high"
    assert s1i._severity_word({"threatInfo": {"confidenceLevel": "suspicious"}}) == "medium"
    assert s1i._severity_word({"threatInfo": {"confidenceLevel": "n/a"}}) is None
    assert s1i._severity_word({}) is None


def test_s1_registered_and_pullable():
    from isoc_api.adapters.ingest import get_adapter

    assert get_adapter("sentinelone") is not None
