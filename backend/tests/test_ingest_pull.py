"""Pull-ingestion Phase 1: scheduling/dedup helpers, the Vision One adapter
mapping, and the Workbench-JSON parser branch.

Pure unit tests — no Postgres/Redis/LLM. The vendored parsers live in
alert-memory-mcp (stdlib-only); we add its dir to sys.path the same way
test_parser_hashes.py does.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from isoc_api.pipeline import ingest_sources as ih

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


# ── scheduling / backoff ────────────────────────────────────────────────
def test_is_due_cold_start_when_never_polled():
    assert ih.is_due(interval_seconds=300, consecutive_errors=0, last_poll_at=None, now=NOW) is True


def test_is_due_false_before_interval_elapses():
    lp = NOW - timedelta(seconds=100)
    assert ih.is_due(interval_seconds=300, consecutive_errors=0, last_poll_at=lp, now=NOW) is False


def test_is_due_true_after_interval_elapses():
    lp = NOW - timedelta(seconds=301)
    assert ih.is_due(interval_seconds=300, consecutive_errors=0, last_poll_at=lp, now=NOW) is True


def test_backoff_multiplies_and_caps_at_8x():
    assert ih.effective_interval(300, 0) == 300
    assert ih.effective_interval(300, 1) == 600
    assert ih.effective_interval(300, 3) == 2400
    assert ih.effective_interval(300, 10) == 2400  # 2**10 capped to 8


def test_backoff_delays_due_after_error():
    # One error -> 600s interval; 400s elapsed is not yet due.
    lp = NOW - timedelta(seconds=400)
    assert ih.is_due(interval_seconds=300, consecutive_errors=1, last_poll_at=lp, now=NOW) is False


def test_is_due_handles_naive_last_poll():
    lp = (NOW - timedelta(seconds=301)).replace(tzinfo=None)
    assert ih.is_due(interval_seconds=300, consecutive_errors=0, last_poll_at=lp, now=NOW) is True


# ── severity floor ──────────────────────────────────────────────────────
def test_severity_floor():
    assert ih.severity_passes("high", "medium") is True
    assert ih.severity_passes("low", "medium") is False
    assert ih.severity_passes("critical", "critical") is True
    assert ih.severity_passes("info", "low") is False
    assert ih.severity_passes(None, None) is True  # no floor accepts everything
    assert ih.severity_passes("high", None) is True


# ── dedup key ───────────────────────────────────────────────────────────
def test_dedup_key_shape_and_no_cross_provider_collision():
    assert ih.dedup_key("vision_one", "WB-1") == "ingest:seen:vision_one:WB-1"
    assert ih.dedup_key("vision_one", "a") != ih.dedup_key("sentinelone", "a")


# ── Vision One adapter mapping ──────────────────────────────────────────
async def test_vision_one_adapter_maps_raw_alerts(monkeypatch):
    from isoc_api.adapters.ingest import vision_one

    sample = [{"id": "WB-1", "severity": "high", "createdDateTime": "2026-07-10T00:00:00Z"}]
    captured: dict = {}

    async def fake_list(**kwargs):
        captured.update(kwargs)
        return sample

    monkeypatch.setattr(vision_one.v1_adapter, "list_workbench_alerts", fake_list)

    creds = SimpleNamespace(api_key="k", region="eu")
    res = await vision_one.VisionOneIngestAdapter().fetch(creds=creds, cursor={}, max_items=50)

    assert len(res.alerts) == 1
    a = res.alerts[0]
    assert a["external_id"] == "WB-1"
    assert a["source_hint"] == "visionone"
    assert a["original"] is sample[0]
    assert a["severity"] == "high"
    # cold start passes region/api_key through and advances the cursor.
    assert captured["region"] == "eu"
    assert captured["api_key"] == "k"
    assert "start" in captured
    assert "last_poll_at" in res.cursor


async def test_vision_one_adapter_skips_alerts_without_id(monkeypatch):
    from isoc_api.adapters.ingest import vision_one

    async def fake_list(**kwargs):
        return [{"severity": "high"}, {"id": "WB-2"}]

    monkeypatch.setattr(vision_one.v1_adapter, "list_workbench_alerts", fake_list)
    res = await vision_one.VisionOneIngestAdapter().fetch(
        creds=SimpleNamespace(api_key="k", region="us"), cursor={}, max_items=50
    )
    assert [a["external_id"] for a in res.alerts] == ["WB-2"]


# ── Workbench-JSON parser branch (vendored parsers) ─────────────────────
def _add_vendored_path() -> None:
    p = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
    )
    if p not in sys.path:
        sys.path.insert(0, p)


_WB_JSON = {
    "id": "WB-30189-20260526-00008",
    "model": "Credential Dumping via Mimikatz",
    "score": 68,
    "severity": "high",
    "createdDateTime": "2026-05-26T20:47:56Z",
    "workbenchLink": "https://portal.eu.xdr.trendmicro.com/index.html#/workbench/alerts/WB-30189",
    "impactScope": {
        "entities": [
            {"entityType": "host", "entityValue": {"name": "UNOEXCSRV01", "ips": ["10.0.0.5"]}},
            {"entityType": "account", "entityValue": "CORP\\jdoe"},
        ]
    },
    "matchedRules": [{"id": "r1", "name": "Mimikatz", "techniques": [{"id": "T1003"}]}],
    "indicators": [
        {"type": "command_line", "value": "mimikatz.exe sekurlsa::logonpasswords"},
        {"type": "file_sha256", "value": "A" * 64},
    ],
}


def test_detect_source_routes_workbench_json_to_visionone():
    _add_vendored_path()
    import parsers

    assert parsers.detect_source(_WB_JSON) == "visionone"
    # A wazuh dict must still route to wazuh (no regression).
    assert parsers.detect_source({"rule": {"id": "5710"}, "agent": {"name": "srv"}}) == "wazuh"


def test_workbench_json_parses_to_rich_normalized_alert():
    _add_vendored_path()
    import parsers

    alert = parsers.parse(_WB_JSON)
    d = alert.to_dict()

    assert d["source_product"] == "visionone"
    assert d["rule_name"] == "Credential Dumping via Mimikatz"
    assert d["severity"] == 9  # V1 "high" -> Wazuh-scale 9
    assert d["v1_workbench_id"] == "WB-30189-20260526-00008"
    assert d["v1_region"] == "eu"
    assert d["hostname"] == "UNOEXCSRV01"
    assert d["src_ip"] == "10.0.0.5"
    assert "jdoe" in (d["username"] or "")
    assert d["mitre_technique"] == "T1003"
    assert d["file_hash_sha256"] == "a" * 64
    # Full-alert extraction (2026-07): the score moved into the description (event_category is now
    # the alertProvider, unset in this fixture); the matched-rule name becomes threat_category; and
    # the command line is folded into the description rather than misfiled into file_path.
    assert "V1 score 68" in (d.get("event_description") or "")
    assert d.get("threat_category") == "Mimikatz"
    assert d.get("file_path") is None
    assert "mimikatz.exe" in (d.get("event_description") or "")


# ── source health / staleness (observability) ───────────────────────────
def test_source_health_states():
    now = NOW
    h = ih.source_health
    assert (
        h(enabled=False, interval_seconds=300, consecutive_errors=0, last_success_at=None, now=now)
        == "disabled"
    )
    assert (
        h(enabled=True, interval_seconds=300, consecutive_errors=2, last_success_at=now, now=now)
        == "error"
    )
    assert (
        h(enabled=True, interval_seconds=300, consecutive_errors=0, last_success_at=None, now=now)
        == "pending"
    )
    assert (
        h(
            enabled=True,
            interval_seconds=300,
            consecutive_errors=0,
            last_success_at=now - timedelta(seconds=60),
            now=now,
        )
        == "ok"
    )
    # last success older than max(3*300, 600) = 900s -> stale
    assert (
        h(
            enabled=True,
            interval_seconds=300,
            consecutive_errors=0,
            last_success_at=now - timedelta(seconds=1000),
            now=now,
        )
        == "stale"
    )


def test_is_stale_grace_and_guards():
    now = NOW
    # short interval: threshold = max(3*60, 600) = 600s
    assert (
        ih.is_stale(
            enabled=True, interval_seconds=60, last_success_at=now - timedelta(seconds=700), now=now
        )
        is True
    )
    assert (
        ih.is_stale(
            enabled=True, interval_seconds=60, last_success_at=now - timedelta(seconds=500), now=now
        )
        is False
    )
    assert ih.is_stale(enabled=True, interval_seconds=60, last_success_at=None, now=now) is False
    assert (
        ih.is_stale(
            enabled=False,
            interval_seconds=60,
            last_success_at=now - timedelta(seconds=9999),
            now=now,
        )
        is False
    )
