"""SLA Tracking — targets resolution + the pure dashboard builder."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from isoc_api.pipeline import sla

UTC = timezone.utc
NOW = datetime(2026, 6, 28, 12, 0, 0, tzinfo=UTC)


def _closed(sev: str, resolution_min: int, case: str) -> dict:
    return {
        "severity": sev,
        "created_at": NOW - timedelta(minutes=resolution_min),
        "closed_at": NOW,
        "case_number": case,
    }


# ── targets ────────────────────────────────────────────────────────────────


def test_effective_targets_defaults():
    assert sla.effective_targets(None) == sla.DEFAULT_TARGET_MINUTES


def test_effective_targets_overrides_and_filters():
    t = sla.effective_targets({"critical": 30, "bogus": 5, "high": 0})
    assert t["critical"] == 30  # override applied
    assert t["high"] == sla.DEFAULT_TARGET_MINUTES["high"]  # zero ignored
    assert "bogus" not in t  # unknown severity dropped


# ── dashboard builder ────────────────────────────────────────────────────


def test_build_sla_dashboard_breaches_and_severity():
    targets = sla.effective_targets(None)  # crit 60, high 240, med 1440, low 4320
    closed = [
        _closed("critical", 30, "C-1"),  # on-time
        _closed("critical", 90, "C-2"),  # breach (>60)
        _closed("high", 300, "C-3"),  # breach (>240)
        _closed("medium", 60, "C-4"),  # on-time
    ]
    open_cases = [
        {
            "severity": "critical",
            "created_at": NOW - timedelta(minutes=200),
            "case_number": "O-1",
        },  # overdue
        {
            "severity": "low",
            "created_at": NOW - timedelta(minutes=10),
            "case_number": "O-2",
        },  # fine
    ]
    out = sla.build_sla_dashboard(closed, open_cases, targets, window_days=30, now=NOW)

    assert out["total_closed"] == 4
    assert out["on_time"] == 2
    assert out["breached"] == 2
    assert out["breach_rate"] == 0.5
    assert out["on_time_rate"] == 0.5

    crit = next(s for s in out["by_severity"] if s["severity"] == "critical")
    assert crit["closed"] == 2 and crit["on_time"] == 1 and crit["breached"] == 1
    assert crit["avg_resolution_minutes"] == 60  # (30 + 90) / 2

    overdue_cases = {o["case_number"] for o in out["open_overdue"]}
    assert "O-1" in overdue_cases and "O-2" not in overdue_cases
    assert len(out["recent_breaches"]) == 2


def test_build_sla_dashboard_empty():
    out = sla.build_sla_dashboard([], [], sla.effective_targets(None), window_days=7, now=NOW)
    assert out["total_closed"] == 0
    assert out["breach_rate"] == 0.0
    assert out["avg_resolution_minutes"] is None
    assert len(out["by_severity"]) == 4  # always all four severities


def test_build_sla_dashboard_all_severities_present():
    out = sla.build_sla_dashboard([], [], sla.effective_targets(None), window_days=30, now=NOW)
    assert [s["severity"] for s in out["by_severity"]] == ["critical", "high", "medium", "low"]


# ── response-time SLA ────────────────────────────────────────────────────────


def test_response_seconds():
    c = datetime(2026, 1, 1, tzinfo=UTC)
    assert sla.response_seconds(c, c + timedelta(minutes=5)) == 300
    assert sla.response_seconds(None, c) is None
    assert sla.response_seconds(c, c - timedelta(minutes=5)) == 0  # clamped at 0


def test_effective_response_targets_defaults_and_overrides():
    assert sla.effective_response_targets(None) == sla.DEFAULT_RESPONSE_MINUTES
    t = sla.effective_response_targets({"high": 90, "bogus": 5, "low": 0})
    assert t["high"] == 90  # override applied
    assert t["low"] == sla.DEFAULT_RESPONSE_MINUTES["low"]  # zero ignored
    assert "bogus" not in t


def _open(sev: str, age_min: int, case: str, claimed_after: int | None = None) -> dict:
    created = NOW - timedelta(minutes=age_min)
    d = {"severity": sev, "created_at": created, "case_number": case}
    if claimed_after is not None:
        d["claimed_at"] = created + timedelta(minutes=claimed_after)
    return d


def test_build_sla_dashboard_response_section():
    rt = sla.effective_response_targets(None)  # crit 15, high 120, med 480, low 1440
    closed = [
        {**_open("high", 300, "C-1", claimed_after=30), "closed_at": NOW},  # 30m ≤120 on-time
        {**_open("high", 300, "C-2", claimed_after=200), "closed_at": NOW},  # 200m >120 breach
        {**_open("critical", 60, "C-3"), "closed_at": NOW},  # no claim → close@60m >15 breach
    ]
    open_cases = [
        _open("high", 200, "O-1"),  # unclaimed 200m > 120 → awaiting_overdue
        _open("high", 30, "O-2"),  # unclaimed 30m < 120 → fine
        _open("critical", 60, "O-3", claimed_after=5),  # claimed@5m ≤15 → responded on-time
    ]
    out = sla.build_sla_dashboard(
        closed,
        open_cases,
        sla.effective_targets(None),
        window_days=30,
        now=NOW,
        response_targets=rt,
    )
    r = out["response"]
    assert r["total_responded"] == 4  # 3 closed + 1 claimed-open
    assert r["on_time"] == 2  # C-1, O-3
    assert r["breached"] == 2  # C-2, C-3
    awaiting = {a["case_number"] for a in r["awaiting_overdue"]}
    assert "O-1" in awaiting and "O-2" not in awaiting
    hi = next(s for s in r["by_severity"] if s["severity"] == "high")
    assert hi["responded"] == 2 and hi["on_time"] == 1 and hi["breached"] == 1
    # resolution half is unchanged / independent of the response half
    assert out["total_closed"] == 3
