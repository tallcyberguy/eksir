"""Unit tests for Team Analytics pure scoring (`analytics/scoring.py`)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from isoc_api.analytics import scoring

NOW = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)


def _rows(analyst, n, *, dur_min=120, flips=0, name=None):
    out = []
    for i in range(n):
        out.append(
            {
                "analyst_id": analyst,
                "analyst_name": name or f"A-{str(analyst)[:4]}",
                "created_at": NOW - timedelta(minutes=dur_min + i),
                "signed_off_at": NOW - timedelta(minutes=i),
                "verdict": "TP",
                "was_flipped": i < flips,
            }
        )
    return out


# ── primitives ────────────────────────────────────────────────────────────
def test_speed_score_clamps():
    assert scoring.speed_score(120) == 1.0
    assert scoring.speed_score(scoring.SPEED_REF_MIN) == 1.0
    assert scoring.speed_score(scoring.SPEED_FLOOR_MIN) == 0.0
    assert scoring.speed_score(None) == 0.0
    mid = (scoring.SPEED_REF_MIN + scoring.SPEED_FLOOR_MIN) / 2
    assert abs(scoring.speed_score(mid) - 0.5) < 1e-6


def test_volume_score():
    assert scoring.volume_score(5, 10) == 0.5
    assert scoring.volume_score(10, 10) == 1.0
    assert scoring.volume_score(3, 0) == 0.0


def test_composite_all_ones_is_100():
    assert scoring.composite_score(accuracy=1.0, volume_norm=1.0, speed=1.0) == 100.0
    assert scoring.composite_score(accuracy=0.0, volume_norm=0.0, speed=0.0) == 0.0


def test_median():
    assert scoring.median([3, 1, 2]) == 2
    assert scoring.median([4, 1, 2, 3]) == 2.5
    assert scoring.median([]) is None


# ── leaderboard ───────────────────────────────────────────────────────────
def test_groups_and_ranks_by_score_then_cases():
    a, b = uuid.uuid4(), uuid.uuid4()
    rows = _rows(a, 10, name="Alex") + _rows(b, 8, name="Bo", flips=4)
    out = scoring.build_leaderboard(rows, window_days=30, now=NOW)
    assert [x["analyst_name"] for x in out["analysts"]] == ["Alex", "Bo"]  # Alex cleaner+busier
    assert out["team"]["cases"] == 18
    assert out["team"]["analyst_count"] == 2


def test_flip_rate_and_accuracy():
    a = uuid.uuid4()
    out = scoring.build_leaderboard(_rows(a, 10, flips=2), window_days=30, now=NOW)
    me = out["analysts"][0]
    assert me["flip_rate"] == 0.2
    assert me["accuracy"] == 0.8


def test_min_volume_floor_routes_to_provisional():
    a, b = uuid.uuid4(), uuid.uuid4()
    rows = _rows(a, 10, name="Ranked") + _rows(b, 3, name="New")
    out = scoring.build_leaderboard(rows, window_days=30, now=NOW)
    assert [x["analyst_name"] for x in out["analysts"]] == ["Ranked"]
    assert [x["analyst_name"] for x in out["provisional"]] == ["New"]


def test_empty_rows_is_zeroed_not_crash():
    out = scoring.build_leaderboard([], window_days=30, now=NOW)
    assert out["analysts"] == []
    assert out["provisional"] == []
    assert out["highlights"] == []
    assert out["team"] == {"cases": 0, "median_minutes": None, "flip_rate": 0.0, "analyst_count": 0}


def test_badge_zero_fp_requires_clean_twenty():
    a, b = uuid.uuid4(), uuid.uuid4()
    clean = scoring.build_leaderboard(_rows(a, 20), window_days=30, now=NOW)
    keys = {bd["key"] for bd in clean["analysts"][0]["badges"]}
    assert "zero_fp" in keys
    flipped = scoring.build_leaderboard(_rows(b, 20, flips=1), window_days=30, now=NOW)
    assert "zero_fp" not in {bd["key"] for bd in flipped["analysts"][0]["badges"]}


def test_quick_draw_is_volume_gated():
    # 6 fast cases (≥MIN_VOLUME so ranked, but <10) must NOT earn quick_draw.
    a = uuid.uuid4()
    out = scoring.build_leaderboard(_rows(a, 6, dur_min=30), window_days=30, now=NOW)
    assert "quick_draw" not in {b["key"] for b in out["analysts"][0]["badges"]}


def test_tie_break_higher_cases_first():
    # Two analysts, identical clean accuracy + speed; the busier one ranks first.
    a, b = uuid.uuid4(), uuid.uuid4()
    rows = _rows(a, 10, name="Busy") + _rows(b, 6, name="Light")
    out = scoring.build_leaderboard(rows, window_days=30, now=NOW)
    assert out["analysts"][0]["analyst_name"] == "Busy"


def test_badge_tones_are_known_tokens():
    a = uuid.uuid4()
    out = scoring.build_leaderboard(_rows(a, 20), window_days=30, now=NOW)
    for bd in out["analysts"][0]["badges"]:
        assert bd["tone"] in {"positive", "accent", "warning"}
