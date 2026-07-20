"""Unit tests for local-feed IOC confidence scoring (`threat_intel/scoring.py`)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from isoc_api.threat_intel import scoring

NOW = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


# ── corroboration ─────────────────────────────────────────────────────────
def test_corroboration_saturating_curve():
    assert scoring.corroboration_score(0) == 0.0
    assert scoring.corroboration_score(1) == 0.5
    assert scoring.corroboration_score(2) == 0.75
    assert round(scoring.corroboration_score(3), 3) == 0.875
    # Monotonic, never exceeds 1.
    seq = [scoring.corroboration_score(n) for n in range(0, 10)]
    assert seq == sorted(seq)
    assert max(seq) <= 1.0


# ── recency ───────────────────────────────────────────────────────────────
def test_recency_decays_by_half_life():
    assert scoring.recency_score(_iso(0), now=NOW) == 1.0
    assert abs(scoring.recency_score(_iso(30), now=NOW) - 0.5) < 1e-6
    assert abs(scoring.recency_score(_iso(60), now=NOW) - 0.25) < 1e-6


def test_recency_floor_and_missing():
    # Ancient → floored, not zero.
    assert scoring.recency_score(_iso(3650), now=NOW) == scoring.RECENCY_FLOOR
    # Missing / unparseable timestamps → floor.
    assert scoring.recency_score(None, now=NOW) == scoring.RECENCY_FLOOR
    assert scoring.recency_score("not-a-date", now=NOW) == scoring.RECENCY_FLOOR


def test_recency_accepts_datetime_and_naive():
    aware = NOW - timedelta(days=30)
    naive = aware.replace(tzinfo=None)  # treated as UTC
    assert abs(scoring.recency_score(naive, now=NOW) - 0.5) < 1e-6


# ── reputation ────────────────────────────────────────────────────────────
def test_reputation_multi_source_fresh_is_high():
    rep = scoring.reputation(4, _iso(0), now=NOW)
    assert rep["band"] == "high"
    assert rep["sources"] == 4
    assert rep["score"] >= scoring.BAND_HIGH


def test_reputation_single_stale_is_low():
    rep = scoring.reputation(1, _iso(365), now=NOW)
    assert rep["band"] == "low"
    assert rep["score"] < scoring.BAND_MEDIUM


def test_reputation_score_clamped_unit_interval():
    for n in (0, 1, 5, 50):
        for d in (0, 30, 9999):
            s = scoring.reputation_score(n, _iso(d), now=NOW)
            assert 0.0 <= s <= 1.0


# ── match scoring (alert hit) ─────────────────────────────────────────────
def test_parent_domain_match_is_discounted_vs_exact():
    base = {"value": "bad.example.com", "sources": ["f1", "f2", "f3"], "last_seen_at": _iso(1)}
    exact = scoring.score_match({**base, "match_kind": "exact"}, now=NOW)
    parent = scoring.score_match({**base, "match_kind": "parent_domain"}, now=NOW)
    assert parent["score"] < exact["score"]
    # Same reputation underneath; only the kind weight differs.
    assert parent["reputation"] == exact["reputation"]
    # Input not mutated.
    assert "score" not in base


def test_summarize_picks_strongest_and_counts():
    matches = [
        {
            "value": "9.9.9.9",
            "ioc_type": "ip",
            "match_kind": "exact",
            "sources": ["f1", "f2", "f3"],
            "last_seen_at": _iso(0),
        },  # strong
        {
            "value": "old.example.com",
            "ioc_type": "domain",
            "match_kind": "parent_domain",
            "sources": ["f1"],
            "last_seen_at": _iso(400),
        },  # weak
    ]
    out = scoring.summarize(matches, now=NOW)
    assert out["match_count"] == 2
    assert out["exact_matches"] == 1
    assert out["distinct_sources"] == 3  # f1,f2,f3 deduped across matches
    assert out["band"] == "high"
    # Strongest first.
    assert out["matches"][0]["value"] == "9.9.9.9"
    assert out["score"] == out["matches"][0]["score"]


def test_summarize_empty_is_zero_low():
    out = scoring.summarize([], now=NOW)
    assert out == {
        "score": 0.0,
        "band": "low",
        "match_count": 0,
        "exact_matches": 0,
        "distinct_sources": 0,
        "matches": [],
    }
