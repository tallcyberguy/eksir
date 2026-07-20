"""Unit tests for Feature 6 — dashboard trend builders.

The DB-backed /dashboard/trends endpoint is validated on the stack; here we lock
the math (percentiles, top-N + other rollup, pivots, empty-window fallback).
"""

from __future__ import annotations

from isoc_api.analytics import trends as t


# ── percentile ──────────────────────────────────────────────────────────────
def test_percentile_linear_interpolation():
    vals = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert t.percentile(vals, 0.5) == 30.0  # rank 2.0 → vals[2]
    assert t.percentile(vals, 0.9) == 46.0  # rank 3.6 → 40 + 0.6*(50-40)
    assert t.percentile(vals, 0.0) == 10.0
    assert t.percentile(vals, 1.0) == 50.0


def test_percentile_edges():
    assert t.percentile([], 0.5) == 0.0
    assert t.percentile([42.0], 0.9) == 42.0


# ── mttr_trend ──────────────────────────────────────────────────────────────
def test_mttr_trend_per_bucket_percentiles():
    rows = [("2026-07-01", 10), ("2026-07-01", 30), ("2026-07-01", 20), ("2026-07-02", 100)]
    out = t.mttr_trend(rows)
    assert out == [
        {"date": "2026-07-01", "p50": 20.0, "p90": 28.0, "avg": 20.0, "count": 3},
        {"date": "2026-07-02", "p50": 100.0, "p90": 100.0, "avg": 100.0, "count": 1},
    ]


def test_mttr_trend_skips_null_and_empty():
    assert t.mttr_trend([]) == []
    assert t.mttr_trend([("2026-07-01", None)]) == []  # null resolution dropped


# ── source_volume_trend ─────────────────────────────────────────────────────
def test_source_volume_top_n_and_other_rollup():
    rows = [
        ("d1", "X", 3),
        ("d1", "Y", 2),
        ("d1", "Z", 1),
        ("d2", "X", 2),
        ("d2", "Y", 1),
    ]
    out = t.source_volume_trend(rows, top_n=2)
    assert out["sources"] == ["X", "Y", "other"]  # Z (smallest) rolled into other
    assert out["series"] == [
        {"date": "d1", "X": 3, "Y": 2, "other": 1},
        {"date": "d2", "X": 2, "Y": 1, "other": 0},
    ]


def test_source_volume_no_tail_no_other():
    out = t.source_volume_trend([("d1", "X", 1), ("d1", "Y", 1)], top_n=6)
    assert out["sources"] == ["X", "Y"]  # no "other" when nothing is dropped
    assert out["series"] == [{"date": "d1", "X": 1, "Y": 1}]


def test_source_volume_null_source_is_unknown_and_empty():
    out = t.source_volume_trend([("d1", None, 4)])
    assert out["sources"] == ["unknown"]
    assert out["series"] == [{"date": "d1", "unknown": 4}]
    assert t.source_volume_trend([]) == {"sources": [], "series": []}


# ── verdict_mix_trend ───────────────────────────────────────────────────────
def test_verdict_mix_pivot():
    rows = [("d1", "TP", 2), ("d1", "FP", 1), ("d2", "TP", 3)]
    out = t.verdict_mix_trend(rows)
    assert out["verdicts"] == ["FP", "TP"]  # sorted
    assert out["series"] == [
        {"date": "d1", "FP": 1, "TP": 2},
        {"date": "d2", "FP": 0, "TP": 3},
    ]


def test_verdict_mix_empty():
    assert t.verdict_mix_trend([]) == {"verdicts": [], "series": []}
