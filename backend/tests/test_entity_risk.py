"""Unit tests for the rolling entity-risk scorer (pipeline/entity_risk.py).

Pure functions — no stack. Pins the design stance: confirmed-TP-only, 30-day
half-life decay, saturating noisy-OR combine, None (not 0) for no history.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from isoc_api.pipeline.entity_risk import HALF_LIFE_DAYS, compute_entity_risk

NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


def _inc(verdict: str, threat: float | None = None, age_days: float = 0.0) -> dict:
    return {
        "verdict": verdict,
        "threat_score": threat,
        "created_at": NOW - timedelta(days=age_days),
    }


def test_no_history_is_none_not_zero():
    assert compute_entity_risk([], now=NOW) is None
    # FP/benign/pending noise never creates risk — still unscored.
    assert (
        compute_entity_risk([_inc("FP", 80), _inc("benign", 90), _inc("pending", 70)], now=NOW)
        is None
    )


def test_single_fresh_tp_equals_its_threat():
    assert compute_entity_risk([_inc("TP", 80)], now=NOW) == 80.0
    # verdict casing tolerated
    assert compute_entity_risk([_inc("tp", 40)], now=NOW) == 40.0


def test_missing_threat_falls_back_to_default():
    assert compute_entity_risk([_inc("TP", None)], now=NOW) == 50.0


def test_half_life_decay():
    # One half-life halves the weight; two quarters it.
    assert compute_entity_risk([_inc("TP", 80, age_days=HALF_LIFE_DAYS)], now=NOW) == 40.0
    assert compute_entity_risk([_inc("TP", 80, age_days=2 * HALF_LIFE_DAYS)], now=NOW) == 20.0


def test_noisy_or_saturates_below_100():
    two = compute_entity_risk([_inc("TP", 80), _inc("TP", 80)], now=NOW)
    assert two == 96.0  # 100·(1 − 0.2·0.2)
    many = compute_entity_risk([_inc("TP", 90)] * 10, now=NOW)
    assert many is not None and 99.0 <= many <= 100.0  # asymptote, never a blowup


def test_fp_noise_does_not_dilute_tp_history():
    tp_only = compute_entity_risk([_inc("TP", 70)], now=NOW)
    with_noise = compute_entity_risk([_inc("TP", 70), _inc("FP", 90), _inc("benign", 90)], now=NOW)
    assert tp_only == with_noise


def test_garbage_inputs_never_raise():
    r = compute_entity_risk(
        [
            {"verdict": "TP", "threat_score": "not-a-number"},  # -> default 50
            {"verdict": "TP", "created_at": "also-not-a-date"},  # -> fresh, default 50
            {"verdict": None},
            {},
        ],
        now=NOW,
    )
    # Both malformed TPs fall back to the 50 default: 100·(1 − 0.5·0.5) = 75.
    assert r == 75.0


def test_iso_string_and_naive_datetimes_accepted():
    iso = compute_entity_risk(
        [{"verdict": "TP", "threat_score": 60, "created_at": NOW.isoformat()}], now=NOW
    )
    assert iso == 60.0
    naive = compute_entity_risk(
        [{"verdict": "TP", "threat_score": 60, "created_at": NOW.replace(tzinfo=None)}], now=NOW
    )
    assert naive == 60.0
    missing = compute_entity_risk([{"verdict": "TP", "threat_score": 60}], now=NOW)
    assert missing == 60.0  # no timestamp -> treated as fresh (conservative-high)
