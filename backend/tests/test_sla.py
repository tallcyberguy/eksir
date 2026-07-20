"""F1 — tests for the SLA duration/breach helpers + lifecycle constants.

`record_sla_event` is DB-backed (validated on the stack); here we lock the pure
metric helpers that SLA Tracking / Team Analytics build on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from isoc_api.pipeline import sla


def test_kinds_include_full_lifecycle():
    assert sla.KINDS == ("detected", "acknowledged", "resolved", "closed")


def test_resolution_seconds_basic():
    t0 = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=21)
    assert sla.resolution_seconds(t0, t1) == 21 * 60


def test_resolution_seconds_missing_endpoint_is_none():
    t0 = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)
    assert sla.resolution_seconds(None, t0) is None
    assert sla.resolution_seconds(t0, None) is None


def test_resolution_seconds_clamped_at_zero():
    t0 = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)
    earlier = t0 - timedelta(minutes=5)  # clock skew: closed before detected
    assert sla.resolution_seconds(t0, earlier) == 0


def test_is_breached():
    assert sla.is_breached(3601, 3600) is True
    assert sla.is_breached(3599, 3600) is False
    assert sla.is_breached(3600, 3600) is False  # exactly on target is not a breach


def test_is_breached_no_target_never_breaches():
    assert sla.is_breached(999999, None) is False
    assert sla.is_breached(999999, 0) is False
    assert sla.is_breached(None, 3600) is False
