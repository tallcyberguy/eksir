"""LLM cost-cap decision logic (pure). The async DB tally is integration-level."""

from __future__ import annotations

from isoc_api.pipeline import budget


def test_disabled_caps_never_block():
    assert (
        budget.cap_reason(spent_today=1000, spent_incident=1000, daily_cap=0, incident_cap=0)
        is None
    )


def test_daily_cap_blocks_at_or_over_threshold():
    # >= is the boundary: exactly at the cap blocks.
    assert (
        budget.cap_reason(spent_today=5.0, spent_incident=0, daily_cap=5.0, incident_cap=0)
        is not None
    )
    assert (
        budget.cap_reason(spent_today=4.99, spent_incident=0, daily_cap=5.0, incident_cap=0) is None
    )


def test_incident_cap_blocks_independently():
    assert (
        budget.cap_reason(spent_today=0, spent_incident=2.0, daily_cap=0, incident_cap=1.5)
        is not None
    )
    assert (
        budget.cap_reason(spent_today=0, spent_incident=1.0, daily_cap=0, incident_cap=1.5) is None
    )


def test_daily_reason_takes_precedence_and_reads_clearly():
    r = budget.cap_reason(spent_today=10, spent_incident=10, daily_cap=5, incident_cap=5)
    assert r is not None and "daily" in r and "$10.00" in r
