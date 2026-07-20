"""Unit tests for the MITRE Coverage route's pure builder (`build_coverage`)."""

from __future__ import annotations

from isoc_api.routes.mitre import build_coverage


def _enr(techniques: list[str]) -> dict:
    """An incident enrichment blob shaped the way the L2 persona emits it."""
    return {"stages": {"l2": {"mitre_techniques": techniques}}}


def test_empty_yields_zero_coverage_but_full_tactic_axis():
    out = build_coverage([], window_days=90, confirmed_only=True)
    assert out["incident_count"] == 0
    assert out["technique_count"] == 0
    assert out["tactic_count"] == 14
    assert out["covered_tactic_count"] == 0
    # All 14 tactics are still present as an axis, just empty.
    assert len(out["tactics"]) == 14
    assert all(t["technique_count"] == 0 for t in out["tactics"])
    assert out["window_days"] == 90
    assert out["confirmed_only"] is True


def test_covered_tactic_count_counts_distinct_tactics():
    # T1059 → Execution (TA0002); T1486 → Impact (TA0040). Two distinct tactics.
    out = build_coverage(
        [_enr(["T1059", "T1486"]), _enr(["T1059"])],
        window_days=30,
        confirmed_only=False,
    )
    assert out["incident_count"] == 2
    assert out["technique_count"] == 2  # distinct techniques
    assert out["occurrence_count"] == 3  # T1059 twice + T1486 once
    assert out["covered_tactic_count"] == 2
    assert out["confirmed_only"] is False

    by_id = {t["tactic_id"]: t for t in out["tactics"]}
    exec_techs = {tt["id"]: tt["count"] for tt in by_id["TA0002"]["techniques"]}
    assert exec_techs["T1059"] == 2


def test_subtechnique_rolls_up_to_parent_and_meta_threads_through():
    # T1059.001 (PowerShell) must roll up under its parent T1059 / Execution.
    out = build_coverage([_enr(["T1059.001"])], window_days=7, confirmed_only=True)
    by_id = {t["tactic_id"]: t for t in out["tactics"]}
    assert by_id["TA0002"]["technique_count"] == 1
    assert out["covered_tactic_count"] == 1
    assert out["window_days"] == 7


def test_unknown_technique_lands_in_unmapped_not_a_tactic():
    out = build_coverage([_enr(["T9999"])], window_days=90, confirmed_only=True)
    assert out["covered_tactic_count"] == 0
    assert [u["id"] for u in out["unmapped"]] == ["T9999"]


def test_incident_with_no_techniques_still_counts():
    # Incidents that matched the filter but emitted no techniques still count as
    # analyzed — coverage stays honest about the denominator.
    out = build_coverage([_enr([]), _enr(["T1566"])], window_days=90, confirmed_only=True)
    assert out["incident_count"] == 2
    assert out["technique_count"] == 1
