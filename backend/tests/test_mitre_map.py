"""F4 — tests for the MITRE map + coverage aggregation."""

from __future__ import annotations

from isoc_api.pipeline import mitre_map as mm


def test_parent_of():
    assert mm.parent_of("T1059.001") == "T1059"
    assert mm.parent_of("T1059") == "T1059"
    assert mm.parent_of("t1059.003") == "T1059"
    assert mm.parent_of("") == ""


def test_tactics_for_known_and_subtechnique():
    assert mm.tactics_for("T1059") == ["TA0002"]  # Execution
    # sub-technique inherits the parent's tactics
    assert mm.tactics_for("T1059.001") == ["TA0002"]


def test_tactics_for_multi_tactic_technique():
    # Valid Accounts spans Initial Access / Persistence / Priv-Esc / Defense Evasion
    tactics = mm.tactics_for("T1078")
    assert set(tactics) == {"TA0001", "TA0003", "TA0004", "TA0005"}


def test_tactics_for_unknown_is_empty():
    assert mm.tactics_for("T9999") == []
    assert mm.technique_name("T9999") is None


def test_extract_techniques_tolerant():
    assert mm.extract_techniques(None) == []
    assert mm.extract_techniques({}) == []
    enr = {"stages": {"l2": {"mitre_techniques": ["T1059.001", "t1078", " "]}}}
    assert mm.extract_techniques(enr) == ["T1059.001", "T1078"]


def test_aggregate_coverage_buckets_and_counts():
    incidents = [
        ["T1059.001", "T1486"],  # Execution + Impact
        ["T1059", "T1110"],  # Execution + Credential Access
        ["T9999"],  # unmapped
    ]
    cov = mm.aggregate_coverage(incidents)

    assert cov["incident_count"] == 3
    assert cov["technique_count"] == 5  # T1059.001, T1486, T1059, T1110, T9999 distinct
    assert cov["occurrence_count"] == 5  # 5 mentions, none repeated

    by_id = {t["tactic_id"]: t for t in cov["tactics"]}
    assert len(cov["tactics"]) == 14  # always all 14 tactics

    # Execution holds both T1059.001 and T1059 → 2 distinct techniques, 2 occurrences
    execu = by_id["TA0002"]
    assert execu["technique_count"] == 2
    assert execu["occurrence_count"] == 2

    # Impact + Credential Access each have one
    assert by_id["TA0040"]["technique_count"] == 1  # T1486
    assert by_id["TA0006"]["technique_count"] == 1  # T1110

    # The unknown technique landed in unmapped, not in any tactic
    assert {u["id"] for u in cov["unmapped"]} == {"T9999"}


def test_aggregate_multi_tactic_attribution():
    cov = mm.aggregate_coverage([["T1078"]])
    by_id = {t["tactic_id"]: t for t in cov["tactics"]}
    # T1078 attributed to all four of its tactics
    for ta in ("TA0001", "TA0003", "TA0004", "TA0005"):
        assert any(t["id"] == "T1078" for t in by_id[ta]["techniques"])
    # but it's one distinct technique / one occurrence globally
    assert cov["technique_count"] == 1
    assert cov["occurrence_count"] == 1


def test_tactics_sorted_in_killchain_order():
    cov = mm.aggregate_coverage([])
    orders = [t["order"] for t in cov["tactics"]]
    assert orders == sorted(orders)
    assert cov["tactics"][0]["tactic_id"] == "TA0043"  # Reconnaissance first
