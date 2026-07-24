"""Unit tests for ADR-0009 manager-owned hunt routing (`decide_hunt`).

Pure functions over the typed contracts; no stack needed (per CLAUDE.md, these
run on the host). `decide_hunt` supersedes `should_hunt`: on a confirmed TP a
hunt is warranted when L2 recommends it OR a hard signal demands it, so the model
cannot veto a hunt on a confirmed critical.
"""

from isoc_api.pipeline.agent_routing import decide_hunt, should_hunt
from isoc_api.pipeline.contracts import AnalysisVerdict, HuntDecision


def _tp(
    hunt_recommended: bool = False, hunt_focus: str | None = "lateral_movement"
) -> AnalysisVerdict:
    return AnalysisVerdict(
        verdict="true_positive",
        hunt_recommended=hunt_recommended,
        hunt_focus=hunt_focus,
    )


def _malicious_enrichment() -> dict:
    return {"triage": [{"verdict": "malicious", "query": {"ioc": "1.2.3.4", "type": "ipv4"}}]}


def test_non_tp_never_hunts():
    # Even with L2 recommending, a non-TP verdict never warrants a hunt.
    for v in ("false_positive", "benign", "inconclusive"):
        d = decide_hunt(AnalysisVerdict(verdict=v, hunt_recommended=True), {})
        assert isinstance(d, HuntDecision)
        assert d.run is False


def test_tp_with_l2_recommendation_hunts():
    d = decide_hunt(_tp(hunt_recommended=True), {})
    assert d.run is True
    assert d.focus == "lateral_movement"
    assert "recommended" in d.reason


def test_tp_without_any_signal_does_not_hunt():
    d = decide_hunt(_tp(hunt_recommended=False), {})
    assert d.run is False
    assert d.focus == "lateral_movement"  # focus is still carried through
    assert "no hunt signal" in d.reason


def test_malicious_ioc_forces_hunt_without_l2_recommendation():
    d = decide_hunt(_tp(hunt_recommended=False), _malicious_enrichment())
    assert d.run is True
    assert "malicious" in d.reason


def test_high_endpoint_criticality_forces_hunt():
    # The "model can't veto a hunt on a confirmed critical" case (ADR-0009 D5).
    for level in ("high", "critical"):
        enrichment = {"ms": {"endpoint": {"criticality": level}}}
        d = decide_hunt(_tp(hunt_recommended=False), enrichment)
        assert d.run is True, level
        assert f"criticality is {level}" in d.reason


def test_high_user_risk_forces_hunt():
    enrichment = {"ms": {"identity": {"risk_level": "high"}}}
    d = decide_hunt(_tp(hunt_recommended=False), enrichment)
    assert d.run is True
    assert "high-risk" in d.reason


def test_low_criticality_and_no_risk_do_not_force_hunt():
    enrichment = {"ms": {"endpoint": {"criticality": "low"}, "identity": {"risk_level": "none"}}}
    d = decide_hunt(_tp(hunt_recommended=False), enrichment)
    assert d.run is False


def test_degrades_gracefully_without_ms_enrichment():
    # Until the pre-L2 Microsoft enrichment lands, decide_hunt falls back to L2's
    # recommendation (parity with the legacy should_hunt on the base case).
    assert decide_hunt(_tp(hunt_recommended=True), {}).run is True
    assert decide_hunt(_tp(hunt_recommended=False), {}).run is False


def test_matches_should_hunt_on_the_base_case():
    # With no enrichment signals, decide_hunt.run agrees with the legacy shim.
    for rec in (True, False):
        l2 = _tp(hunt_recommended=rec)
        assert decide_hunt(l2, {}).run == should_hunt(l2)
