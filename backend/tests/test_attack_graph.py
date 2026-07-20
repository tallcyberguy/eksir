"""Unit tests for the Attack Path pure builder (`routes/attack_graph.build_attack_path`)."""

from __future__ import annotations

from isoc_api.routes.attack_graph import build_attack_path


def _enr(l2: dict) -> dict:
    return {"stages": {"l2": l2}}


def test_empty_or_none_is_not_synthesized():
    for e in (None, {}, {"stages": {}}, {"stages": {"l2": {}}}):
        out = build_attack_path(e)
        assert out["synthesized"] is False
        assert out["stages"] == []
        assert out["technique_count"] == 0


def test_short_circuited_incident_has_no_path():
    out = build_attack_path({"stages": {"fast": {"x": 1}}})  # no l2
    assert out["synthesized"] is False
    assert out["stages"] == []


def test_attack_chain_carries_evidence_and_orders_by_tactic():
    # T1486 (Impact) listed before T1059 (Execution) — output must reorder.
    out = build_attack_path(
        _enr(
            {
                "attack_chain": [
                    {"technique": "T1486", "evidence": "ransom note dropped"},
                    {"technique": "T1059", "evidence": "powershell spawned"},
                ]
            }
        )
    )
    assert out["synthesized"] is True
    names = [s["name"] for s in out["stages"]]
    assert names.index("Execution") < names.index("Impact")
    exec_stage = next(s for s in out["stages"] if s["name"] == "Execution")
    assert exec_stage["techniques"][0]["evidence"] == "powershell spawned"


def test_bare_mitre_techniques_fallback_no_evidence():
    out = build_attack_path(_enr({"mitre_techniques": ["T1566"]}))
    assert out["technique_count"] == 1
    tech = out["stages"][0]["techniques"][0]
    assert tech["id"] == "T1566"
    assert tech["evidence"] == ""


def test_subtechnique_rolls_up_to_parent():
    out = build_attack_path(_enr({"mitre_techniques": ["T1059.001"]}))
    stage = out["stages"][0]
    assert stage["name"] == "Execution"
    assert stage["techniques"][0]["id"] == "T1059"


def test_unknown_technique_lands_in_unmapped():
    out = build_attack_path(_enr({"mitre_techniques": ["T9999"]}))
    assert out["stages"] == []
    assert [u["id"] for u in out["unmapped"]] == ["T9999"]


def test_multitactic_technique_placed_once_at_earliest():
    # T1078 Valid Accounts spans Initial Access / Persistence / PrivEsc / Defense Evasion.
    out = build_attack_path(_enr({"mitre_techniques": ["T1078"]}))
    assert out["technique_count"] == 1
    assert out["tactic_count"] == 1  # placed once
    assert out["stages"][0]["name"] == "Initial Access"  # earliest by kill-chain order


def test_duplicate_technique_deduped():
    out = build_attack_path(
        _enr({"attack_chain": [{"technique": "T1059"}, {"technique": "T1059.002"}]})
    )
    # both roll up to T1059 → counted once
    assert out["technique_count"] == 1
