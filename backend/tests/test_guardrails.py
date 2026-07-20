"""Unit tests for autonomy guardrails recommendation core (`pipeline/guardrails.py`)."""

from __future__ import annotations

from isoc_api.pipeline import guardrails as g


def test_confidence_buckets():
    assert g.confidence_to_score("high") == 0.9
    assert g.confidence_to_score("medium") == 0.6
    assert g.confidence_to_score("low") == 0.3
    assert g.confidence_to_score("garbage") == 0.3  # fail-safe low


def test_read_only_high_confidence_is_auto():
    rec = g.recommend("tag", "high")
    assert rec["blast_radius"] == "read"
    assert rec["autonomy"] == "auto"
    rec2 = g.recommend("enrich", "low")  # read-only is auto even at low confidence
    assert rec2["autonomy"] == "auto"


def test_effect_kinds_always_escalate_even_at_high_confidence():
    # The headline invariant: containment is never auto, never review.
    for kind in ("isolate_host", "blocklist_ioc", "collect_file"):
        rec = g.recommend(kind, "high")
        assert rec["autonomy"] == "escalate", kind
        assert "analyst-gated" in rec["reason"]


def test_unknown_kind_is_failsafe_high_and_not_auto():
    rec = g.recommend("frobnicate", "high")
    assert rec["blast_radius"] == "high"
    assert rec["autonomy"] in ("review", "escalate")  # never auto for unknown


def test_low_blast_radius_ladder_edges():
    # 'close_alert' = low: auto≥0.6, review≥0.3.
    assert g.recommend("close_alert", "high")["autonomy"] == "auto"  # 0.9 ≥ 0.6
    assert g.recommend("close_alert", "medium")["autonomy"] == "auto"  # 0.6 ≥ 0.6
    assert g.recommend("close_alert", "low")["autonomy"] == "review"  # 0.3 ≥ 0.3


def test_policy_override_changes_blast_radius_and_ladder():
    # Override 'tag' to be high blast radius with a strict ladder → no longer auto.
    policy = {"tag": {"blast_radius": "high", "auto": 1.01, "review": 0.6, "escalation": 0.0}}
    rec = g.recommend("tag", "high", policy)
    assert rec["blast_radius"] == "high"
    assert rec["autonomy"] == "review"  # 0.9 < 1.01 auto floor


def test_apply_annotates_without_mutating_other_fields():
    actions = [{"id": "a1", "kind": "isolate_host", "justification": "x", "status": "pending"}]
    out = g.apply(actions, "high")
    assert out[0]["id"] == "a1"
    assert out[0]["justification"] == "x"
    assert out[0]["autonomy"] == "escalate"
    assert out[0]["blast_radius"] == "critical"
    assert "autonomy_reason" in out[0]
    # input not mutated
    assert "autonomy" not in actions[0]


def test_apply_empty_safe():
    assert g.apply([], "high") == []
    assert g.apply(None, "high") == []


def test_build_effective_policy_precedence_code_yaml_global_tenant():
    yaml_map = {"tag": {"auto": 0.95}}
    global_rows = [
        {
            "action_kind": "tag",
            "blast_radius": "read",
            "auto_confidence": 0.8,
            "review_confidence": 0.3,
            "escalation_confidence": 0.0,
            "source": "db",
            "reason": None,
        },
    ]
    tenant_rows = [
        {
            "action_kind": "tag",
            "blast_radius": "read",
            "auto_confidence": 0.7,
            "review_confidence": 0.2,
            "escalation_confidence": 0.0,
            "source": "db",
            "reason": "t",
        },
    ]
    out = g.build_effective_policy(
        yaml_map=yaml_map, global_rows=global_rows, tenant_rows=tenant_rows
    )
    tag = out["actions"]["tag"]
    assert tag["auto"] == 0.7  # tenant beats global beats yaml beats code
    assert tag["source"] == "db"
    # a kind with no overrides keeps the code default + source
    assert out["actions"]["isolate_host"]["source"] == "code"
    assert out["actions"]["isolate_host"]["is_effect"] is True


def test_build_effective_policy_lists_all_known_kinds():
    out = g.build_effective_policy()
    assert set(out["actions"]) == set(g.BLAST_RADIUS)
