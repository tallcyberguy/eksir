"""Unit tests for the confidence/threat fusion (pipeline/scoring.py).

Pure functions — no stack. Assertions lock the *behavior* (bands, ordering,
caps, FP-sinks-effective-threat) rather than brittle exact values, with a few
anchor numbers pinned where the weighting matters.
"""

from __future__ import annotations

from isoc_api.pipeline import scoring
from isoc_api.pipeline.scoring import SignalBundle, compute_scores


def test_strong_exact_match_fp_is_high_confidence_low_effective_threat():
    b = SignalBundle(
        proposed_verdict="FP",
        llm_band="high",
        severity="high",
        exact_cosine=0.95,
        exact_verdict="fp",
        nway_agreed=4,
        nway_total=5,
        nway_verdict="fp",
    )
    r = compute_scores(b)
    assert r.confidence_band == "high"
    assert r.confidence_score >= 90  # 0.75 prior + exact + n_way
    # inherent threat is high (sev=high) but FP sinks the EFFECTIVE number
    assert r.threat_inherent >= 70
    assert r.threat_score <= 15  # p_malicious = 1-conf is small


def test_confirmed_tp_is_high_confidence_high_threat():
    b = SignalBundle(
        proposed_verdict="TP",
        llm_band="high",
        severity="critical",
        exact_cosine=0.92,
        exact_verdict="tp",
        nway_agreed=4,
        nway_total=5,
        nway_verdict="tp",
        vt_malicious=9,
        abuseipdb_pct=90,
        ti_malicious_sources=2,
        attack_chain_len=3,
        hunt_focus="lateral_movement",
    )
    r = compute_scores(b)
    assert r.confidence_band == "high"
    assert r.threat_inherent >= 90
    assert r.threat_score >= 80  # confident TP -> effective ~ inherent


def test_no_priors_caps_confidence_at_medium():
    # LLM says high, but there is zero prior-case evidence -> hard cap 0.60.
    b = SignalBundle(proposed_verdict="TP", llm_band="high", severity="medium")
    r = compute_scores(b)
    assert r.confidence_score == 60
    assert r.confidence_band == "medium"
    assert r.contributions["confidence"].get("_cap_no_priors") == 0.60


def test_contradicting_evidence_lowers_confidence():
    # Verdict FP but the exact match + TI both say malicious -> penalties.
    contra = compute_scores(
        SignalBundle(
            proposed_verdict="FP",
            llm_band="medium",
            severity="medium",
            exact_cosine=0.90,
            exact_verdict="tp",  # disagrees with FP
            ti_malicious_sources=3,  # TI says malicious
        )
    )
    # Same case without the contradicting signals (just the band + a weak prior).
    clean = compute_scores(
        SignalBundle(
            proposed_verdict="FP",
            llm_band="medium",
            severity="medium",
            similar_top_adjusted=0.6,
            similar_verified_count=1,
        )
    )
    assert contra.confidence_score < clean.confidence_score
    c = contra.contributions["confidence"]
    assert c["exact_match"] < 0 and c["ti_contradiction"] < 0


def test_sensitive_rule_dismissal_is_capped():
    b = SignalBundle(
        proposed_verdict="benign",
        llm_band="high",
        severity="high",
        exact_cosine=0.95,
        exact_verdict="benign",
        nway_agreed=5,
        nway_total=5,
        nway_verdict="benign",
        sensitive_rule=True,
    )
    r = compute_scores(b)
    assert r.confidence_score <= 70  # never HIGH-confident dismissal
    assert r.contributions["confidence"].get("_cap_sensitive_dismiss") == 0.70


def test_inconclusive_verdict_is_capped():
    b = SignalBundle(
        proposed_verdict="inconclusive",
        llm_band="high",
        severity="high",
        exact_cosine=0.95,
        exact_verdict="tp",
    )
    r = compute_scores(b)
    assert r.confidence_score <= 40
    assert r.p_malicious == 0.5


def test_low_confidence_high_threat_survives_in_effective():
    # The "needs eyes" cell: high inherent threat, unsure verdict.
    b = SignalBundle(proposed_verdict="inconclusive", llm_band="low", severity="critical")
    r = compute_scores(b)
    assert r.threat_inherent >= 85
    # p_malicious=0.5 keeps effective threat meaningfully elevated
    assert 35 <= r.threat_score <= 55


def test_llm_band_alone_cannot_exceed_ceiling():
    # With priors present but weak, a high band should approach but the model
    # alone never blows past ~0.75 without hard corroboration.
    b = SignalBundle(
        proposed_verdict="TP",
        llm_band="high",
        severity="medium",
        similar_top_adjusted=0.58,
        similar_verified_count=1,
    )
    r = compute_scores(b)
    assert r.confidence_score <= 80  # 0.75 + tiny similar support


def test_build_bundle_extracts_from_enrichment():
    enrichment = {
        "exact_match": {"score": 0.93, "verdict": "fp"},
        "n_way": {"agreement": "4/5", "verdict": "fp"},
        "similar_top5": [
            {"adjusted_score": 0.88, "human_verified": True, "verdict": "FP"},
            {"adjusted_score": 0.71, "human_verified": False, "verdict": "FP"},
        ],
        "triage": [
            {"verdict": "malicious", "summary": {"vt_malicious": 8, "abuseipdb": "90%"}},
            {"verdict": "clean", "summary": {"vt_malicious": 0, "abuseipdb": 0}},
        ],
        "sensitive_rule": {"matched": True, "keyword": "admin login"},
    }
    b = scoring.build_bundle(
        enrichment,
        proposed_verdict="FP",
        llm_band="medium",
        severity="high",
        attack_chain_len=2,
        hunt_focus="c2",
    )
    assert b.exact_cosine == 0.93 and b.exact_verdict == "fp"
    assert b.nway_agreed == 4 and b.nway_total == 5
    assert b.similar_top_adjusted == 0.88 and b.similar_verified_count == 1
    assert b.vt_malicious == 8 and b.abuseipdb_pct == 90
    assert b.ti_malicious_sources == 1  # only the malicious triage row counts
    assert b.sensitive_rule is True
    assert b.attack_chain_len == 2 and b.hunt_focus == "c2"


def test_build_bundle_tolerates_empty_enrichment():
    b = scoring.build_bundle({}, proposed_verdict="TP", llm_band="low", severity="medium")
    r = compute_scores(b)
    assert 0 <= r.confidence_score <= 100 and 0 <= r.threat_score <= 100


# ── correlation cluster nudge (Phase 2b follow-up, agreed 2026-07) ───────────
def test_cluster_term_scales_and_is_bounded():
    def inherent(size: int) -> tuple[float, dict]:
        return scoring.score_threat_inherent(
            SignalBundle(proposed_verdict="TP", severity="medium", cluster_size=size)
        )

    base, c0 = inherent(0)
    assert "cluster_corroboration" not in c0
    _, c1 = inherent(1)
    assert "cluster_corroboration" not in c1  # size 1 = just self, no nudge

    s2, c2 = inherent(2)
    assert c2["cluster_corroboration"] == 2.5
    assert s2 == base + 2.5

    s5, c5 = inherent(5)
    assert c5["cluster_corroboration"] == 10.0
    s20, c20 = inherent(20)
    assert c20["cluster_corroboration"] == 10.0  # bounded — a storm doesn't run away
    assert s20 == s5


def test_cluster_dismiss_cap_applies_to_fp_in_big_cluster():
    # Strong corroborated FP that would otherwise be HIGH-confident…
    kwargs = dict(
        proposed_verdict="FP",
        llm_band="high",
        severity="medium",
        exact_cosine=0.95,
        exact_verdict="fp",
        nway_agreed=4,
        nway_total=5,
        nway_verdict="fp",
    )
    uncapped = compute_scores(SignalBundle(**kwargs))
    assert uncapped.confidence_score > 70

    # …is capped at 0.70 once it's one member of a >=3 correlated burst.
    capped = compute_scores(SignalBundle(**kwargs, cluster_size=3))
    assert capped.confidence_score == 70
    assert "_cap_cluster_dismiss" in capped.contributions["confidence"]

    # A 2-cluster does NOT trigger the cap; a TP verdict is never capped by it.
    small = compute_scores(SignalBundle(**kwargs, cluster_size=2))
    assert small.confidence_score > 70
    tp = compute_scores(
        SignalBundle(
            proposed_verdict="TP",
            llm_band="high",
            severity="medium",
            exact_cosine=0.95,
            exact_verdict="tp",
            cluster_size=5,
        )
    )
    assert "_cap_cluster_dismiss" not in tp.contributions["confidence"]


def test_build_bundle_reads_cluster_member_count():
    b = scoring.build_bundle(
        {"cluster": {"cluster_id": "x", "member_count": 4}},
        proposed_verdict="TP",
        llm_band="low",
        severity="medium",
    )
    assert b.cluster_size == 4
    # absent / malformed -> 0, never raises
    b0 = scoring.build_bundle({}, proposed_verdict="TP", llm_band="low", severity="medium")
    assert b0.cluster_size == 0


def test_vendor_score_raises_inherent_threat_bounded():
    # the vendor's own 0-100 risk score (e.g. Trend V1 score) nudges inherent threat, bounded.
    b0 = SignalBundle(proposed_verdict="TP", llm_band="high", severity="medium")
    b1 = SignalBundle(proposed_verdict="TP", llm_band="high", severity="medium", vendor_score=90)
    r0 = compute_scores(b0)
    r1 = compute_scores(b1)
    assert r1.threat_inherent > r0.threat_inherent
    assert "vendor_score" in r1.contributions["threat"]
    assert r1.threat_inherent - r0.threat_inherent <= 12  # bounded by _T_VENDOR_MAX
    # a zero/absent vendor score changes nothing
    assert (
        compute_scores(SignalBundle(proposed_verdict="TP", vendor_score=0)).threat_inherent
        == compute_scores(SignalBundle(proposed_verdict="TP")).threat_inherent
    )
