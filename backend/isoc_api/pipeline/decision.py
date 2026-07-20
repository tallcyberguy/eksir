"""Decision gate — deterministic verdict logic.

Returns (verdict, confidence, short_circuit_reason) or (None, None, None) if inconclusive.
"""

from __future__ import annotations

from ..db.enums import Confidence, Verdict

# n_way short-circuit closes a case with NO LLM at all, so it demands the
# strictest agreement — deliberately stricter than the orchestrator's
# POPULATE / CORROBORATE thresholds (see orchestrator.py for the rationale).
N_WAY_CLOSE_MIN = 4
N_WAY_CLOSE_TOTAL_MIN = 5


def evaluate(
    *,
    exact_match: dict | None,
    n_way: dict | None,
    autoclose: dict | None,
    triage_results: list[dict],
) -> tuple[Verdict | None, Confidence | None, dict | None]:
    """Determine if we can short-circuit without an LLM call.

    Order of precedence (highest signal first):
      1. EXACT_MATCH, cosine ≥ 0.9. NOTE: store_adapter.find_exact_match already
         guarantees human_verified=True AND verdict ∈ {FP, benign} before it ever
         returns a row, and its ``score`` is the TRUE cosine (not the RRF fusion
         score) — so this 0.9 gate is a real similarity threshold, not a rank score.
      2. AUTO_CLOSE rule fired (pre or post) + TI clean.
      3. N_WAY_AGREEMENT ≥ N_WAY_CLOSE_MIN / N_WAY_CLOSE_TOTAL_MIN, computed by
         the orchestrator over *verified* priors only.
    """
    # 1) Exact match short-circuit (score is the true cosine; None-safe guard)
    if exact_match and (exact_match.get("score") or 0.0) >= 0.9:
        verdict = (exact_match.get("verdict") or "").lower()
        if verdict in ("fp", "benign"):
            return (
                Verdict(verdict.upper()) if verdict == "fp" else Verdict.BENIGN,
                Confidence.HIGH,
                {
                    "gate": "exact_match",
                    "alert_id": exact_match.get("alert_id"),
                    "score": exact_match.get("score"),
                    "verdict_reason": exact_match.get("verdict_reason"),
                },
            )

    # 2) Auto-close post-enrichment + clean TI
    if autoclose and _ti_clean(triage_results):
        verdict_str = (autoclose.get("verdict") or "").lower()
        if verdict_str in ("fp", "benign"):
            return (
                Verdict.FP if verdict_str == "fp" else Verdict.BENIGN,
                Confidence.HIGH,
                {
                    "gate": "auto_close_post_enrichment",
                    "rule_id": autoclose.get("rule_id"),
                    "reason": autoclose.get("reason"),
                },
            )

    # 3) N-way agreement (≥ N_WAY_CLOSE_MIN of N_WAY_CLOSE_TOTAL_MIN)
    if n_way:
        try:
            agreed, total = n_way["agreement"].split("/")
            if int(agreed) >= N_WAY_CLOSE_MIN and int(total) >= N_WAY_CLOSE_TOTAL_MIN:
                verdict = (n_way.get("verdict") or "").lower()
                if verdict in ("fp", "benign", "tp"):
                    v = (
                        Verdict.FP
                        if verdict == "fp"
                        else Verdict.BENIGN
                        if verdict == "benign"
                        else Verdict.TP
                    )
                    return (
                        v,
                        Confidence.MEDIUM,
                        {
                            "gate": "n_way_agreement",
                            "agreement": n_way["agreement"],
                            "matches": [m.get("alert_id") for m in n_way.get("matches", [])],
                        },
                    )
        except (KeyError, ValueError):
            pass

    return None, None, None


def _ti_clean(triage_results: list[dict]) -> bool:
    """Heuristic: all triage results found verdict ∈ {clean, suspicious-low}."""
    if not triage_results:
        # No public IOCs to check = clean by default.
        return True
    for r in triage_results:
        verdict = (r.get("verdict") or "").lower()
        if verdict in ("malicious", "high"):
            return False
        # Defensive: VT detections in summary
        summary = r.get("summary", {})
        vt = summary.get("vt_malicious") or summary.get("virustotal_malicious") or 0
        try:
            if int(vt) > 3:
                return False
        except (TypeError, ValueError):
            pass
        abuse = summary.get("abuseipdb") or 0
        try:
            if isinstance(abuse, str):
                abuse = int(abuse.rstrip("%"))
            if int(abuse) > 25:
                return False
        except (TypeError, ValueError):
            pass
    return True
