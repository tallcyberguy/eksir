"""Heuristic re-ranker for similar-case retrieval.

Qdrant returns by RRF score. That's a good starting signal but ignores three
things that matter to a SOC analyst:
  • whether the prior verdict was confirmed by a human (vs. seeded)
  • how recent the prior case is (90+ days old is staler signal)
  • how much reasoning text the prior verdict came with

This module applies a small additive boost on top of the RRF score so the
top-N the LLM sees is biased toward verified, recent, well-reasoned priors —
without throwing away the raw cosine signal. It's a placeholder for a
cross-encoder re-ranker that may replace it later.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Bonus weights (additive, on top of the [0, ~1] RRF score).
_W_HUMAN_VERIFIED = 0.05
_W_RECENT = 0.02  # within the last 90 days
_W_REASON_LONG = 0.02  # verdict_reason ≥ 100 chars
_W_TP_PENALTY = -0.01  # TP cases re-investigate by design; slight demotion


def rerank(similar: list[dict]) -> list[dict]:
    """Return a new list, re-sorted descending by adjusted score.

    Does not mutate input dicts; adds `adjusted_score` for transparency.
    """
    if not similar:
        return []

    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for s in similar:
        # Base on the TRUE cosine when available (honest [0,1] signal); fall
        # back to the RRF score only for legacy rows that lack a cosine.
        base = s.get("cosine")
        if base is None:
            base = s.get("score")
        base = float(base or 0.0)

        bonus = 0.0
        if s.get("human_verified"):
            bonus += _W_HUMAN_VERIFIED
        if _is_recent(s.get("timestamp"), now):
            bonus += _W_RECENT
        if len(s.get("verdict_reason") or "") >= 100:
            bonus += _W_REASON_LONG
        if (s.get("verdict") or "").upper() == "TP":
            bonus += _W_TP_PENALTY

        # adjusted_score is an ORDERING signal only — never displayed as a %.
        # Clamp to [0, 1] so a verified/recent prior can't exceed 100%.
        adjusted = max(0.0, min(1.0, base + bonus))
        out.append({**s, "adjusted_score": round(adjusted, 4)})

    out.sort(key=lambda x: x["adjusted_score"], reverse=True)
    return out


def _is_recent(ts: str | None, now: datetime, days: int = 90) -> bool:
    """Returns True if `ts` parses to a tz-aware time within `days` of now."""
    if not ts or not isinstance(ts, str):
        return False
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).days <= days
    except (ValueError, TypeError):
        return False
