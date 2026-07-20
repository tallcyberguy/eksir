"""Rolling per-entity risk from confirmed-verdict history (Phase 3).

  risk [0,100] — how much confirmed-TP history this entity (host / user /
  hash / …) has accumulated, decayed by recency.

Design stance (agreed 2026-07, mirrors scoring.py's):
  1. Risk = CONFIRMED history only. Only analyst-committed TP verdicts
     contribute — pending/inconclusive incidents and FP/benign noise add
     nothing (an FP doesn't make an entity safer either; it is just noise).
     This keeps the number auditable: "N confirmed incidents, decayed".
  2. Recency decay: each TP's weight halves every ``HALF_LIFE_DAYS`` (30) so
     an entity that was compromised a year ago and cleaned isn't forever hot.
  3. Saturating combine (noisy-OR): risk = 100·(1 − Π(1 − wᵢ)). Bounded,
     monotonic, and two strong confirmations push toward — but never past —
     100 without any per-term cap fiddling.
  4. ``None`` (not 0) when there is no TP history at all, so unscored
     entities stay blank in the UI instead of implying "assessed: zero".

Pure functions, no stack deps — unit-testable on the host (like scoring.py).
"""

from __future__ import annotations

from datetime import datetime, timezone

HALF_LIFE_DAYS = 30.0
_DEFAULT_THREAT = 50.0  # TP with no fused threat score (pre-scoring incidents)


def _as_utc(ts: object) -> datetime | None:
    """Parse a datetime or ISO string; assume UTC when naive. None on garbage."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def compute_entity_risk(incidents: list[dict], *, now: datetime | None = None) -> float | None:
    """Fuse an entity's incident history into one 0-100 risk number.

    ``incidents``: one dict per linked incident with keys
      verdict       — "TP" | "FP" | "benign" | "pending" | … (only TP counts)
      threat_score  — fused 0-100 effective threat, or None (falls back to 50)
      created_at    — datetime or ISO string (recency basis; missing = now)

    Returns None when no TP history exists (unscored ≠ zero-risk).
    """
    now = now or datetime.now(timezone.utc)
    survive = 1.0  # Π(1 − wᵢ)
    seen_tp = False
    for inc in incidents or []:
        if str(inc.get("verdict") or "").upper() != "TP":
            continue
        seen_tp = True
        try:
            threat = float(inc.get("threat_score"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            threat = _DEFAULT_THREAT  # missing / malformed -> neutral default
        base = max(0.0, min(1.0, threat / 100.0))
        created = _as_utc(inc.get("created_at"))
        age_days = max(0.0, (now - created).total_seconds() / 86400.0) if created else 0.0
        weight = base * (0.5 ** (age_days / HALF_LIFE_DAYS))
        survive *= 1.0 - weight
    if not seen_tp:
        return None
    return round(100.0 * (1.0 - survive), 1)
