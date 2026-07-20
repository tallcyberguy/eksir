"""IOC confidence scoring over the local aggregated threat feed.

AiSOC's threat-intel service *wanted* an aggregation-driven IOC confidence but
only stubbed it (confidence came straight from STIX, or a flat default — no
corroboration, no recency, no feed weighting). isoc already stores the better
substrate: `ThreatIOC.sources` is a multi-feed provenance array and
first/last-seen are tracked. This module turns that substrate into a graded
score so the pipeline can stop treating every hit as equally damning.

A score in [0, 1] from three signals:
  * **corroboration** — how many distinct feeds flag the IOC (saturating curve;
    one feed is a real but modest signal, several feeds is strong);
  * **recency** — exponential decay on `last_seen_at` (half-life configurable);
    a feed entry last seen a year ago is weaker than one seen yesterday;
  * **match kind** (for an alert hit only) — an exact value match counts full;
    a parent-domain match is discounted.

Pure + deterministic given `now`; no DB, no I/O — unit-tested in isolation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Weights for the standing reputation of a stored IOC (corroboration vs freshness).
W_CORROBORATION = 0.6
W_RECENCY = 0.4

# Recency decay: score halves every this-many days since last_seen.
DEFAULT_HALF_LIFE_DAYS = 30.0
# Floor so an ancient-but-corroborated IOC never collapses to ~0 (stays listed).
RECENCY_FLOOR = 0.05

# Match-kind discount applied on top of reputation for an alert hit.
MATCH_KIND_WEIGHT = {"exact": 1.0, "parent_domain": 0.6}

# Band thresholds on the final score.
BAND_HIGH = 0.66
BAND_MEDIUM = 0.33


def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def band(score: float) -> str:
    """low | medium | high for a [0,1] score."""
    if score >= BAND_HIGH:
        return "high"
    if score >= BAND_MEDIUM:
        return "medium"
    return "low"


def corroboration_score(source_count: int) -> float:
    """Saturating curve: 1→0.50, 2→0.75, 3→0.875, 4→0.9375 … → 1.0.

    More feeds flagging the same indicator is stronger evidence, with
    diminishing returns. Zero sources scores 0 (shouldn't happen for a stored
    row, but stays well-defined)."""
    n = max(0, int(source_count))
    if n == 0:
        return 0.0
    return _clamp(1.0 - 0.5 ** min(n, 8))


def _as_aware(dt: datetime | str | None) -> datetime | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def recency_score(
    last_seen_at: datetime | str | None,
    *,
    now: datetime,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
) -> float:
    """Exponential decay on age. Fresh→1.0, one half-life→0.5, floored at
    RECENCY_FLOOR. Missing/unparseable timestamp → floor."""
    seen = _as_aware(last_seen_at)
    if seen is None:
        return RECENCY_FLOOR
    age_days = max(0.0, (now - seen).total_seconds() / 86400.0)
    decayed = 0.5 ** (age_days / max(half_life_days, 0.001))
    return _clamp(max(RECENCY_FLOOR, decayed))


def reputation_score(
    source_count: int,
    last_seen_at: datetime | str | None,
    *,
    now: datetime,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
) -> float:
    """Standing reputation of a stored IOC, independent of any alert."""
    c = corroboration_score(source_count)
    r = recency_score(last_seen_at, now=now, half_life_days=half_life_days)
    return round(_clamp(W_CORROBORATION * c + W_RECENCY * r), 4)


def reputation(
    source_count: int,
    last_seen_at: datetime | str | None,
    *,
    now: datetime,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
) -> dict[str, Any]:
    """`{score, band, sources, corroboration, recency}` for a stored IOC row."""
    c = corroboration_score(source_count)
    r = recency_score(last_seen_at, now=now, half_life_days=half_life_days)
    score = round(_clamp(W_CORROBORATION * c + W_RECENCY * r), 4)
    return {
        "score": score,
        "band": band(score),
        "sources": max(0, int(source_count)),
        "corroboration": round(c, 4),
        "recency": round(r, 4),
    }


def score_match(
    match: dict, *, now: datetime, half_life_days: float = DEFAULT_HALF_LIFE_DAYS
) -> dict:
    """A local-feed match (from `lookup.match_iocs`) scored as an alert hit.

    Returns the match dict with `score`/`band`/`reputation`/`source_count`
    added; never mutates the input."""
    source_count = len(match.get("sources") or [])
    rep = reputation_score(
        source_count, match.get("last_seen_at"), now=now, half_life_days=half_life_days
    )
    kind = str(match.get("match_kind") or "exact")
    score = round(_clamp(rep * MATCH_KIND_WEIGHT.get(kind, 1.0)), 4)
    return {
        **match,
        "source_count": source_count,
        "reputation": rep,
        "score": score,
        "band": band(score),
    }


def summarize(
    matches: list[dict],
    *,
    now: datetime | None = None,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
) -> dict[str, Any]:
    """Score every alert match and roll them into one incident-level signal.

    Returns:
        {
          score: float,            # the strongest single match
          band: low|medium|high,   # band of that score
          match_count: int,
          exact_matches: int,
          distinct_sources: int,   # distinct feeds across all matches
          matches: [scored match, …],   # sorted strongest-first
        }
    Empty input → a zeroed, low-band summary.
    """
    now = now or datetime.now(timezone.utc)
    scored = [score_match(m, now=now, half_life_days=half_life_days) for m in (matches or [])]
    scored.sort(key=lambda m: (-m["score"], m.get("value") or ""))

    distinct: set[str] = set()
    exact = 0
    for m in scored:
        for s in m.get("sources") or []:
            distinct.add(str(s))
        if m.get("match_kind") == "exact":
            exact += 1

    top = scored[0]["score"] if scored else 0.0
    return {
        "score": top,
        "band": band(top),
        "match_count": len(scored),
        "exact_matches": exact,
        "distinct_sources": len(distinct),
        "matches": scored,
    }
