"""Team Analytics (3.5) — pure leaderboard scoring.

Reads nothing; the route supplies one row per signed-off incident and this turns
them into a per-analyst leaderboard. Composite **score = accuracy + volume +
speed** (weights below). Accuracy = 1 − FP-flip rate (a verdict later reversed),
the chosen ground-truth — labeled "flip rate" in the UI, never overclaimed as
calibrated accuracy. Speed is deliberately the lowest weight and its badge is
volume-gated so the board can't reward rushing the gate.

The analyst gate stays the sole commit point: this module only aggregates the
attribution the gate already wrote. It proposes/commits nothing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

MIN_VOLUME = 5  # below this an analyst is "provisional" (shown, not ranked)
SPEED_REF_MIN = 240  # full speed credit at/under this median time-to-signoff (min)
SPEED_FLOOR_MIN = 1440  # zero speed credit at/over this
W_ACCURACY, W_VOLUME, W_SPEED = 0.5, 0.3, 0.2


def median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def speed_score(median_minutes: float | None) -> float:
    """1.0 at/under SPEED_REF_MIN, linear decay to 0.0 at/over SPEED_FLOOR_MIN.
    None (no resolved cases) → 0.0."""
    if median_minutes is None:
        return 0.0
    if median_minutes <= SPEED_REF_MIN:
        return 1.0
    if median_minutes >= SPEED_FLOOR_MIN:
        return 0.0
    span = SPEED_FLOOR_MIN - SPEED_REF_MIN
    return round(1.0 - (median_minutes - SPEED_REF_MIN) / span, 4)


def volume_score(cases: int, max_cases: int) -> float:
    """Cases normalized against the board's busiest analyst. 0 when no cases."""
    if max_cases <= 0:
        return 0.0
    return round(cases / max_cases, 4)


def composite_score(*, accuracy: float, volume_norm: float, speed: float) -> float:
    """0–100. All components 1.0 → 100.0."""
    raw = W_ACCURACY * accuracy + W_VOLUME * volume_norm + W_SPEED * speed
    return round(raw * 100, 1)


def award_badges(stats: dict) -> list[dict]:
    """Rule-based chips. `stats`: {cases, flip_rate, accuracy, median_minutes,
    is_top_volume}. tone ∈ positive|accent|warning."""
    cases = stats.get("cases", 0)
    flip_rate = stats.get("flip_rate", 0.0)
    accuracy = stats.get("accuracy", 0.0)
    med = stats.get("median_minutes")
    badges: list[dict] = []
    if cases >= 20 and flip_rate == 0:
        badges.append({"key": "zero_fp", "label": "Zero FP", "tone": "positive"})
    if accuracy >= 0.95 and cases >= 10:
        badges.append({"key": "sharpshooter", "label": "Sharpshooter", "tone": "accent"})
    if stats.get("is_top_volume") and cases > 0:
        badges.append({"key": "workhorse", "label": "Workhorse", "tone": "accent"})
    # Volume-gated: a single fast sloppy close earns nothing.
    if med is not None and med <= SPEED_REF_MIN and cases >= 10:
        badges.append({"key": "quick_draw", "label": "Quick Draw", "tone": "positive"})
    if MIN_VOLUME <= cases <= 10:
        badges.append({"key": "newcomer", "label": "Newcomer", "tone": "warning"})
    return badges


def _minutes(created: datetime | None, signed: datetime | None) -> float | None:
    if not created or not signed:
        return None
    return max(0.0, (signed - created).total_seconds() / 60.0)


def build_leaderboard(rows: list[dict], *, window_days: int, now: datetime) -> dict[str, Any]:
    """`rows`: one dict per signed-off incident —
    {analyst_id, analyst_name, created_at, signed_off_at, verdict, was_flipped}.
    Groups by analyst, scores, ranks. Sub-`MIN_VOLUME` analysts go to
    `provisional` (shown, unranked). Empty rows → zeros, never crashes."""
    by: dict[str, dict] = {}
    all_durations: list[float] = []
    total_flips = 0
    for r in rows:
        aid = str(r.get("analyst_id"))
        a = by.setdefault(
            aid,
            {
                "analyst_id": aid,
                "analyst_name": r.get("analyst_name") or aid[:8],
                "durations": [],
                "cases": 0,
                "flips": 0,
            },
        )
        a["cases"] += 1
        dur = _minutes(r.get("created_at"), r.get("signed_off_at"))
        if dur is not None:
            a["durations"].append(dur)
            all_durations.append(dur)
        if r.get("was_flipped"):
            a["flips"] += 1
            total_flips += 1

    max_cases = max((a["cases"] for a in by.values()), default=0)

    analysts: list[dict] = []
    provisional: list[dict] = []
    for a in by.values():
        cases = a["cases"]
        med = median(a["durations"])
        flip_rate = round(a["flips"] / cases, 4) if cases else 0.0
        accuracy = round(1.0 - flip_rate, 4)
        if cases < MIN_VOLUME:
            provisional.append(
                {"analyst_id": a["analyst_id"], "analyst_name": a["analyst_name"], "cases": cases}
            )
            continue
        vol = volume_score(cases, max_cases)
        spd = speed_score(med)
        stats = {
            "cases": cases,
            "flip_rate": flip_rate,
            "accuracy": accuracy,
            "median_minutes": med,
            "is_top_volume": cases == max_cases and cases > 0,
        }
        analysts.append(
            {
                "analyst_id": a["analyst_id"],
                "analyst_name": a["analyst_name"],
                "cases": cases,
                "median_minutes": round(med) if med is not None else None,
                "flip_rate": flip_rate,
                "accuracy": accuracy,
                "volume_norm": vol,
                "speed": spd,
                "score": composite_score(accuracy=accuracy, volume_norm=vol, speed=spd),
                "badges": award_badges(stats),
            }
        )

    analysts.sort(key=lambda x: (-x["score"], -x["cases"], x["analyst_name"]))
    provisional.sort(key=lambda x: (-x["cases"], x["analyst_name"]))

    total_cases = sum(a["cases"] for a in by.values())
    highlights = [
        f"{a['analyst_name']} earned {b['label']}"
        for a in analysts
        for b in a["badges"]
        if b["key"] in ("zero_fp", "sharpshooter", "workhorse")
    ][:8]

    return {
        "window_days": window_days,
        "generated_at": now.isoformat(),
        "team": {
            "cases": total_cases,
            "median_minutes": round(median(all_durations)) if all_durations else None,
            "flip_rate": round(total_flips / total_cases, 4) if total_cases else 0.0,
            "analyst_count": len(by),
        },
        "analysts": analysts,
        "provisional": provisional,
        "highlights": highlights,
    }
