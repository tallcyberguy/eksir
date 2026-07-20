"""Feature 6 — SOC dashboard trend aggregations (pure builders).

The DB queries (date_trunc GROUP BYs, tenant-scoped) live in routes/dashboard.py;
these take the raw rows and shape the time-series the charts consume. Pure +
unit-tested — the correctness (percentile math, bucketing, top-N + "other"
rollup, empty-window fallback) lives here, mirroring routes/costs.build_dashboard.
"""

from __future__ import annotations

from collections import defaultdict


def percentile(sorted_vals: list[float], p: float) -> float:
    """Linear-interpolation percentile (matches numpy 'linear' / Postgres
    percentile_cont). `sorted_vals` must be ascending; `p` in [0, 1]."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (len(sorted_vals) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (rank - lo)


def mttr_trend(rows: list[tuple[str, float | None]]) -> list[dict]:
    """Per-bucket resolution-time p50/p90/avg from `(bucket, minutes)` samples
    (one row per closed incident). Percentiles, not a single mean, so a few slow
    incidents don't distort the picture."""
    by_bucket: dict[str, list[float]] = defaultdict(list)
    for bucket, minutes in rows:
        if bucket and minutes is not None:
            by_bucket[bucket].append(float(minutes))
    out = []
    for bucket in sorted(by_bucket):
        vals = sorted(by_bucket[bucket])
        out.append(
            {
                "date": bucket,
                "p50": round(percentile(vals, 0.5), 1),
                "p90": round(percentile(vals, 0.9), 1),
                "avg": round(sum(vals) / len(vals), 1),
                "count": len(vals),
            }
        )
    return out


def source_volume_trend(rows: list[tuple[str, str | None, int]], *, top_n: int = 6) -> dict:
    """Per-source incident volume over time. Keeps the top-N sources by total and
    rolls the long tail into "other" so the chart stays legible. Returns
    `{"sources": [...ordered keys...], "series": [{date, <source>: n, ...}]}`."""
    totals: dict[str, int] = defaultdict(int)
    for _bucket, source, count in rows:
        totals[source or "unknown"] += int(count)
    top = [s for s, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]]
    top_set = set(top)
    tail = any(s not in top_set for s in totals)

    by_bucket: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for bucket, source, count in rows:
        s = source or "unknown"
        by_bucket[bucket][s if s in top_set else "other"] += int(count)

    keys = [*top, *(["other"] if tail else [])]
    series = []
    for bucket in sorted(by_bucket):
        row: dict = {"date": bucket}
        for k in keys:
            row[k] = by_bucket[bucket].get(k, 0)
        series.append(row)
    return {"sources": keys, "series": series}


def verdict_mix_trend(rows: list[tuple[str, str, int]]) -> dict:
    """Verdict counts per bucket over time, pivoted for a stacked chart.
    Returns `{"verdicts": [...sorted...], "series": [{date, <verdict>: n}]}`."""
    by_bucket: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    verdicts: set[str] = set()
    for bucket, verdict, count in rows:
        v = str(verdict)
        by_bucket[bucket][v] += int(count)
        verdicts.add(v)
    keys = sorted(verdicts)
    series = []
    for bucket in sorted(by_bucket):
        row: dict = {"date": bucket}
        for k in keys:
            row[k] = by_bucket[bucket].get(k, 0)
        series.append(row)
    return {"verdicts": keys, "series": series}
