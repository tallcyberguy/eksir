"""Pure report-context assembly (Feature 7).

Takes the raw aggregation `gather.gather_report_data` returns and shapes it into
the flat context the Jinja base template renders — KPI tiles, colour-coded
breakdown rows with bar widths, resolution percentiles, and section selection.
No DB, no I/O: unit-tested in tests/test_reports.py.
"""

from __future__ import annotations

from ..analytics.trends import percentile
from .registry import get_template

# Palette mirrors the frontend (app/reports/page.tsx) so PDF ≈ dashboard.
VERDICT_COLORS = {
    "TP": "#FF4B6E",
    "FP": "#F4A12C",
    "benign": "#00E08F",
    "pending": "#A6B0CF",
}
SEVERITY_COLORS = {
    "critical": "#FF4B6E",
    "high": "#F4A12C",
    "medium": "#00E5FF",
    "low": "#A6B0CF",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Scope-of-service bullets for the report's scope slide (mirrors the customer
# report "KAPSAM" footprint). Static default; per-tenant text is a follow-up.
SCOPE_BULLETS = (
    "24/7 monitoring and triage of SIEM & EDR alerts",
    "Investigation and enrichment of alerts requiring attention",
    "Reporting of cases that need customer control or action",
    "Detection and containment of malicious activity",
    "Continuous false-positive tuning to reduce alert noise",
)


def _fmt_int(n: int | float | None) -> str:
    return f"{int(n or 0):,}"


def _fmt_minutes(m: float | None) -> str:
    """Human resolution time: '—' / '45m' / '3h 12m' / '2d 4h'."""
    if m is None:
        return "—"
    m = int(round(m))
    if m < 60:
        return f"{m}m"
    if m < 60 * 24:
        return f"{m // 60}h {m % 60}m"
    return f"{m // 1440}d {(m % 1440) // 60}h"


def _pct(part: int, whole: int) -> float:
    return round(part / whole * 100, 1) if whole else 0.0


def _bars(counts: dict[str, int], colors: dict[str, str], order: dict | None = None) -> list[dict]:
    """Breakdown rows sorted by a fixed order (else by count desc), each with a
    0–100 bar width relative to the largest bucket."""
    items = [(k, int(v)) for k, v in counts.items() if v]
    if order is not None:
        items.sort(key=lambda kv: order.get(kv[0], 99))
    else:
        items.sort(key=lambda kv: (-kv[1], kv[0]))
    total = sum(v for _, v in items)
    top = max((v for _, v in items), default=0)
    return [
        {
            "name": k,
            "count": v,
            "pct": _pct(v, total),
            "width": round(v / top * 100, 1) if top else 0.0,
            "color": colors.get(k, "#A6B0CF"),
        }
        for k, v in items
    ]


def select_sections(requested: list[str], data: dict) -> list[str]:
    """Drop sections the gathered data can't fill, so the report never shows a
    hollow heading. Preserves the template's declared order."""
    empty_when_missing = {
        "top_customers": "top_customers",
        "ioc_digest": "iocs",
        "daily_volume": "daily_series",
        "fp_trend": "fp_trend",
        "source_volume": "source_volume",
        "mttr": "mttr_minutes",
        "incident_detail": "incidents",
    }
    out = []
    for s in requested:
        key = empty_when_missing.get(s)
        if key is not None and not data.get(key):
            continue
        out.append(s)
    return out


def _kpi_tiles(data: dict) -> list[dict]:
    t = data.get("totals", {})
    mins = sorted(data.get("mttr_minutes") or [])
    p50 = percentile(mins, 0.5) if mins else None
    tiles = [
        {"label": "Total Incidents", "value": _fmt_int(t.get("total", 0)), "accent": "fg"},
        {"label": "True Positives", "value": _fmt_int(t.get("tp", 0)), "accent": "danger"},
        {"label": "False Positives", "value": _fmt_int(t.get("fp", 0)), "accent": "warning"},
        {"label": "FP Rate", "value": f"{t.get('fp_rate', 0)}%", "accent": "warning"},
        {"label": "Median Resolution", "value": _fmt_minutes(p50), "accent": "positive"},
    ]
    cost = float(data.get("llm", {}).get("cost_usd") or 0)
    if cost:
        tiles.append({"label": "LLM Cost", "value": f"${cost:.2f}", "accent": "muted"})
    return tiles


def _daily_bars(series: list[dict]) -> dict:
    """Inline-SVG-friendly daily volume: each point carries a 0–100 height."""
    top = max((int(p.get("incidents", 0)) for p in series), default=0)
    points = [
        {
            "date": p.get("date", ""),
            "incidents": int(p.get("incidents", 0)),
            "height": round(int(p.get("incidents", 0)) / top * 100, 1) if top else 0.0,
        }
        for p in series
    ]
    return {"max": top, "points": points}


def _mttr_summary(data: dict) -> dict:
    mins = sorted(data.get("mttr_minutes") or [])
    return {
        "p50": _fmt_minutes(percentile(mins, 0.5) if mins else None),
        "p90": _fmt_minutes(percentile(mins, 0.9) if mins else None),
        "avg": _fmt_minutes(sum(mins) / len(mins) if mins else None),
        "count": len(mins),
    }


def _source_rows(sources: list[dict]) -> list[dict]:
    items = sorted(sources, key=lambda s: -int(s.get("count", 0)))
    top = max((int(s.get("count", 0)) for s in items), default=0)
    return [
        {
            "source": s.get("source") or "unknown",
            "count": int(s.get("count", 0)),
            "width": round(int(s.get("count", 0)) / top * 100, 1) if top else 0.0,
        }
        for s in items
    ]


def _summary_text(data: dict) -> str:
    """A short deterministic narrative for the executive-summary slide — no LLM,
    just the headline numbers phrased for a customer reader."""
    t = data.get("totals", {})
    total = int(t.get("total", 0))
    scope = data.get("scope_label", "the environment")
    period = (data.get("period") or {}).get("label", "this period")
    if not total:
        return f"No incidents were recorded for {scope} during {period}."
    parts = [f"During {period}, the SOC triaged {_fmt_int(total)} alerts for {scope}."]
    parts.append(
        f"{_fmt_int(t.get('tp', 0))} were confirmed true positives and "
        f"{_fmt_int(t.get('fp', 0))} false positives "
        f"({t.get('fp_rate', 0)}% false-positive rate)."
    )
    mins = sorted(data.get("mttr_minutes") or [])
    if mins:
        parts.append(f"Median time to resolution was {_fmt_minutes(percentile(mins, 0.5))}.")
    src = data.get("source_volume") or []
    if src:
        top = max(src, key=lambda s: int(s.get("count", 0)))
        parts.append(f"The most active detection source was {top.get('source') or 'unknown'}.")
    return " ".join(parts)


def _action_status(data: dict) -> dict:
    """Actioned vs pending callout — mirrors the report's 'action status' slide.
    Actioned = a verdict has been committed (analyst decided); pending = still
    awaiting a decision."""
    t = data.get("totals", {})
    pending = int(t.get("pending", 0))
    taken = int(t.get("total", 0)) - pending
    return {"taken": taken, "pending": pending}


def _incident_rows(incidents: list[dict]) -> list[dict]:
    """Shape the notable-incident detail rows: severity colour + a status label."""
    out = []
    for r in incidents:
        sev = (r.get("severity") or "").lower()
        out.append(
            {
                "case": r.get("case", ""),
                "date": r.get("date", ""),
                "category": r.get("category", "—"),
                "severity": sev or "—",
                "sev_color": SEVERITY_COLORS.get(sev, "#A6B0CF"),
                "status": "Actioned" if r.get("actioned") else "Pending",
                "actioned": bool(r.get("actioned")),
            }
        )
    return out


def _ioc_block(iocs: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    for r in iocs:
        by_type[r.get("ioc_type", "unknown")] = by_type.get(r.get("ioc_type", "unknown"), 0) + 1
    return {
        "rows": iocs,
        "total": len(iocs),
        "by_type": sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0])),
    }


def build_report_context(
    data: dict,
    *,
    template_key: str,
    branding: dict | None = None,
    generated_at: str = "",
) -> dict:
    """Assemble the flat Jinja context for the report base template. `data` is
    the gather.gather_report_data() output; `branding` is
    {logo_data_uri, accent_color, display_name} or None (falls back to theme)."""
    tmpl = get_template(template_key) or get_template("monthly_ops")
    assert tmpl is not None  # registry guarantees monthly_ops exists
    sections = select_sections(tmpl["sections"], data)
    branding = branding or {}

    totals = data.get("totals", {})
    verdict_counts = {
        "TP": totals.get("tp", 0),
        "FP": totals.get("fp", 0),
        "benign": totals.get("benign", 0),
        "pending": totals.get("pending", 0),
    }

    return {
        "template": {"key": tmpl["key"], "title": tmpl["title"]},
        "sections": sections,
        "period": data.get("period", {}),
        "scope_label": data.get("scope_label", "All customers"),
        "generated_at": generated_at,
        "summary_text": _summary_text(data),
        "branding": {
            "logo_data_uri": branding.get("logo_data_uri"),
            "accent_color": branding.get("accent_color") or "#00D4FF",
            "display_name": branding.get("display_name"),
        },
        "kpis": _kpi_tiles(data),
        "verdict_rows": _bars(verdict_counts, VERDICT_COLORS),
        "severity_rows": _bars(data.get("severity", {}), SEVERITY_COLORS, _SEVERITY_ORDER),
        "daily": _daily_bars(data.get("daily_series", [])),
        "mttr": _mttr_summary(data),
        "source_rows": _source_rows(data.get("source_volume", [])),
        "fp_trend": data.get("fp_trend", []),
        "top_customers": data.get("top_customers", []),
        "iocs": _ioc_block(data.get("iocs", [])),
        "action_status": _action_status(data),
        "incidents": _incident_rows(data.get("incidents", [])),
        "scope_bullets": list(SCOPE_BULLETS),
        "llm": data.get("llm", {}),
    }
