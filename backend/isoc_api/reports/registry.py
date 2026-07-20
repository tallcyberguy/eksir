"""Built-in report templates (Feature 7).

Templates are code-defined for day one (reusable across every tenant + period);
per-tenant DB-editable template *bodies* are a deliberate follow-up. A template
is just a title + an ordered list of section keys — all three render through the
single Jinja base (`templates/reports/report.html.j2`), which emits only the
sections present in the context. `data.select_sections` filters the requested
set to those the gathered data can actually fill.
"""

from __future__ import annotations

# Every section the base template knows how to render. Keep in sync with
# templates/reports/report.html.j2 and data.build_report_context.
ALL_SECTIONS = (
    "scope",  # scope-of-service bullets (KAPSAM)
    "kpis",  # headline tiles: total / TP / FP / FP-rate / MTTR / LLM cost
    "verdict_mix",  # verdict breakdown (table + inline bars)
    "severity",  # severity breakdown
    "daily_volume",  # incidents per day (inline SVG sparkline)
    "mttr",  # resolution-time p50/p90 (feature-6 trend)
    "source_volume",  # per-source incident counts (categories)
    "action_status",  # actioned vs pending callout
    "incident_detail",  # paginated notable-incident table (notification details)
    "fp_trend",  # 6-month false-positive-rate trend
    "top_customers",  # top customers by volume (all-scope / MSSP only)
    "ioc_digest",  # analyst-confirmed indicators
    "closing",  # thank-you / contact
)


TEMPLATES: dict[str, dict] = {
    "exec_summary": {
        "key": "exec_summary",
        "title": "Executive Summary",
        "description": "One-page management view: headline KPIs, verdict and "
        "severity mix, and the false-positive-rate trend.",
        "sections": ["kpis", "verdict_mix", "severity", "fp_trend", "closing"],
    },
    "monthly_ops": {
        "key": "monthly_ops",
        "title": "SOC & MDR Report",
        "description": "Full customer report: scope, KPIs, verdict/severity mix, "
        "daily volume, categories, action status, and a paginated detail of every "
        "notable incident.",
        "sections": [
            "scope",
            "kpis",
            "verdict_mix",
            "severity",
            "daily_volume",
            "source_volume",
            "action_status",
            "incident_detail",
            "closing",
        ],
    },
    "ioc_digest": {
        "key": "ioc_digest",
        "title": "Threat Indicator Digest",
        "description": "Analyst-confirmed indicators of compromise for the period, "
        "with headline KPIs and detection sources.",
        "sections": ["kpis", "ioc_digest", "source_volume", "closing"],
    },
}

DEFAULT_TEMPLATE = "monthly_ops"


def list_templates() -> list[dict]:
    """Public metadata for the template picker (no internal fields to hide, but
    return copies so callers can't mutate the registry)."""
    return [dict(t) for t in TEMPLATES.values()]


def get_template(key: str) -> dict | None:
    t = TEMPLATES.get(key)
    return dict(t) if t else None


def is_valid(key: str) -> bool:
    return key in TEMPLATES
