"""Unit tests for Feature 7 — branded reports (pure parts).

The DB aggregation (gather) and PDF render are validated on the stack; here we
lock the deterministic logic: schedule/period math, template registry, report
context assembly, and section selection.
"""

from __future__ import annotations

from datetime import datetime, timezone

from isoc_api.reports import periods, registry
from isoc_api.reports.data import build_report_context, select_sections


def _dt(y, m, d, h=0):
    return datetime(y, m, d, h, tzinfo=timezone.utc)


# ── periods.next_run_after ──────────────────────────────────────────────────
def test_next_run_after_monthly_is_first_of_next_month_at_run_hour():
    # mid-June → 1 July 06:00
    assert periods.next_run_after("monthly", _dt(2026, 6, 15, 9)) == _dt(
        2026, 7, 1, periods.RUN_HOUR
    )


def test_next_run_after_monthly_december_rolls_year():
    assert periods.next_run_after("monthly", _dt(2026, 12, 20)) == _dt(2027, 1, 1, periods.RUN_HOUR)


def test_next_run_after_weekly_is_next_monday():
    # 2026-07-15 is a Wednesday → next Monday is 2026-07-20.
    assert periods.next_run_after("weekly", _dt(2026, 7, 15, 9)) == _dt(
        2026, 7, 20, periods.RUN_HOUR
    )


def test_next_run_after_weekly_from_monday_advances_a_full_week():
    # 2026-07-20 is a Monday → must go to the NEXT Monday, not stay.
    assert periods.next_run_after("weekly", _dt(2026, 7, 20, 3)) == _dt(
        2026, 7, 27, periods.RUN_HOUR
    )


def test_next_run_after_unknown_cadence_falls_back_to_monthly():
    assert periods.next_run_after("nonsense", _dt(2026, 6, 15)) == _dt(2026, 7, 1, periods.RUN_HOUR)


# ── periods.period_for ──────────────────────────────────────────────────────
def test_period_for_monthly_is_previous_calendar_month():
    start, end = periods.period_for("monthly", _dt(2026, 7, 1, periods.RUN_HOUR))
    assert start == _dt(2026, 6, 1)
    assert (end.year, end.month, end.day, end.hour, end.minute) == (2026, 6, 30, 23, 59)


def test_period_for_monthly_january_rolls_to_prior_december():
    start, end = periods.period_for("monthly", _dt(2026, 1, 1, periods.RUN_HOUR))
    assert start == _dt(2025, 12, 1)
    assert end.month == 12 and end.year == 2025


def test_period_for_weekly_is_prior_monday_to_sunday():
    # Fire on Monday 2026-07-20 → report the previous week Mon 07-13 .. Sun 07-19.
    start, end = periods.period_for("weekly", _dt(2026, 7, 20, periods.RUN_HOUR))
    assert start == _dt(2026, 7, 13)
    assert end.year == 2026 and end.month == 7 and end.day == 19 and end.hour == 23


# ── periods.schedule_due ────────────────────────────────────────────────────
def test_schedule_due_never_run_is_due():
    assert periods.schedule_due(None, _dt(2026, 7, 12)) is True


def test_schedule_due_past_is_due_future_is_not():
    now = _dt(2026, 7, 12, 6)
    assert periods.schedule_due(_dt(2026, 7, 12, 5), now) is True
    assert periods.schedule_due(_dt(2026, 7, 12, 7), now) is False


def test_six_month_starts_trails_and_rolls_year():
    assert periods.six_month_starts(2026, 2) == [
        (2025, 9),
        (2025, 10),
        (2025, 11),
        (2025, 12),
        (2026, 1),
        (2026, 2),
    ]


# ── registry ────────────────────────────────────────────────────────────────
def test_registry_has_three_builtins_and_default():
    keys = {t["key"] for t in registry.list_templates()}
    assert keys == {"exec_summary", "monthly_ops", "ioc_digest"}
    assert registry.is_valid(registry.DEFAULT_TEMPLATE)
    assert registry.get_template("nope") is None


def test_registry_sections_are_known():
    for t in registry.list_templates():
        assert set(t["sections"]).issubset(set(registry.ALL_SECTIONS))


# ── data.select_sections ────────────────────────────────────────────────────
def test_select_sections_drops_empty_data_sections():
    requested = ["kpis", "ioc_digest", "top_customers", "source_volume"]
    data = {"iocs": [], "top_customers": [], "source_volume": [{"source": "wazuh", "count": 3}]}
    # kpis is always kept (no data-gate); the empty ones drop; order preserved.
    assert select_sections(requested, data) == ["kpis", "source_volume"]


# ── data.build_report_context ───────────────────────────────────────────────
def _sample_data():
    return {
        "period": {"label": "July 2026", "kind": "monthly"},
        "scope_label": "Acme",
        "totals": {"total": 100, "tp": 30, "fp": 60, "benign": 8, "pending": 2, "fp_rate": 60.0},
        "sla": {"avg_minutes": 120.0},
        "severity": {"critical": 5, "high": 20, "medium": 60, "low": 15},
        "llm": {"cost_usd": 4.5, "input_tokens": 1000, "output_tokens": 200},
        "daily_series": [
            {"date": "2026-07-01", "incidents": 4},
            {"date": "2026-07-02", "incidents": 8},
        ],
        "mttr_minutes": [30.0, 60.0, 90.0, 120.0, 600.0],
        "source_volume": [{"source": "wazuh", "count": 70}, {"source": "qradar", "count": 30}],
        "fp_trend": [{"month": "2026-07", "total": 100, "fp": 60, "fp_rate": 60.0}],
        "top_customers": [{"customer": "Acme", "total": 100, "tp": 30, "fp": 60, "benign": 8}],
        "iocs": [
            {
                "ioc_type": "ipv4-addr",
                "value": "1.2.3.4",
                "first_seen": "2026-07-01",
                "incidents": "INC-1",
            }
        ],
    }


def test_build_context_exec_summary_selects_expected_sections():
    ctx = build_report_context(_sample_data(), template_key="exec_summary")
    assert ctx["sections"] == ["kpis", "verdict_mix", "severity", "fp_trend", "closing"]
    assert ctx["template"]["key"] == "exec_summary"


def test_monthly_ops_follows_customer_report_footprint():
    # scope → stats → action status → incident detail → closing (cover is implicit)
    data = _sample_data()
    data["incidents"] = [
        {
            "case": "INC-1",
            "date": "01.07.2026",
            "category": "wazuh",
            "severity": "high",
            "actioned": False,
        }
    ]
    ctx = build_report_context(data, template_key="monthly_ops")
    assert ctx["sections"] == [
        "scope",
        "kpis",
        "verdict_mix",
        "severity",
        "daily_volume",
        "source_volume",
        "action_status",
        "incident_detail",
        "closing",
    ]


def test_action_status_taken_is_total_minus_pending():
    ctx = build_report_context(_sample_data(), template_key="monthly_ops")
    # sample: total 100, pending 2 → taken 98
    assert ctx["action_status"] == {"taken": 98, "pending": 2}


def test_incident_rows_shape_status_and_colour():
    data = _sample_data()
    data["incidents"] = [
        {
            "case": "INC-9",
            "date": "03.07.2026",
            "category": "Web",
            "severity": "high",
            "actioned": True,
        },
        {
            "case": "INC-8",
            "date": "02.07.2026",
            "category": "System",
            "severity": "medium",
            "actioned": False,
        },
    ]
    rows = build_report_context(data, template_key="monthly_ops")["incidents"]
    assert rows[0]["status"] == "Actioned" and rows[0]["actioned"] is True
    assert rows[0]["sev_color"] == "#F4A12C"  # high
    assert rows[1]["status"] == "Pending" and rows[1]["actioned"] is False


def test_incident_detail_section_drops_when_no_incidents():
    # sample data has no "incidents" key → incident_detail must not render.
    ctx = build_report_context(_sample_data(), template_key="monthly_ops")
    assert "incident_detail" not in ctx["sections"]
    assert "scope" in ctx["sections"] and "closing" in ctx["sections"]


def test_build_context_kpi_tiles_and_median_resolution():
    ctx = build_report_context(_sample_data(), template_key="monthly_ops")
    labels = {t["label"]: t["value"] for t in ctx["kpis"]}
    assert labels["Total Incidents"] == "100"
    assert labels["FP Rate"] == "60.0%"
    # median of [30,60,90,120,600] = 90 → "1h 30m"
    assert labels["Median Resolution"] == "1h 30m"
    assert labels["LLM Cost"] == "$4.50"


def test_build_context_verdict_bars_have_pct_and_color():
    ctx = build_report_context(_sample_data(), template_key="exec_summary")
    rows = {r["name"]: r for r in ctx["verdict_rows"]}
    assert rows["FP"]["count"] == 60
    assert rows["FP"]["pct"] == 60.0  # 60/100
    assert rows["FP"]["width"] == 100.0  # FP is the largest bucket
    assert rows["TP"]["color"] == "#FF4B6E"


def test_build_context_severity_uses_fixed_order():
    ctx = build_report_context(_sample_data(), template_key="exec_summary")
    assert [r["name"] for r in ctx["severity_rows"]] == ["critical", "high", "medium", "low"]


def test_build_context_mttr_percentiles():
    ctx = build_report_context(_sample_data(), template_key="monthly_ops")
    assert ctx["mttr"]["p50"] == "1h 30m"  # 90 min
    assert ctx["mttr"]["count"] == 5


def test_build_context_branding_accent_default_and_override():
    ctx = build_report_context(_sample_data(), template_key="exec_summary")
    assert ctx["branding"]["accent_color"] == "#00D4FF"  # theme default when None
    ctx2 = build_report_context(
        _sample_data(), template_key="exec_summary", branding={"accent_color": "#FF8800"}
    )
    assert ctx2["branding"]["accent_color"] == "#FF8800"


def test_build_context_empty_window_is_safe():
    empty = {
        "period": {"label": "July 2026"},
        "scope_label": "Acme",
        "totals": {"total": 0, "tp": 0, "fp": 0, "benign": 0, "pending": 0, "fp_rate": 0.0},
        "sla": {"avg_minutes": None},
        "severity": {},
        "llm": {"cost_usd": 0},
        "daily_series": [],
        "mttr_minutes": [],
        "source_volume": [],
        "fp_trend": [],
        "top_customers": [],
        "iocs": [],
    }
    ctx = build_report_context(empty, template_key="monthly_ops")
    # data-gated sections all drop; kpis + verdict/severity headings remain.
    assert "daily_volume" not in ctx["sections"]
    assert "mttr" not in ctx["sections"]
    assert "top_customers" not in ctx["sections"]
    assert {t["label"]: t["value"] for t in ctx["kpis"]}["Median Resolution"] == "—"


def test_build_context_unknown_template_falls_back_to_default():
    ctx = build_report_context(_sample_data(), template_key="does_not_exist")
    assert ctx["template"]["key"] == registry.DEFAULT_TEMPLATE


def test_build_context_summary_text_narrates_headline_numbers():
    ctx = build_report_context(_sample_data(), template_key="monthly_ops")
    s = ctx["summary_text"]
    assert "100" in s  # total
    assert "60.0%" in s  # fp rate
    assert "1h 30m" in s  # median resolution (90 min)
    assert "wazuh" in s  # top source


def test_build_context_summary_text_empty_window():
    empty = {
        "period": {"label": "July 2026"},
        "scope_label": "Acme",
        "totals": {"total": 0, "tp": 0, "fp": 0, "benign": 0, "pending": 0, "fp_rate": 0.0},
        "sla": {"avg_minutes": None},
        "severity": {},
        "llm": {"cost_usd": 0},
        "daily_series": [],
        "mttr_minutes": [],
        "source_volume": [],
        "fp_trend": [],
        "top_customers": [],
        "iocs": [],
    }
    ctx = build_report_context(empty, template_key="monthly_ops")
    assert "No incidents" in ctx["summary_text"]
