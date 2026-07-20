"""Dashboard metrics — totals, breakdowns, time-series for the home screen."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics import trends as trend_agg
from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.enums import Verdict as V
from ..db.models import Incident, IOCRecord, LLMCall, User
from ..db.session import get_session
from ..schemas import DashboardStats

router = APIRouter()

_WINDOWS = {
    "24h": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}


@router.get("/stats", response_model=DashboardStats)
async def stats(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window: str = Query(default="30d"),
) -> DashboardStats:
    cutoff = datetime.now(timezone.utc) - _WINDOWS.get(window, _WINDOWS["30d"])
    scope_w = scope_clause_for_incidents(scope)

    total = (
        await session.scalar(
            select(func.count(Incident.id)).where(Incident.created_at >= cutoff, scope_w)
        )
        or 0
    )

    # IOCs: scope through their parent incident
    iocs = (
        await session.scalar(
            select(func.count(func.distinct(IOCRecord.value)))
            .join(Incident, Incident.id == IOCRecord.incident_id)
            .where(IOCRecord.created_at >= cutoff, scope_w)
        )
        or 0
    )

    avg_sla = await session.scalar(
        select(
            func.avg(func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0)
        ).where(
            Incident.closed_at.is_not(None),
            Incident.created_at >= cutoff,
            scope_w,
        )
    )

    status_rows = (
        await session.execute(
            select(Incident.status, func.count(Incident.id))
            .where(Incident.created_at >= cutoff, scope_w)
            .group_by(Incident.status)
        )
    ).all()
    status_breakdown = {str(s): int(c) for s, c in status_rows}

    sev_rows = (
        await session.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(Incident.created_at >= cutoff, scope_w)
            .group_by(Incident.severity)
        )
    ).all()
    severity_breakdown = {str(s): int(c) for s, c in sev_rows}

    # Verdict series — monthly buckets
    series = (
        await session.execute(
            select(
                func.date_trunc("day", Incident.closed_at).label("d"),
                Incident.verdict,
                func.count(Incident.id),
            )
            .where(
                Incident.closed_at.is_not(None),
                Incident.closed_at >= cutoff,
                scope_w,
            )
            .group_by("d", Incident.verdict)
            .order_by("d")
        )
    ).all()
    series_by_day: dict[str, dict[str, int]] = {}
    for d, v, c in series:
        key = d.date().isoformat() if d else "n/a"
        series_by_day.setdefault(key, {})[str(v)] = int(c)
    verdict_series = [{"date": k, **v} for k, v in sorted(series_by_day.items())]

    # Monthly cases vs incidents (last 6 months)
    six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)
    monthly = (
        await session.execute(
            select(
                func.date_trunc("month", Incident.created_at).label("m"),
                func.count(Incident.id),
            )
            .where(Incident.created_at >= six_months_ago, scope_w)
            .group_by("m")
            .order_by("m")
        )
    ).all()
    monthly_cases = [
        {"month": (m.date().isoformat() if m else "n/a"), "incidents": int(c)} for m, c in monthly
    ]

    # FP count + total closed for FP rate
    fp_count = (
        await session.scalar(
            select(func.count(Incident.id)).where(
                Incident.created_at >= cutoff, scope_w, Incident.verdict == V.FP
            )
        )
        or 0
    )
    total_closed = (
        await session.scalar(
            select(func.count(Incident.id)).where(
                Incident.created_at >= cutoff, scope_w, Incident.closed_at.is_not(None)
            )
        )
        or 0
    )

    # Top 10 IOCs by incident frequency
    ioc_rows = (
        await session.execute(
            select(
                IOCRecord.value,
                IOCRecord.ioc_type,
                func.count(func.distinct(IOCRecord.incident_id)).label("cnt"),
            )
            .join(Incident, Incident.id == IOCRecord.incident_id)
            .where(IOCRecord.created_at >= cutoff, scope_w)
            .group_by(IOCRecord.value, IOCRecord.ioc_type)
            .order_by(desc("cnt"))
            .limit(10)
        )
    ).all()
    top_indicators = [
        {"value": r.value, "type": str(r.ioc_type), "count": int(r.cnt)} for r in ioc_rows
    ]

    # Top 10 alert rules by incident count
    rule_rows = (
        await session.execute(
            select(Incident.rule_name, func.count(Incident.id).label("cnt"))
            .where(Incident.created_at >= cutoff, scope_w, Incident.rule_name.is_not(None))
            .group_by(Incident.rule_name)
            .order_by(desc("cnt"))
            .limit(10)
        )
    ).all()
    top_rules = [{"rule": r.rule_name, "count": int(r.cnt)} for r in rule_rows]

    # ── SLA breakdowns ──────────────────────────────────────────────────
    # `sla_minutes` is the close time in minutes from incident.created_at to
    # incident.closed_at. Only closed incidents contribute.
    #
    # We use plain AVG (not percentiles) here because the dashboard audience
    # is SOC managers, not SREs — they want the actual number for the period,
    # broken out by priority. Averages are easier to read at a glance and
    # match how SLAs are typically reported to leadership.

    _sla_expr = func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0

    # A. Trend — daily average per severity. SQL groups by (day, severity);
    # we pivot in Python so the frontend gets one row per day with severity
    # columns, ready for a 4-line chart.
    trend_rows = (
        await session.execute(
            select(
                func.date_trunc("day", Incident.closed_at).label("d"),
                Incident.severity.label("sev"),
                func.avg(_sla_expr).label("avg"),
                func.count(Incident.id).label("cnt"),
            )
            .where(Incident.closed_at.is_not(None), Incident.closed_at >= cutoff, scope_w)
            .group_by("d", Incident.severity)
            .order_by("d")
        )
    ).all()
    # Pivot rows + compute weighted overall avg per day. The frontend renders
    # two charts off this one structure: an "overall" line (sla-trend panel)
    # and a per-severity line set (sla-by-sev panel). Building both in one
    # query keeps things consistent across the panels.
    _trend_pivot: dict[str, dict] = {}
    _day_sums: dict[str, tuple[float, int]] = {}  # date → (weighted_sum, total_count)
    for r in trend_rows:
        key = r.d.date().isoformat() if r.d else "n/a"
        row = _trend_pivot.setdefault(key, {"date": key, "count": 0})
        sev = str(r.sev).split(".")[-1].lower()
        row[sev] = round(float(r.avg), 1) if r.avg is not None else None
        cnt = int(r.cnt)
        row["count"] += cnt
        if r.avg is not None and cnt > 0:
            ws, tc = _day_sums.get(key, (0.0, 0))
            _day_sums[key] = (ws + float(r.avg) * cnt, tc + cnt)
    for key, row in _trend_pivot.items():
        ws, tc = _day_sums.get(key, (0.0, 0))
        row["overall"] = round(ws / tc, 1) if tc > 0 else None
    sla_trend = [_trend_pivot[k] for k in sorted(_trend_pivot.keys())]

    # B. Distribution — histogram of close times bucketed. Buckets chosen for
    # the SOC analyst use case: most closes should land in the first three
    # buckets; the long tail bucket signals the cases that needed real work.
    _buckets = [
        ("≤ 5 min", 0, 5),
        ("5–30 min", 5, 30),
        ("30 min–2 h", 30, 120),
        ("2–24 h", 120, 1440),
        ("> 24 h", 1440, None),
    ]
    sla_distribution: list[dict] = []
    for label, lo, hi in _buckets:
        conditions = [
            Incident.closed_at.is_not(None),
            Incident.closed_at >= cutoff,
            scope_w,
            _sla_expr >= lo,
        ]
        if hi is not None:
            conditions.append(_sla_expr < hi)
        cnt = await session.scalar(select(func.count(Incident.id)).where(*conditions)) or 0
        sla_distribution.append({"bucket": label, "count": int(cnt)})

    # C. By severity — average close time grouped by severity (critical/high/medium/low).
    # Ordered critical → low so the chart reads left-to-right by urgency.
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    by_sev_rows = (
        await session.execute(
            select(
                Incident.severity,
                func.avg(_sla_expr).label("avg"),
                func.count(Incident.id).label("cnt"),
            )
            .where(Incident.closed_at.is_not(None), Incident.closed_at >= cutoff, scope_w)
            .group_by(Incident.severity)
        )
    ).all()
    sla_by_severity = sorted(
        [
            {
                "severity": str(r.severity).split(".")[-1].lower(),
                "avg": round(float(r.avg), 1) if r.avg is not None else None,
                "count": int(r.cnt),
            }
            for r in by_sev_rows
        ],
        key=lambda x: _sev_order.get(x["severity"], 99),
    )

    # ── Extra KPIs + series for opt-in panels ───────────────────────────
    # True-positive count (counterpart to false_positive_count).
    tp_count = (
        await session.scalar(
            select(func.count(Incident.id)).where(
                Incident.created_at >= cutoff, scope_w, Incident.verdict == V.TP
            )
        )
        or 0
    )

    # Daily incidents — count per day inside the active window. Used by the
    # area chart panel "Daily Incidents". Bucketed by created_at so newly
    # opened incidents still appear even before they close.
    daily_rows = (
        await session.execute(
            select(
                func.date_trunc("day", Incident.created_at).label("d"),
                func.count(Incident.id),
            )
            .where(Incident.created_at >= cutoff, scope_w)
            .group_by("d")
            .order_by("d")
        )
    ).all()
    daily_incidents = [
        {"date": (d.date().isoformat() if d else "n/a"), "count": int(c)} for d, c in daily_rows
    ]

    # FP rate trend — last 6 calendar months. Each row holds (total_closed,
    # fp_count) so the frontend can render rate = fp / total. We split it on
    # the wire instead of dividing here so the chart can show "0/0 = n/a" for
    # months with no closes (vs the lying 0%).
    fp_trend_rows = (
        await session.execute(
            select(
                func.date_trunc("month", Incident.created_at).label("m"),
                func.count(Incident.id).filter(Incident.closed_at.is_not(None)).label("closed"),
                func.count(Incident.id).filter(Incident.verdict == V.FP).label("fps"),
            )
            .where(Incident.created_at >= six_months_ago, scope_w)
            .group_by("m")
            .order_by("m")
        )
    ).all()
    fp_rate_trend = [
        {
            "month": (m.date().isoformat() if m else "n/a"),
            "closed": int(closed),
            "fps": int(fps),
            "rate": round(float(fps) / float(closed) * 100, 1) if closed else None,
        }
        for m, closed, fps in fp_trend_rows
    ]

    # LLM usage for the current calendar month. Aggregating all calls regardless
    # of incident scope because LLM budget tracking is a global concern (a single
    # admin dashboard shouldn't need to know which tenant burned the budget).
    # If we ever want per-tenant LLM breakdowns we'd add a tenant_id to LLMCall.
    month_start = datetime.now(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    llm_row = (
        await session.execute(
            select(
                func.coalesce(func.sum(LLMCall.input_tokens), 0),
                func.coalesce(func.sum(LLMCall.output_tokens), 0),
                func.coalesce(func.sum(LLMCall.cost_usd), 0),
                func.count(LLMCall.id),
            ).where(LLMCall.created_at >= month_start)
        )
    ).one()
    llm_input_tokens_month, llm_output_tokens_month, llm_cost_month, llm_call_count = llm_row

    return DashboardStats(
        total_incidents=int(total),
        unique_iocs=int(iocs),
        avg_sla_minutes=float(avg_sla) if avg_sla else None,
        true_positive_count=int(tp_count),
        false_positive_count=int(fp_count),
        total_closed=int(total_closed),
        status_breakdown=status_breakdown,
        severity_breakdown=severity_breakdown,
        verdict_series=verdict_series,
        monthly_cases=monthly_cases,
        top_indicators=top_indicators,
        top_rules=top_rules,
        sla_trend=sla_trend,
        sla_distribution=sla_distribution,
        sla_by_severity=sla_by_severity,
        daily_incidents=daily_incidents,
        fp_rate_trend=fp_rate_trend,
        llm_input_tokens_month=int(llm_input_tokens_month or 0),
        llm_output_tokens_month=int(llm_output_tokens_month or 0),
        llm_cost_month_usd=float(llm_cost_month or 0),
        llm_call_count_month=int(llm_call_count or 0),
    )


def _bucket_label(dt, hourly: bool) -> str:
    """date_trunc result → chart x-axis label."""
    return dt.strftime("%m-%d %H:00") if hourly else dt.date().isoformat()


@router.get("/trends")
async def trends(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window: str = Query(default="30d"),
) -> dict:
    """Time-series for the manager view (Feature 6): MTTR p50/p90 bands,
    per-source volume, and verdict mix over time. Tenant-scoped; read-only."""
    cutoff = datetime.now(timezone.utc) - _WINDOWS.get(window, _WINDOWS["30d"])
    scope_w = scope_clause_for_incidents(scope)
    hourly = window == "24h"
    grain = "hour" if hourly else "day"

    resolution_min = func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0

    # MTTR: one raw sample per closed incident → percentiles computed in Python.
    mttr_rows = (
        await session.execute(
            select(func.date_trunc(grain, Incident.closed_at), resolution_min).where(
                Incident.closed_at.is_not(None), Incident.closed_at >= cutoff, scope_w
            )
        )
    ).all()
    mttr_samples = [(_bucket_label(d, hourly), m) for d, m in mttr_rows if d is not None]

    # Per-source volume (by created_at). Group by the SELECT label (`grain` is a
    # bind param, so date_trunc in SELECT vs GROUP BY wouldn't match otherwise).
    src_rows = (
        await session.execute(
            select(
                func.date_trunc(grain, Incident.created_at).label("d"),
                Incident.source_product,
                func.count(Incident.id),
            )
            .where(Incident.created_at >= cutoff, scope_w)
            .group_by("d", Incident.source_product)
        )
    ).all()
    src_samples = [(_bucket_label(d, hourly), s, c) for d, s, c in src_rows if d is not None]

    # Verdict mix (by closed_at).
    vm_rows = (
        await session.execute(
            select(
                func.date_trunc(grain, Incident.closed_at).label("d"),
                Incident.verdict,
                func.count(Incident.id),
            )
            .where(Incident.closed_at.is_not(None), Incident.closed_at >= cutoff, scope_w)
            .group_by("d", Incident.verdict)
        )
    ).all()
    vm_samples = [(_bucket_label(d, hourly), str(v), c) for d, v, c in vm_rows if d is not None]

    return {
        "window": window,
        "mttr_trend": trend_agg.mttr_trend(mttr_samples),
        "source_volume": trend_agg.source_volume_trend(src_samples),
        "verdict_mix": trend_agg.verdict_mix_trend(vm_samples),
    }
