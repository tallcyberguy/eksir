"""Async DB aggregation for reports (Feature 7).

Reuses the platform's existing analytics rather than inventing parallel numbers:
  • the monthly-summary aggregation (also serves routes/reports.monthly)
  • feature-6 per-source volume (date_trunc GROUP BY)
  • feature-4's confirmed-IOC selection (Incident.verdict==TP, not excluded)

Range-based (start/end) so it serves both monthly on-demand reports and the
weekly cron. All queries are tenant-scoped via scope_clause_for_incidents.
"""

from __future__ import annotations

import calendar
from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.tenancy import TenantScope, scope_clause_for_incidents
from ..db.enums import Severity, Verdict
from ..db.models import Incident, IOCRecord, LLMCall
from ..threat_intel import export as ioc_export
from . import periods

_RESOLUTION_MIN = func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0
_IOC_DIGEST_CAP = 200  # deduped indicators shown in the digest table
# Notable incidents listed in the paginated detail table (crit/high/med, newest
# first) — mirrors the customer report's "notification details" pages.
_INCIDENT_DETAIL_CAP = 150


def month_window(year: int, month: int) -> tuple[datetime, datetime, str, str]:
    """(start, end, label, kind) for a calendar month — the on-demand default."""
    start, end = periods.month_bounds(year, month)
    return start, end, f"{calendar.month_name[month]} {year}", "monthly"


async def gather_monthly_stats(
    session: AsyncSession,
    scope: TenantScope,
    year: int,
    month: int,
    customer: str | None = None,
) -> dict:
    """The monthly-summary dict (kept as the single source shared with the
    /reports/monthly route). Range logic lives in the primitives below."""
    start, end, _label, _kind = month_window(year, month)
    data = await gather_report_data(session, scope, start=start, end=end, customer=customer)
    t = data["totals"]
    return {
        "year": year,
        "month": month,
        "customer": customer,
        "total": t["total"],
        "tp": t["tp"],
        "fp": t["fp"],
        "benign": t["benign"],
        "pending": t["pending"],
        "fp_rate": t["fp_rate"],
        "avg_sla_minutes": data["sla"]["avg_minutes"],
        "severity_breakdown": data["severity"],
        "llm_total_cost_usd": data["llm"]["cost_usd"],
        "llm_input_tokens": data["llm"]["input_tokens"],
        "llm_output_tokens": data["llm"]["output_tokens"],
        "daily_series": data["daily_series"],
        "fp_trend": data["fp_trend"],
    }


async def gather_report_data(
    session: AsyncSession,
    scope: TenantScope,
    *,
    start: datetime,
    end: datetime,
    label: str | None = None,
    kind: str = "monthly",
    customer: str | None = None,
    include_iocs: bool = True,
) -> dict:
    """Full aggregation for a reporting window, tenant-scoped. `customer` narrows
    to a single customer; when None the all-scope top-customers table is filled."""
    scope_w = scope_clause_for_incidents(scope)

    def _win(q):
        q = q.where(Incident.created_at >= start, Incident.created_at <= end, scope_w)
        return q.where(Incident.customer == customer) if customer else q

    # ── Totals + LLM token counts (on Incident) ──────────────────────────
    agg = (
        await session.execute(
            _win(
                select(
                    func.count(Incident.id).label("total"),
                    func.sum(case((Incident.verdict == "TP", 1), else_=0)).label("tp"),
                    func.sum(case((Incident.verdict == "FP", 1), else_=0)).label("fp"),
                    func.sum(case((Incident.verdict == "benign", 1), else_=0)).label("benign"),
                    func.sum(case((Incident.verdict == "pending", 1), else_=0)).label("pending"),
                    func.avg(_RESOLUTION_MIN).label("avg_sla_minutes"),
                )
            )
        )
    ).one()
    total = int(agg.total or 0)
    fp = int(agg.fp or 0)
    totals = {
        "total": total,
        "tp": int(agg.tp or 0),
        "fp": fp,
        "benign": int(agg.benign or 0),
        "pending": int(agg.pending or 0),
        "fp_rate": round(fp / total * 100, 1) if total else 0.0,
    }

    # ── Severity breakdown ───────────────────────────────────────────────
    sev_rows = (
        await session.execute(
            _win(select(Incident.severity, func.count(Incident.id))).group_by(Incident.severity)
        )
    ).all()
    severity = {str(s): int(c) for s, c in sev_rows if s is not None}

    # ── LLM cost + tokens (llm_calls, scoped via incident join) ─────────
    # Same source the /monthly route uses so the shared helper is drop-in.
    llm = (
        await session.execute(
            select(
                func.sum(LLMCall.cost_usd).label("cost_usd"),
                func.sum(LLMCall.input_tokens).label("in_tok"),
                func.sum(LLMCall.output_tokens).label("out_tok"),
            )
            .join(Incident, Incident.id == LLMCall.incident_id, isouter=True)
            .where(LLMCall.created_at >= start, LLMCall.created_at <= end, scope_w)
        )
    ).one()

    # ── Daily volume (sparkline) ─────────────────────────────────────────
    daily_rows = (
        await session.execute(
            _win(
                select(
                    func.date_trunc("day", Incident.created_at).label("d"), func.count(Incident.id)
                )
            )
            .group_by("d")
            .order_by("d")
        )
    ).all()
    daily_series = [
        {"date": d.date().isoformat() if d else "n/a", "incidents": int(c)} for d, c in daily_rows
    ]

    # ── MTTR raw samples (percentiles computed in data.py) ───────────────
    mttr_q = select(_RESOLUTION_MIN).where(
        Incident.closed_at.is_not(None),
        Incident.created_at >= start,
        Incident.created_at <= end,
        scope_w,
    )
    if customer:
        mttr_q = mttr_q.where(Incident.customer == customer)
    mttr_rows = (await session.execute(mttr_q)).all()
    mttr_minutes = [float(m) for (m,) in mttr_rows if m is not None]

    # ── Per-source volume ────────────────────────────────────────────────
    src_rows = (
        await session.execute(
            _win(select(Incident.source_product, func.count(Incident.id))).group_by(
                Incident.source_product
            )
        )
    ).all()
    source_volume = [{"source": s, "count": int(c)} for s, c in src_rows]

    # ── 6-month FP-rate trend (anchored on the window's end month) ───────
    fp_trend = []
    for y, m in periods.six_month_starts(end.year, end.month):
        s, e = periods.month_bounds(y, m)
        tq = _select_fp_window(scope_w, s, e, customer)
        tr = (await session.execute(tq)).one()
        t_total = int(tr.total or 0)
        t_fp = int(tr.fp or 0)
        fp_trend.append(
            {
                "month": f"{y}-{m:02d}",
                "total": t_total,
                "fp": t_fp,
                "fp_rate": round(t_fp / t_total * 100, 1) if t_total else 0.0,
            }
        )

    # ── Top customers (all-scope reports only) ───────────────────────────
    top_customers: list[dict] = []
    if not customer:
        cust_rows = (
            await session.execute(
                select(
                    Incident.customer,
                    func.count(Incident.id).label("total"),
                    func.sum(case((Incident.verdict == "TP", 1), else_=0)).label("tp"),
                    func.sum(case((Incident.verdict == "FP", 1), else_=0)).label("fp"),
                    func.sum(case((Incident.verdict == "benign", 1), else_=0)).label("benign"),
                )
                .where(Incident.created_at >= start, Incident.created_at <= end, scope_w)
                .group_by(Incident.customer)
                .order_by(func.count(Incident.id).desc())
                .limit(10)
            )
        ).all()
        top_customers = [
            {
                "customer": r.customer or "Unknown",
                "total": int(r.total),
                "tp": int(r.tp or 0),
                "fp": int(r.fp or 0),
                "benign": int(r.benign or 0),
            }
            for r in cust_rows
        ]

    # ── Confirmed IOCs (feature-4 selection) ─────────────────────────────
    iocs: list[dict] = []
    if include_iocs:
        iq = (
            select(
                IOCRecord.ioc_type,
                IOCRecord.value,
                IOCRecord.first_seen_at,
                Incident.case_number,
                IOCRecord.tenant,
            )
            .join(Incident, IOCRecord.incident_id == Incident.id)
            .where(Incident.verdict == Verdict.TP)
            .where(IOCRecord.excluded.is_(False))
            .where(Incident.created_at >= start, Incident.created_at <= end, scope_w)
        )
        if customer:
            iq = iq.where(Incident.customer == customer)
        raw = [tuple(r) for r in (await session.execute(iq)).all()]
        deduped = ioc_export.dedupe(raw)
        iocs = [
            {
                "ioc_type": r.ioc_type,
                "value": r.value,
                "first_seen": r.first_seen.strftime("%Y-%m-%d") if r.first_seen else "",
                "incidents": ", ".join(r.incidents[:5]),
            }
            for r in deduped[:_IOC_DIGEST_CAP]
        ]

    # ── Notable-incident detail (paginated table) ───────────────────────
    inc_q = (
        select(
            Incident.case_number,
            Incident.created_at,
            Incident.source_product,
            Incident.severity,
            Incident.verdict,
        )
        .where(
            Incident.created_at >= start,
            Incident.created_at <= end,
            Incident.severity.in_([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]),
            scope_w,
        )
        .order_by(Incident.created_at.desc())
        .limit(_INCIDENT_DETAIL_CAP)
    )
    if customer:
        inc_q = inc_q.where(Incident.customer == customer)
    incidents = [
        {
            "case": r.case_number,
            "date": r.created_at.strftime("%d.%m.%Y") if r.created_at else "",
            "category": r.source_product or "—",
            "severity": str(r.severity) if r.severity else "—",
            "actioned": str(r.verdict) != "pending",
        }
        for r in (await session.execute(inc_q)).all()
    ]

    scope_label = customer or "All customers"
    return {
        "period": {
            "label": label or f"{start:%Y-%m-%d} – {end:%Y-%m-%d}",
            "start": start.isoformat(),
            "end": end.isoformat(),
            "kind": kind,
        },
        "scope_label": scope_label,
        "totals": totals,
        "sla": {
            "avg_minutes": round(float(agg.avg_sla_minutes), 1) if agg.avg_sla_minutes else None
        },
        "severity": severity,
        "llm": {
            "cost_usd": float(llm.cost_usd or 0),
            "input_tokens": int(llm.in_tok or 0),
            "output_tokens": int(llm.out_tok or 0),
        },
        "daily_series": daily_series,
        "mttr_minutes": mttr_minutes,
        "source_volume": source_volume,
        "fp_trend": fp_trend,
        "top_customers": top_customers,
        "iocs": iocs,
        "incidents": incidents,
    }


def _select_fp_window(scope_w, start: datetime, end: datetime, customer: str | None):
    q = select(
        func.count(Incident.id).label("total"),
        func.sum(case((Incident.verdict == "FP", 1), else_=0)).label("fp"),
    ).where(Incident.created_at >= start, Incident.created_at <= end, scope_w)
    return q.where(Incident.customer == customer) if customer else q
