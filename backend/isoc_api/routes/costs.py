"""Cost Dashboard — LLM spend, imputed at read time from recorded token counts.

`LLMCall.cost_usd` isn't populated on write, so we price the recorded tokens
against `llm/pricing.py`'s public list-price table (clearly labelled estimates;
self-hosted models are $0 — the BYOK-savings story). Admin-only, global.

The aggregation (`build_dashboard`) is pure + unit-tested; the endpoint only
runs the two grouped SQL queries and feeds it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import require_admin
from ..db.models import Incident, LLMCall, User
from ..db.session import get_session
from ..llm import pricing

router = APIRouter()

# "What a hosted model would have cost" reference for the BYOK-savings figure —
# self-hosted tokens priced at a mid-tier (sonnet-ish) rate, USD per 1M.
_SAVINGS_REF: tuple[float, float] = (3.0, 15.0)

PRICING_NOTE = (
    "Estimated from public list prices — not billing-grade. Self-hosted models are $0; "
    "savings price those tokens at a mid-tier hosted rate."
)


def build_dashboard(rows: list[dict], top_rows: list[dict], *, window_days: int) -> dict[str, Any]:
    """Pure builder. `rows`: one per (day, model) with token sums/calls/avg latency.
    `top_rows`: one per (incident_id, model) with token sums/calls/case_number."""
    by_model: dict[str, dict] = {}
    by_day: dict[Any, dict] = {}
    total_cost = 0.0
    total_in = total_out = total_calls = 0
    savings = 0.0

    for r in rows:
        model = r.get("model") or "unknown"
        in_t = int(r.get("input_tokens") or 0)
        out_t = int(r.get("output_tokens") or 0)
        calls = int(r.get("calls") or 0)
        cost = pricing.impute_cost_usd(model, in_t, out_t)
        total_cost += cost
        total_in += in_t
        total_out += out_t
        total_calls += calls

        m = by_model.setdefault(
            model,
            {
                "model": model,
                "calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0,
                "_lat_sum": 0.0,
                "_lat_n": 0,
                "is_local": pricing.is_local(model),
            },
        )
        m["calls"] += calls
        m["input_tokens"] += in_t
        m["output_tokens"] += out_t
        m["cost_usd"] += cost
        lat = r.get("avg_latency_ms")
        if lat is not None and calls:
            m["_lat_sum"] += float(lat) * calls
            m["_lat_n"] += calls

        day = r.get("day")
        d = by_day.setdefault(day, {"day": day, "cost_usd": 0.0, "calls": 0, "tokens": 0})
        d["cost_usd"] += cost
        d["calls"] += calls
        d["tokens"] += in_t + out_t

        if pricing.is_local(model):
            savings += (in_t / 1_000_000.0) * _SAVINGS_REF[0] + (
                out_t / 1_000_000.0
            ) * _SAVINGS_REF[1]

    models_out = [
        {
            "model": m["model"],
            "calls": m["calls"],
            "input_tokens": m["input_tokens"],
            "output_tokens": m["output_tokens"],
            "cost_usd": round(m["cost_usd"], 4),
            "avg_latency_ms": round(m["_lat_sum"] / m["_lat_n"]) if m["_lat_n"] else None,
            "is_local": m["is_local"],
        }
        for m in by_model.values()
    ]
    models_out.sort(key=lambda x: (-x["cost_usd"], -x["calls"]))

    def _day_iso(v: Any) -> str:
        return v.isoformat() if hasattr(v, "isoformat") else str(v)

    days_out = sorted(
        (
            {
                "day": _day_iso(d["day"]),
                "cost_usd": round(d["cost_usd"], 4),
                "calls": d["calls"],
                "tokens": d["tokens"],
            }
            for d in by_day.values()
        ),
        key=lambda x: x["day"],
    )

    inc: dict[Any, dict] = {}
    for r in top_rows:
        iid = r.get("incident_id")
        if iid is None:
            continue
        cost = pricing.impute_cost_usd(
            r.get("model"), r.get("input_tokens"), r.get("output_tokens")
        )
        e = inc.setdefault(
            iid,
            {
                "incident_id": str(iid),
                "case_number": r.get("case_number"),
                "cost_usd": 0.0,
                "calls": 0,
            },
        )
        e["cost_usd"] += cost
        e["calls"] += int(r.get("calls") or 0)
    top = sorted(inc.values(), key=lambda x: -x["cost_usd"])[:10]
    for t in top:
        t["cost_usd"] = round(t["cost_usd"], 4)

    return {
        "window_days": window_days,
        "total_cost_usd": round(total_cost, 4),
        "total_tokens": total_in + total_out,
        "total_input_tokens": total_in,
        "total_output_tokens": total_out,
        "total_calls": total_calls,
        "avg_cost_per_call_usd": round(total_cost / total_calls, 6) if total_calls else 0.0,
        "byok_savings_usd": round(savings, 4),
        "by_model": models_out,
        "by_day": days_out,
        "top_incidents": top,
        "pricing_note": PRICING_NOTE,
    }


@router.get("/dashboard")
async def cost_dashboard(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
    window_days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    day_col = func.date_trunc("day", LLMCall.created_at).label("day")

    rows = (
        await session.execute(
            select(
                day_col,
                LLMCall.model,
                func.sum(LLMCall.input_tokens).label("input_tokens"),
                func.sum(LLMCall.output_tokens).label("output_tokens"),
                func.count(LLMCall.id).label("calls"),
                func.avg(LLMCall.latency_ms).label("avg_latency_ms"),
            )
            .where(LLMCall.created_at >= cutoff)
            .group_by(day_col, LLMCall.model)
        )
    ).all()
    row_dicts = [
        {
            "day": r.day.date() if hasattr(r.day, "date") else r.day,
            "model": r.model,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "calls": r.calls,
            "avg_latency_ms": r.avg_latency_ms,
        }
        for r in rows
    ]

    top_raw = (
        await session.execute(
            select(
                LLMCall.incident_id,
                LLMCall.model,
                func.sum(LLMCall.input_tokens).label("input_tokens"),
                func.sum(LLMCall.output_tokens).label("output_tokens"),
                func.count(LLMCall.id).label("calls"),
                Incident.case_number,
            )
            .join(Incident, Incident.id == LLMCall.incident_id, isouter=True)
            .where(LLMCall.created_at >= cutoff, LLMCall.incident_id.is_not(None))
            .group_by(LLMCall.incident_id, LLMCall.model, Incident.case_number)
        )
    ).all()
    top_dicts = [
        {
            "incident_id": r.incident_id,
            "model": r.model,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "calls": r.calls,
            "case_number": r.case_number,
        }
        for r in top_raw
    ]

    out = build_dashboard(row_dicts, top_dicts, window_days=window_days)
    out["generated_at"] = datetime.now(timezone.utc).isoformat()
    return out
