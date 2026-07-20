"""LLM cost budget guard.

Fail-safe: when a USD ceiling is reached the caller SKIPS the deep LLM call and
parks the incident for a human — it never auto-decides. Local/self-hosted models
price at $0 (see llm/pricing.py), so caps never fire on a local deployment.

`cap_reason` is a pure function (unit-tested); `over_budget` sums the persisted
LLMCall.cost_usd tallies.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..settings import settings


def cap_reason(
    *,
    spent_today: float,
    spent_incident: float,
    daily_cap: float,
    incident_cap: float,
) -> str | None:
    """Reason a call should be blocked, or None if within budget.

    A cap of 0 (or less) means that ceiling is disabled.
    """
    if daily_cap > 0 and spent_today >= daily_cap:
        return f"daily LLM budget cap reached (${spent_today:.2f} >= ${daily_cap:.2f})"
    if incident_cap > 0 and spent_incident >= incident_cap:
        return f"per-incident LLM budget cap reached (${spent_incident:.2f} >= ${incident_cap:.2f})"
    return None


async def over_budget(session, incident_id: uuid.UUID) -> str | None:
    """Return a block reason if today's or this incident's LLM spend hit its cap.

    Returns None when both caps are disabled (the default) so there is zero
    overhead on deployments that don't set a budget.
    """
    daily_cap = float(settings.llm_daily_cost_cap_usd or 0)
    incident_cap = float(settings.llm_incident_cost_cap_usd or 0)
    if daily_cap <= 0 and incident_cap <= 0:
        return None

    from sqlalchemy import func, select

    from ..db.models import LLMCall

    spent_today = 0.0
    if daily_cap > 0:
        day_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        spent_today = float(
            await session.scalar(
                select(func.coalesce(func.sum(LLMCall.cost_usd), 0)).where(
                    LLMCall.created_at >= day_start
                )
            )
            or 0
        )

    spent_incident = 0.0
    if incident_cap > 0:
        spent_incident = float(
            await session.scalar(
                select(func.coalesce(func.sum(LLMCall.cost_usd), 0)).where(
                    LLMCall.incident_id == incident_id
                )
            )
            or 0
        )

    return cap_reason(
        spent_today=spent_today,
        spent_incident=spent_incident,
        daily_cap=daily_cap,
        incident_cap=incident_cap,
    )
