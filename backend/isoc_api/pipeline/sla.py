"""F1 — SLA lifecycle events + duration/breach helpers.

`record_sla_event` appends one row to the `sla_events` ledger within the caller's
transaction. It is **best-effort**: construction is guarded so a bad value can
never break a verdict commit or the pipeline (the row still participates in the
caller's commit, like TimelineEvent). The pure helpers are what SLA Tracking and
Team Analytics will build their metrics on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..logging_config import get_logger

logger = get_logger("isoc.sla")

# Lifecycle kinds. `acknowledged` is defined for the Investigation Queue feature
# (claim/open) to emit later; F1 emits `detected`, `resolved`, `closed`.
DETECTED = "detected"
ACKNOWLEDGED = "acknowledged"
RESOLVED = "resolved"
CLOSED = "closed"
KINDS = (DETECTED, ACKNOWLEDGED, RESOLVED, CLOSED)


def record_sla_event(
    session: Any,
    incident: Any,
    kind: str,
    *,
    actor_id: Any | None = None,
    meta: dict | None = None,
) -> None:
    """Append an SLAEvent to the session (committed with the caller's tx).

    Never raises — a failure to record an SLA event must not break the gate or
    the pipeline.
    """
    try:
        from ..db.models import SLAEvent

        session.add(
            SLAEvent(
                incident_id=incident.id,
                tenant_id=getattr(incident, "tenant_id", None),
                kind=kind,
                at=datetime.now(timezone.utc),
                actor_id=actor_id,
                meta=meta or None,
            )
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("sla.record_failed", kind=kind, error=str(exc))


def resolution_seconds(detected_at: datetime | None, closed_at: datetime | None) -> int | None:
    """Whole seconds from detection to close; None if either endpoint is missing.
    Clamped at 0 so clock skew can't produce a negative duration."""
    if not detected_at or not closed_at:
        return None
    return max(0, int((closed_at - detected_at).total_seconds()))


def response_seconds(created_at: datetime | None, responded_at: datetime | None) -> int | None:
    """Whole seconds from creation to first analyst response; None if either
    endpoint is missing. Clamped at 0. Symmetric with `resolution_seconds`."""
    if not created_at or not responded_at:
        return None
    return max(0, int((responded_at - created_at).total_seconds()))


def is_breached(elapsed_seconds: int | None, target_seconds: int | None) -> bool:
    """True when `elapsed_seconds` exceeds the SLA target. A missing/zero/negative
    target means 'no SLA' and never breaches; a missing elapsed never breaches."""
    if not target_seconds or target_seconds <= 0:
        return False
    return elapsed_seconds is not None and elapsed_seconds > target_seconds


# ── SLA targets + dashboard (per-severity resolution-time SLA) ───────────────

SEVERITIES = ("critical", "high", "medium", "low")

# Default time-to-resolve targets in minutes. Admin overrides live in `sla_targets`.
DEFAULT_TARGET_MINUTES: dict[str, int] = {
    "critical": 60,
    "high": 240,
    "medium": 1440,
    "low": 4320,
}

# Default time-to-first-response targets (minutes). 24/7 wall-clock, always
# tighter than the resolution target — an alert must be acknowledged/triaged well
# before it is fully resolved. Admin overrides live in `sla_targets`
# (`response_target_minutes`).
DEFAULT_RESPONSE_MINUTES: dict[str, int] = {
    "critical": 15,
    "high": 120,
    "medium": 480,
    "low": 1440,
}


def _merge_targets(defaults: dict[str, int], overrides: dict[str, int] | None) -> dict[str, int]:
    t = dict(defaults)
    for sev, mins in (overrides or {}).items():
        if sev in t and mins and int(mins) > 0:
            t[sev] = int(mins)
    return t


def effective_targets(overrides: dict[str, int] | None) -> dict[str, int]:
    """Resolution-time defaults merged with admin overrides (known severities, >0)."""
    return _merge_targets(DEFAULT_TARGET_MINUTES, overrides)


def effective_response_targets(overrides: dict[str, int] | None) -> dict[str, int]:
    """Response-time defaults merged with admin overrides (known severities, >0)."""
    return _merge_targets(DEFAULT_RESPONSE_MINUTES, overrides)


def _response_section(
    closed: list[dict],
    open_cases: list[dict],
    targets: dict[str, int],
    *,
    now: datetime,
) -> dict:
    """Response-time (time-to-first-response) half of the SLA dashboard.

    Response anchor = `claimed_at` (an analyst claimed the incident); a closed case
    with no claim counts at `closed_at` (it was responded to no later than close).
    Open, still-unclaimed cases past their response target become `awaiting_overdue`
    — the actionable "response SLA is blowing right now" list. Symmetric in shape
    with the resolution aggregation so the UI renders the two the same way.
    """

    def _sev(c: dict) -> str:
        return c.get("severity") if c.get("severity") in SEVERITIES else "medium"

    by_sev = {
        s: {
            "severity": s,
            "target_minutes": targets.get(s),
            "responded": 0,
            "on_time": 0,
            "breached": 0,
            "_sum": 0.0,
        }
        for s in SEVERITIES
    }
    total = on_time = breached = 0
    resp_sum = 0.0
    breaches: list[dict] = []
    awaiting: list[dict] = []

    # Responded = every closed case (anchor claimed_at|closed_at) + open cases that
    # have been claimed. Open + unclaimed + past target → awaiting_overdue.
    responded: list[tuple[dict, Any]] = [
        (c, c.get("claimed_at") or c.get("closed_at")) for c in closed
    ]
    for o in open_cases:
        claimed = o.get("claimed_at")
        if claimed:
            responded.append((o, claimed))
            continue
        sev = _sev(o)
        tgt = targets.get(sev) or 0
        ca = o.get("created_at")
        if ca and tgt > 0:
            age = (now - ca).total_seconds() / 60.0
            if age > tgt:
                awaiting.append(
                    {
                        "case_number": o.get("case_number"),
                        "severity": sev,
                        "age_minutes": round(age),
                        "target_minutes": tgt,
                    }
                )

    for c, ra in responded:
        ca = c.get("created_at")
        if not ca or not ra:
            continue
        sev = _sev(c)
        tgt = targets.get(sev) or 0
        rmin = max(0.0, (ra - ca).total_seconds() / 60.0)
        b = by_sev[sev]
        b["responded"] += 1
        b["_sum"] += rmin
        total += 1
        resp_sum += rmin
        if tgt > 0 and rmin > tgt:
            b["breached"] += 1
            breached += 1
            breaches.append(
                {
                    "case_number": c.get("case_number"),
                    "severity": sev,
                    "response_minutes": round(rmin),
                    "target_minutes": tgt,
                }
            )
        else:
            b["on_time"] += 1
            on_time += 1

    awaiting.sort(key=lambda x: -(x["age_minutes"] - x["target_minutes"]))
    breaches.sort(key=lambda x: SEV_RANK.get(x["severity"], 9))

    by_sev_out = [
        {
            "severity": s,
            "target_minutes": by_sev[s]["target_minutes"],
            "responded": by_sev[s]["responded"],
            "on_time": by_sev[s]["on_time"],
            "breached": by_sev[s]["breached"],
            "avg_response_minutes": (
                round(by_sev[s]["_sum"] / by_sev[s]["responded"])
                if by_sev[s]["responded"]
                else None
            ),
            "breach_rate": (
                round(by_sev[s]["breached"] / by_sev[s]["responded"], 3)
                if by_sev[s]["responded"]
                else 0.0
            ),
        }
        for s in SEVERITIES
    ]

    return {
        "targets": targets,
        "total_responded": total,
        "on_time": on_time,
        "breached": breached,
        "breach_rate": round(breached / total, 3) if total else 0.0,
        "on_time_rate": round(on_time / total, 3) if total else 0.0,
        "avg_response_minutes": round(resp_sum / total) if total else None,
        "by_severity": by_sev_out,
        "awaiting_overdue": awaiting[:20],
        "recent_breaches": breaches[:20],
    }


def build_sla_dashboard(
    closed: list[dict],
    open_cases: list[dict],
    targets: dict[str, int],
    *,
    window_days: int,
    now: datetime,
    response_targets: dict[str, int] | None = None,
) -> dict:
    """Pure SLA aggregation — resolution (top level) + response (`response` key).

    `closed`: dicts with severity / created_at / closed_at / claimed_at / case_number
    (resolved cases in the window). `open_cases`: severity / created_at / claimed_at /
    case_number (still open). `targets`: per-severity resolution minutes;
    `response_targets`: per-severity response minutes (defaults when None). Resolution
    time = closed_at − created_at; a case breaches when it exceeds its severity's
    target. Open cases past target → `open_overdue`. Response metrics live under the
    `response` key (see `_response_section`).
    """
    by_sev = {
        s: {
            "severity": s,
            "target_minutes": targets.get(s),
            "closed": 0,
            "on_time": 0,
            "breached": 0,
            "_sum": 0.0,
        }
        for s in SEVERITIES
    }
    total = on_time = breached = 0
    res_sum = 0.0
    breaches: list[dict] = []

    for c in closed:
        sev = c.get("severity") if c.get("severity") in by_sev else "medium"
        tgt = targets.get(sev) or 0
        ca, cl = c.get("created_at"), c.get("closed_at")
        if not ca or not cl:
            continue
        res_min = max(0.0, (cl - ca).total_seconds() / 60.0)
        b = by_sev[sev]
        b["closed"] += 1
        b["_sum"] += res_min
        total += 1
        res_sum += res_min
        if tgt > 0 and res_min > tgt:
            b["breached"] += 1
            breached += 1
            breaches.append(
                {
                    "case_number": c.get("case_number"),
                    "severity": sev,
                    "resolution_minutes": round(res_min),
                    "target_minutes": tgt,
                    "closed_at": cl.isoformat() if hasattr(cl, "isoformat") else str(cl),
                }
            )
        else:
            b["on_time"] += 1
            on_time += 1

    overdue: list[dict] = []
    for o in open_cases:
        sev = o.get("severity") if o.get("severity") in by_sev else "medium"
        tgt = targets.get(sev) or 0
        ca = o.get("created_at")
        if not ca or tgt <= 0:
            continue
        age = (now - ca).total_seconds() / 60.0
        if age > tgt:
            overdue.append(
                {
                    "case_number": o.get("case_number"),
                    "severity": sev,
                    "age_minutes": round(age),
                    "target_minutes": tgt,
                }
            )
    overdue.sort(key=lambda x: -(x["age_minutes"] - x["target_minutes"]))
    breaches.sort(key=lambda x: x["closed_at"], reverse=True)

    by_sev_out = []
    for s in SEVERITIES:
        b = by_sev[s]
        by_sev_out.append(
            {
                "severity": s,
                "target_minutes": b["target_minutes"],
                "closed": b["closed"],
                "on_time": b["on_time"],
                "breached": b["breached"],
                "avg_resolution_minutes": round(b["_sum"] / b["closed"]) if b["closed"] else None,
                "breach_rate": round(b["breached"] / b["closed"], 3) if b["closed"] else 0.0,
            }
        )

    return {
        "window_days": window_days,
        "targets": targets,
        "total_closed": total,
        "on_time": on_time,
        "breached": breached,
        "breach_rate": round(breached / total, 3) if total else 0.0,
        "on_time_rate": round(on_time / total, 3) if total else 0.0,
        "avg_resolution_minutes": round(res_sum / total) if total else None,
        "by_severity": by_sev_out,
        "open_overdue": overdue[:20],
        "recent_breaches": breaches[:20],
        "response": _response_section(
            closed,
            open_cases,
            response_targets or DEFAULT_RESPONSE_MINUTES,
            now=now,
        ),
    }


# ── Investigation Queue (3.6) — pure ranking builder ─────────────────────────

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_BUCKET_RANK = {"mine": 0, "unassigned": 1}


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


def build_queue(
    rows: list[dict],
    *,
    me_id: str,
    now: datetime,
    targets: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Rank an incident worklist: mine-first → unassigned, then SLA-due asc,
    then severity. Drops other-analysts' rows and currently-snoozed rows. SLA due
    = created_at + the severity's target (virtual; nothing materialized). Pure +
    unit-tested — the route just supplies the rows.

    `rows`: dicts with id, case_number, title, severity, status, tenant_id,
    customer, assignee_id, snoozed_until, created_at, proposed_actions, asset.
    """
    tgt = effective_targets(targets)
    ranked: list[tuple[tuple, dict]] = []
    count_mine = count_unassigned = 0

    for r in rows:
        assignee = r.get("assignee_id")
        assignee_s = str(assignee) if assignee else None
        if assignee_s == me_id:
            bucket = "mine"
        elif assignee_s is None:
            bucket = "unassigned"
        else:
            continue  # someone else's case — not in my queue

        snoozed = _as_aware(r.get("snoozed_until"))
        if snoozed is not None and snoozed > now:
            continue  # re-enters automatically once snoozed_until passes

        sev = str(r.get("severity") or "medium").lower()
        target_min = tgt.get(sev, max(tgt.values()))
        created = _as_aware(r.get("created_at")) or now
        sla_due = created + timedelta(minutes=target_min)
        remaining = (sla_due - now).total_seconds()
        window = target_min * 60
        if remaining < 0:
            sla_state = "breached"
        elif window > 0 and remaining < 0.25 * window:
            sla_state = "amber"
        else:
            sla_state = "green"

        item = {
            "id": str(r.get("id")) if r.get("id") is not None else None,
            "case_number": r.get("case_number"),
            "title": r.get("title"),
            "severity": sev,
            "status": str(r["status"]) if r.get("status") is not None else None,
            "tenant_id": str(r["tenant_id"]) if r.get("tenant_id") else None,
            "customer": r.get("customer"),
            "assignee_id": assignee_s,
            "bucket": bucket,
            "sla_due_at": sla_due.isoformat(),
            "sla_remaining_seconds": int(remaining),
            "sla_state": sla_state,
            "proposed_actions": r.get("proposed_actions") or [],
            "asset": r.get("asset"),
            "created_at": created.isoformat(),
        }
        ranked.append(((_BUCKET_RANK[bucket], sla_due, SEV_RANK.get(sev, 9)), item))
        if bucket == "mine":
            count_mine += 1
        else:
            count_unassigned += 1

    ranked.sort(key=lambda t: t[0])
    items = [it for _, it in ranked]
    return {
        "items": items,
        "total": len(items),
        "counts": {"mine": count_mine, "unassigned": count_unassigned, "all": len(items)},
        "next_up_id": items[0]["id"] if items else None,
        "generated_at": now.isoformat(),
    }
