"""Shift Handoff (Phase 3) — a real, read-only handoff report built from live state.

AiSOC's Shifts screen is a static mock. isoc derives the same surface from the
data it already has: the open-incident worklist (what the next analyst must pick
up) plus a window rollup (what this shift triaged / closed / escalated). Pure +
unit-tested — the route supplies rows, this ranks and counts. Nothing here writes
state or fires an action; it only *describes* the board for handoff.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .sla import SEV_RANK

# Statuses that still need a human's attention on the next shift.
_OPEN_STATUSES = frozenset(
    {
        "received",
        "parsed",
        "enriching",
        "auto_closed_candidate",
        "awaiting_synthesis",
        "synthesized",
        "awaiting_review",
        "awaiting_signoff",
    }
)

# Bucket = why this item is on the board; lower rank = surfaces first.
_BUCKET_RANK = {"gate": 0, "review": 1, "in_progress": 2, "new": 3}


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


def _bucket(status: str, assignee_id: str | None) -> str:
    if status == "awaiting_signoff":
        return "gate"
    if status in ("synthesized", "awaiting_review"):
        return "review"
    if assignee_id:
        return "in_progress"
    return "new"


def _note(status: str, verdict: str | None, assignee_name: str | None, n_actions: int) -> str:
    if status == "awaiting_signoff":
        v = (verdict or "pending").upper()
        tail = f" · {n_actions} proposed action{'s' if n_actions != 1 else ''}" if n_actions else ""
        return f"At sign-off gate — proposed {v}{tail}"
    if status in ("synthesized", "awaiting_review"):
        return "Synthesis done — needs analyst review"
    if assignee_name:
        return f"Claimed by {assignee_name} — in progress"
    return "Unassigned — needs triage"


def build_handoff(
    open_rows: list[dict],
    window_rows: list[dict],
    *,
    now: datetime,
    window_hours: int,
    on_duty: str | None = None,
) -> dict[str, Any]:
    """Assemble the handoff board.

    `open_rows`: currently-open incidents (status not closed/failed) with id,
    case_number, title, severity, status, verdict, customer, assignee_id,
    assignee_name, created_at, snoozed_until, proposed_actions.
    `window_rows`: incidents created OR closed in the window with created_at,
    closed_at, signed_off_at, approved_by_id. Used only for the rollup counts.
    """
    window_start = now.timestamp() - window_hours * 3600

    items: list[tuple[tuple, dict]] = []
    for r in open_rows:
        status = str(r.get("status") or "").lower()
        if status not in _OPEN_STATUSES:
            continue
        snoozed = _as_aware(r.get("snoozed_until"))
        if snoozed is not None and snoozed > now:
            continue  # sleeping — not a handoff concern until it wakes
        sev = str(r.get("severity") or "medium").lower()
        assignee_id = str(r["assignee_id"]) if r.get("assignee_id") else None
        assignee_name = r.get("assignee_name")
        created = _as_aware(r.get("created_at")) or now
        age_hours = max(0.0, (now.timestamp() - created.timestamp()) / 3600)
        n_actions = len(r.get("proposed_actions") or [])
        bucket = _bucket(status, assignee_id)
        auto_note = _note(status, r.get("verdict"), assignee_name, n_actions)
        analyst_note = (r.get("handoff_note") or "").strip() or None
        item = {
            "id": str(r.get("id")) if r.get("id") is not None else None,
            "case_number": r.get("case_number"),
            "title": r.get("title"),
            "severity": sev,
            "priority": sev,  # UI alias
            "status": status,
            "verdict": (str(r["verdict"]).upper() if r.get("verdict") else None),
            "customer": r.get("customer"),
            "assignee_id": assignee_id,
            "assignee": assignee_name or "unassigned",
            "bucket": bucket,
            "at_gate": bucket == "gate",
            "age_hours": round(age_hours, 1),
            "created_at": created.isoformat(),
            # `note` = what to show: the analyst's handoff note wins over the auto
            # one. `auto_note` + `handoff_note` are kept so the UI can distinguish
            # an analyst-written note (editable, styled) from the derived default.
            "note": analyst_note or auto_note,
            "auto_note": auto_note,
            "handoff_note": analyst_note,
        }
        # gate first → severity → oldest first
        key = (_BUCKET_RANK.get(bucket, 9), SEV_RANK.get(sev, 9), created)
        items.append((key, item))

    items.sort(key=lambda t: t[0])
    ranked = [it for _, it in items]

    # ── window rollup (what this shift did) ─────────────────────────────────
    ingested = closed = auto_resolved = signed_off = 0
    for r in window_rows:
        created = _as_aware(r.get("created_at"))
        closed_at = _as_aware(r.get("closed_at"))
        signed_at = _as_aware(r.get("signed_off_at"))
        if created is not None and created.timestamp() >= window_start:
            ingested += 1
        if closed_at is not None and closed_at.timestamp() >= window_start:
            closed += 1
            # auto-resolved = pipeline closed it with no human sign-off
            if not r.get("approved_by_id"):
                auto_resolved += 1
        if signed_at is not None and signed_at.timestamp() >= window_start:
            signed_off += 1

    counts = {
        "open": len(ranked),
        "at_gate": sum(1 for it in ranked if it["at_gate"]),
        "unassigned": sum(1 for it in ranked if it["assignee_id"] is None),
        "by_bucket": {
            b: sum(1 for it in ranked if it["bucket"] == b)
            for b in ("gate", "review", "in_progress", "new")
        },
        "by_severity": {
            s: sum(1 for it in ranked if it["severity"] == s)
            for s in ("critical", "high", "medium", "low")
        },
    }
    summary = {
        "ingested": ingested,
        "closed": closed,
        "auto_resolved": auto_resolved,
        "signed_off": signed_off,
        "escalations": counts["at_gate"],
    }
    return {
        "generated_at": now.isoformat(),
        "window_hours": window_hours,
        "on_duty": on_duty,
        "summary": summary,
        "counts": counts,
        "items": ranked,
    }


def render_handoff_markdown(handoff: dict[str, Any]) -> str:
    """A copy-pasteable handoff note (the 'Generate Handoff Report' button)."""
    s = handoff.get("summary", {})
    c = handoff.get("counts", {})
    when = handoff.get("generated_at", "")
    lines = [
        "# Shift Handoff",
        "",
        f"_Generated {when} · last {handoff.get('window_hours', 12)}h_"
        + (f" · on duty: {handoff['on_duty']}" if handoff.get("on_duty") else ""),
        "",
        "## This shift",
        f"- Ingested: **{s.get('ingested', 0)}**",
        f"- Closed: **{s.get('closed', 0)}** ({s.get('auto_resolved', 0)} auto-resolved, "
        f"{s.get('signed_off', 0)} analyst-signed)",
        f"- At sign-off gate (escalations pending): **{s.get('escalations', 0)}**",
        "",
        f"## Open items for the next shift ({c.get('open', 0)})",
    ]
    items = handoff.get("items", [])
    if not items:
        lines.append("- _Clean board — nothing open._")
    for it in items:
        flag = "🚦 GATE " if it.get("at_gate") else ""
        lines.append(
            f"- {flag}**{it.get('case_number') or it.get('id')}** "
            f"[{str(it.get('severity', '')).upper()}] {it.get('title', '')} — "
            f"{it.get('note', '')} (age {it.get('age_hours', 0)}h)"
        )
    return "\n".join(lines)
