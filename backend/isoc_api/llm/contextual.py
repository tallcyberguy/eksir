"""AI Copilot (3.8) — read-only contextual LLM actions.

A small set of named, single-shot assistant actions (summarize / next-steps /
explain). STRICTLY read-only: Copilot explains and summarizes; it NEVER issues a
verdict, writes a proposal, or fires a response action — the analyst gate stays
the sole commit point. Every call goes through `llm.client.complete`, so the F3
egress contract applies automatically.

Prompt building is pure + unit-tested here; the route does the DB/LLM I/O.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

# Shared guardrail preamble — prepended to every action's system prompt.
COPILOT_SYSTEM = (
    "You are EKSIR Copilot, a read-only assistant for SOC analysts. You explain, "
    "summarize, and suggest lines of inquiry. You DO NOT issue verdicts, approve or "
    "reject cases, or trigger any response action — the human analyst owns every "
    "decision and is the only one who can act. Be concise and factual, ground every "
    "claim in the provided context, and say plainly when the context doesn't support "
    "an answer. Never fabricate indicators, hostnames, or hashes."
)

# Each action: key, label, scope ('incident' needs case context; 'general' is free-form),
# and its task-specific system instruction.
ACTIONS: list[dict[str, str]] = [
    {
        "key": "summarize",
        "label": "Summarize this incident",
        "scope": "incident",
        "system": "Summarize the incident for a busy analyst in 4–6 bullet points: what "
        "happened, the key evidence, and the current state. Do not recommend a verdict.",
    },
    {
        "key": "next_steps",
        "label": "Suggest investigation next steps",
        "scope": "incident",
        "system": "Propose the 3–5 most useful next investigative steps (queries to run, "
        "artifacts to pull, things to confirm). These are suggestions for the analyst to "
        "consider — frame them as questions/checks, never as actions you will take.",
    },
    {
        "key": "explain_report",
        "label": "Explain in plain English",
        "scope": "incident",
        "system": "Explain this incident and its analyst report in plain English for a "
        "junior analyst or a non-technical stakeholder. Define jargon. No verdict.",
    },
    {
        "key": "explain",
        "label": "Explain an indicator or term",
        "scope": "general",
        "system": "Explain the indicator, technique, or term the analyst asks about — what "
        "it is, why it matters in a SOC, and how it's typically investigated. If asked about "
        "a specific IOC value you have no data on, explain the type/risk generically and say "
        "you have no reputation data on that specific value.",
    },
]
_BY_KEY = {a["key"]: a for a in ACTIONS}


def available_actions() -> list[dict[str, str]]:
    return [{"key": a["key"], "label": a["label"], "scope": a["scope"]} for a in ACTIONS]


def incident_context(
    *,
    case_number: str | None,
    title: str | None,
    severity: Any,
    verdict: Any,
    report: str | None,
    proposed_actions: list | None = None,
    ti_band: str | None = None,
    mitre: list | None = None,
    max_report_chars: int = 6000,
) -> str:
    """A compact, egress-safe markdown context block for an incident.

    Built from the *already-synthesized* report (raw payloads stripped by the
    pipeline) plus curated scalar fields — never the raw alert JSON."""
    lines = [f"## Incident {case_number or '?'}: {title or '(untitled)'}"]
    lines.append(f"- Severity: {severity}")
    lines.append(
        f"- Current verdict: {verdict} "
        "(PENDING means no analyst decision has been made yet — do not assume one)"
    )
    if proposed_actions:
        kinds = ", ".join(str(a) for a in proposed_actions[:8])
        lines.append(f"- Proposed actions awaiting analyst sign-off: {kinds}")
    if ti_band:
        lines.append(f"- Local threat-intel confidence: {ti_band}")
    if mitre:
        lines.append(f"- MITRE techniques: {', '.join(str(m) for m in mitre[:12])}")
    lines.append("")
    lines.append("### Analyst report")
    if report:
        body = report.strip()
        if len(body) > max_report_chars:
            body = body[:max_report_chars] + "\n…(truncated)"
        lines.append(body)
    else:
        lines.append("(no synthesized report yet)")
    return "\n".join(lines)


def build_prompt(
    action_key: str, *, incident_ctx: str | None = None, question: str | None = None
) -> tuple[str, str]:
    """(system, user) for an action. Raises ValueError on unknown action or when
    an incident-scoped action is missing its context. Pure — no I/O."""
    action = _BY_KEY.get(action_key)
    if action is None:
        raise ValueError(f"unknown copilot action: {action_key}")
    if action["scope"] == "incident" and not incident_ctx:
        raise ValueError(f"action '{action_key}' requires an incident context")

    system = f"{COPILOT_SYSTEM}\n\n{action['system']}"

    parts: list[str] = []
    if incident_ctx:
        parts.append(incident_ctx)
    q = (question or "").strip()
    if q:
        parts.append(f"### Analyst question\n{q}")
    elif action["scope"] == "general":
        raise ValueError(f"action '{action_key}' requires a question")
    if not incident_ctx and not q:
        parts.append("(no context provided)")
    return system, "\n\n".join(parts)


def copilot_call_row(result, *, incident_id: uuid.UUID | None):
    """Build an LLMCall for a copilot turn. Like the pipeline's `_llm_call_row`
    but `incident_id` may be None (general, non-incident actions)."""
    from ..db.enums import LLMStatus
    from ..db.models import LLMCall
    from ..settings import settings

    keep = bool(getattr(settings, "log_llm_transcripts", True))
    return LLMCall(
        incident_id=incident_id,
        purpose="copilot",
        model=result.model,
        provider=getattr(result, "provider", None),
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        latency_ms=getattr(result, "latency_ms", None),
        status=LLMStatus(result.status),
        prompt_hash=getattr(result, "prompt_hash", None),
        created_at=datetime.now(timezone.utc),
        system_prompt=(getattr(result, "system_prompt", None) if keep else None),
        user_prompt=(getattr(result, "user_prompt", None) if keep else None),
        response_text=(result.text if keep else None),
        error=getattr(result, "error", None),
    )
