"""Conversational Incident Manager at the human gate.

The deterministic pipeline parks an incident at AWAITING_SIGNOFF with a proposed
verdict + proposed response actions. This module lets an analyst converse with
the manager to refine that proposal before committing: the manager LLM can
revise the proposed verdict/actions and RE-TASK the hunter/forensic personas
with the analyst's directive — but it never commits and never executes actions
(the approve endpoint does that). Tool use is forced (`gated=False`), independent
of ISOC_ENABLE_LLM_TOOLS which only governs the automatic L2 path.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters import integration_store, store_adapter
from ..db.models import Incident
from ..llm import prompts
from ..llm import tools as llm_tools
from ..llm.client import complete, complete_with_tools
from ..settings import settings
from . import briefing, contracts
from .orchestrator import (
    _emit,
    _hunt_iocs,
    _llm_call_row,
    _persona_stage_done,
    _persona_stage_start,
)

DEEP = settings.isoc_model_deep
_VALID_ACTION_KINDS = ("blocklist_ioc", "isolate_host", "collect_file")


def _valid_collect_params(params: dict | None) -> bool:
    """A collect_file action needs a real file path (not empty/slash-only) AND a
    target (agentGuid or hostname). Guards against junk the model can emit."""
    p = params or {}
    file_ok = bool(str(p.get("file_path") or "").strip().strip("\\/"))
    has_target = bool(p.get("agent_guid") or p.get("endpoint_name"))
    return file_ok and has_target


# Per-incident action vocabulary for the manager-chat propose_actions tool. The manager
# is offered ONLY the action kinds valid for THIS incident's EDR, and the provider is
# stamped from the incident (not trusted from the model) — so a Defender incident can
# never be revised into a V1-routed action, or vice versa.
_PROVIDER_ACTIONS: dict[str, dict[str, Any]] = {
    "vision_one": {
        "kinds": _VALID_ACTION_KINDS,  # blocklist_ioc / isolate_host / collect_file
        "params_hint": "{ioc_type, value, scan_action} · {endpoint_name} · "
        "{file_path, agent_guid|endpoint_name}",
    },
    "microsoft_defender": {
        "kinds": ("blocklist_ioc", "isolate_host", "scan_endpoint", "disable_user"),
        "params_hint": "{indicator_type, value} for blocklist · {machine_id} for isolate/scan · "
        "{user_id} for disable_user",
    },
}


def _provider_for(incident: Incident) -> str:
    """Which EDR this incident's response actions target (from source_product)."""
    src = str((incident.normalized or {}).get("source_product") or "").lower()
    return "microsoft_defender" if src == "microsoft_defender" else "vision_one"


def _build_revised_actions(vocab: dict[str, Any], provider: str, actions: list) -> list[dict]:
    """Filter + shape the manager's proposed actions to this incident's EDR vocabulary,
    stamping ``provider`` from the incident (never trusted from the model). Pure — the
    caller persists the result. Drops kinds outside the vocab and junk params."""
    new: list[dict] = []
    for a in actions or []:
        kind = (a or {}).get("kind")
        if kind not in vocab["kinds"]:
            continue
        params = a.get("params") or {}
        if kind == "collect_file" and not _valid_collect_params(params):
            continue
        # Defender endpoint actions need a device id; blocklist needs a value.
        if provider == "microsoft_defender":
            if (
                kind in ("isolate_host", "scan_endpoint")
                and not str(params.get("machine_id") or "").strip()
            ):
                continue
            if kind == "blocklist_ioc" and not str(params.get("value") or "").strip():
                continue
            if kind == "disable_user" and not str(params.get("user_id") or "").strip():
                continue
        new.append(
            {
                "id": f"act{len(new)}",  # renumber over kept actions — no gaps
                "kind": kind,
                "provider": provider,
                "params": params,
                "justification": a.get("justification") or "",
                "status": "pending",
            }
        )
    return new


def _propose_actions_tool(vocab: dict[str, Any]) -> dict[str, Any]:
    """Build the propose_actions tool schema for one incident's action vocabulary."""
    return {
        "type": "function",
        "function": {
            "name": "propose_actions",
            "description": (
                "Replace the incident's proposed response actions with this list (add, drop, "
                "or change them). Proposals only — they execute only when the analyst approves. "
                "Only the action kinds valid for THIS incident's EDR are offered."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {"type": "string", "enum": list(vocab["kinds"])},
                                "params": {
                                    "type": "object",
                                    "description": f"e.g. {vocab['params_hint']}",
                                },
                                "justification": {"type": "string"},
                            },
                            "required": ["kind", "params"],
                        },
                    }
                },
                "required": ["actions"],
            },
        },
    }


# ── Tool schemas (OpenAI function format) ───────────────────────────────────
MANAGER_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "propose_actions",
            "description": (
                "Replace the incident's proposed response actions with this list "
                "(use it to add, drop, or change blocks / isolations / file "
                "collections). Proposals only — they execute only when the analyst "
                "approves."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {
                                    "type": "string",
                                    "enum": list(_VALID_ACTION_KINDS),
                                },
                                "params": {
                                    "type": "object",
                                    "description": "e.g. {ioc_type, value, scan_action} or {endpoint_name}",
                                },
                                "justification": {"type": "string"},
                            },
                            "required": ["kind", "params"],
                        },
                    }
                },
                "required": ["actions"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_proposed_verdict",
            "description": "Revise the proposed verdict and its reasoning (still requires analyst approval to commit).",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["TP", "FP", "benign", "inconclusive"]},
                    "reasoning": {"type": "string"},
                },
                "required": ["verdict"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_hunt",
            "description": (
                "Re-task the Threat Hunter. When the live Vision One search is enabled this "
                "EXECUTES the endpoint-activity queries and returns results; otherwise it "
                "stages queries + re-assesses spread. Call this whenever the analyst asks to "
                "run / execute a hunt — do not just describe the queries."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "focus": {
                        "type": "string",
                        "description": "lateral_movement | persistence | exfil | c2",
                    },
                    "instruction": {
                        "type": "string",
                        "description": "What the analyst wants hunted",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_forensics",
            "description": "Re-task the forensic analyst to reconstruct a timeline / establish root cause, with an optional analyst directive.",
            "parameters": {
                "type": "object",
                "properties": {"instruction": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_ioc_history",
            "description": "Prior verdict track record for one IP / file hash / domain across analyst-verified alerts.",
            "parameters": {
                "type": "object",
                "properties": {"indicator": {"type": "string"}},
                "required": ["indicator"],
            },
        },
    },
]


# ── Briefing + persona re-tasking (used by the manager's tools) ─────────────
def render_case_briefing(incident: Incident, *, fast_classifier: dict | None = None) -> str:
    e = incident.enrichment or {}
    return briefing.render(
        normalized=incident.normalized or {},
        autoclose_pre=(incident.autoclose_match or {}).get("pre"),
        autoclose_post=(incident.autoclose_match or {}).get("post"),
        exact_match=e.get("exact_match"),
        n_way=e.get("n_way"),
        similar=e.get("similar_top5") or [],
        kb_hits=e.get("kb_hits") or [],
        triage_results=e.get("triage") or [],
        ip_enrichments=e.get("ipinfo") or [],
        threat_intel_matches=e.get("threat_intel_matches") or [],
        excluded_iocs=e.get("excluded_iocs") or [],
        fast_classifier=fast_classifier or e.get("fast_classifier"),
        temporal=e.get("temporal"),
        sensitive=e.get("sensitive_rule"),
        deobfuscation=e.get("deobfuscation"),
        v1_enrichment=e.get("v1"),
    )


def _hunt_window(incident: Incident) -> tuple[str | None, str | None]:
    """RFC3339-Z (start, end) bracketing the alert time by ±v1_activity_window_hours.
    Falls back to (None, None) — the adapter then lets V1 default to the last 24h."""
    e = incident.enrichment or {}
    created = ((e.get("v1") or {}).get("workbench") or {}).get("createdDateTime")
    base_iso = created or (incident.normalized or {}).get("timestamp")
    if not base_iso:
        return None, None
    try:
        base = datetime.fromisoformat(str(base_iso).replace("Z", "+00:00"))
    except ValueError:
        return None, None
    h = settings.v1_activity_window_hours
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = (base - timedelta(hours=h)).astimezone(timezone.utc).strftime(fmt)
    end = (base + timedelta(hours=h)).astimezone(timezone.utc).strftime(fmt)
    return start, end


async def _hunt_activity_tool(incident: Incident, collector: list | None = None):
    """When enabled and this customer has V1 creds, return (tools, dispatch, system)
    giving the hunter a live read-only endpoint-activity search; else None.
    Analyst-triggered path only — the automated hunt stays query-building only.
    `collector` accumulates the matched records for the downloadable evidence log."""
    if not settings.v1_activity_search_enabled:
        return None
    try:
        creds = await integration_store.get_creds("vision_one", incident.customer)
    except Exception:
        creds = None
    if creds is None:
        return None
    start, end = _hunt_window(incident)
    handler = llm_tools.make_endpoint_activity_handler(
        creds,
        start=start,
        end=end,
        max_records=settings.v1_activity_max_records,
        collector=collector,
    )
    return (
        [llm_tools.GET_ENDPOINT_ACTIVITY_TOOL],
        {"get_endpoint_activity": handler},
        prompts.HUNT_SYSTEM_LIVE,
    )


async def _defender_hunt_tool(incident: Incident):
    """When enabled and this customer has microsoft_defender creds, give the hunter a live
    read-only Microsoft Defender advanced-hunting tool (Graph runHuntingQuery); else None.
    Analyst-triggered path only — the automated hunt stays query-building only. Reuses the
    Phase-1 creds-bound handler; results go to the transcript (no evidence-log collector)."""
    if not settings.defender_tools_enabled:
        return None
    try:
        creds = await integration_store.get_creds("microsoft_defender", incident.customer)
    except Exception:
        creds = None
    if creds is None:
        return None
    handler = llm_tools.make_defender_handlers(creds)["defender_run_hunt"]
    return (
        [llm_tools.DEFENDER_RUN_HUNT_TOOL],
        {"defender_run_hunt": handler},
        prompts.HUNT_SYSTEM_LIVE,
    )


def _hunt_live_state(live_v1, live_def) -> str:
    """Honest reason for the manager: a live hunt tool was available, or why it wasn't."""
    if live_v1 is not None or live_def is not None:
        return "available"
    if not settings.v1_activity_search_enabled and not settings.defender_tools_enabled:
        return "disabled_by_config"
    return "no_credentials"


async def _run_hunt(
    session: AsyncSession,
    incident: Incident,
    analysis: dict,
    *,
    instruction: str | None = None,
    focus: str | None = None,
) -> dict:
    if focus:
        analysis = {**analysis, "hunt_focus": focus}
    brief = render_case_briefing(incident)
    user = prompts.build_hunt_prompt(
        brief,
        analysis,
        _hunt_iocs(incident.enrichment or {}),
        source_product=(incident.normalized or {}).get("source_product"),
    )
    if instruction:
        user += f"\n\nANALYST DIRECTIVE: {instruction}"
    t0 = await _persona_stage_start(session, incident, "hunt")
    evidence: list[dict] = []  # raw matched records captured for the downloadable log
    # Assemble whatever live-hunt tools this customer has — V1 Endpoint Activity and/or
    # Microsoft Defender advanced hunting. Analyst-triggered path only (gated=False).
    live_v1 = await _hunt_activity_tool(incident, collector=evidence)
    live_def = await _defender_hunt_tool(incident)
    tools_list: list = []
    dispatch: dict = {}
    for src in (live_v1, live_def):
        if src is not None:
            tools_list += src[0]
            dispatch.update(src[1])
    # Tell the manager WHY a live search did or didn't run, so it reports the truth.
    live_state = _hunt_live_state(live_v1, live_def)
    if tools_list:
        res = await complete_with_tools(
            system=prompts.HUNT_SYSTEM_LIVE,
            user=user,
            tools=tools_list,
            dispatch=dispatch,
            model=DEEP,
            gated=False,
        )
    else:
        res = await complete(system=prompts.HUNT_SYSTEM, user=user, model=DEEP)
    session.add(_llm_call_row(incident_id=incident.id, purpose="manager_hunt", result=res))
    hunt = contracts.parse_into(contracts.HuntResult, res.text) if res.status == "ok" else None
    if hunt:
        e = dict(incident.enrichment or {})
        st = dict(e.get("stages") or {})
        hunt_stage = hunt.model_dump()
        if evidence:
            # Lean flag stays in the polled payload; the raw rows live under a
            # separate key served only by the download endpoint.
            hunt_stage["evidence_count"] = sum(int(r.get("count") or 0) for r in evidence)
            e["hunt_evidence"] = evidence
        st["hunt"] = hunt_stage
        e["stages"] = st
        incident.enrichment = e
    await _persona_stage_done(
        session,
        incident,
        "hunt",
        t0,
        display=f"Hunt (manager re-task): {hunt.spread_assessment if hunt else 'no result'}",
    )
    if hunt is None:
        return {"error": "hunt produced no result", "live_search": live_state}
    out = hunt.model_dump()
    out["live_search"] = "executed" if (live_state == "available" and hunt.executed) else live_state
    return out


async def _run_forensics(
    session: AsyncSession, incident: Incident, analysis: dict, *, instruction: str | None = None
) -> dict:
    brief = render_case_briefing(incident)
    hunt = ((incident.enrichment or {}).get("stages") or {}).get("hunt")
    user = prompts.build_forensic_prompt(brief, analysis, hunt)
    if instruction:
        user += f"\n\nANALYST DIRECTIVE: {instruction}"
    t0 = await _persona_stage_start(session, incident, "forensics")
    res = await complete(system=prompts.FORENSIC_SYSTEM, user=user, model=DEEP)
    session.add(_llm_call_row(incident_id=incident.id, purpose="manager_forensics", result=res))
    fz = contracts.parse_into(contracts.ForensicResult, res.text) if res.status == "ok" else None
    if fz:
        e = dict(incident.enrichment or {})
        st = dict(e.get("stages") or {})
        st["forensics"] = fz.model_dump()
        e["stages"] = st
        incident.enrichment = e
    await _persona_stage_done(
        session,
        incident,
        "forensics",
        t0,
        display=f"Forensics (manager re-task): scope {fz.scope if fz else 'no result'}",
    )
    return fz.model_dump() if fz else {"error": "forensics produced no result"}


# ── Prompt assembly ─────────────────────────────────────────────────────────
def _case_summary(incident: Incident) -> str:
    e = incident.enrichment or {}
    st = e.get("stages") or {}
    prop = e.get("proposal") or {}
    pa = e.get("proposed_actions") or []
    lines = [
        f"# Case {incident.case_number} — {incident.rule_name or ''}",
        f"Severity: {incident.severity}",
        f"\n## Proposed verdict: {prop.get('proposed_verdict')} ({prop.get('confidence')})",
    ]
    if prop.get("reasoning"):
        lines.append(prop["reasoning"])
    lines.append("\n## Proposed actions:")
    if pa:
        for a in pa:
            lines.append(
                f"- [{a.get('id')}] {a.get('kind')} {json.dumps(a.get('params') or {})} — {a.get('status')}"
            )
    else:
        lines.append("- (none)")
    l2 = st.get("l2") or {}
    if l2:
        lines.append(
            f"\n## L2: {l2.get('verdict')}/{l2.get('confidence')} · "
            f"MITRE {', '.join(l2.get('mitre_techniques') or [])} · hunt_focus {l2.get('hunt_focus')}"
        )
    if st.get("hunt"):
        h = st["hunt"]
        hline = (
            f"## Hunt: spread {h.get('spread_assessment')}, {len(h.get('queries') or [])} queries"
        )
        if h.get("affected_hosts"):
            hline += f"; affected hosts: {', '.join(h['affected_hosts'][:10])}"
        lines.append(hline)
        if h.get("reasoning"):
            lines.append(str(h["reasoning"])[:500])
    if st.get("forensics"):
        f = st["forensics"]
        lines.append(f"## Forensics: scope {f.get('scope')} — {str(f.get('root_cause', ''))[:200]}")
    if incident.llm_report_markdown:
        lines.append("\n## L2 report:\n" + incident.llm_report_markdown[:3000])
    return "\n".join(lines)


def _user_prompt(incident: Incident, message: str) -> str:
    history = (incident.enrichment or {}).get("manager_chat") or []
    parts = [_case_summary(incident), "\n## Conversation so far:"]
    if history:
        for m in history[-12:]:
            parts.append(f"{str(m.get('role', '?')).capitalize()}: {m.get('text', '')}")
    else:
        parts.append("(none yet)")
    parts.append(f"\nAnalyst: {message}")
    return "\n".join(parts)


# ── The turn ─────────────────────────────────────────────────────────────────
async def manager_turn(session: AsyncSession, incident: Incident, message: str) -> str:
    """Run one analyst→manager turn. Tools mutate the proposal / re-task personas;
    the reply text + transcript are persisted in enrichment['manager_chat']."""

    # This incident's EDR decides which action kinds the manager may propose, and the
    # provider is stamped from the incident below — never trusted from the model.
    provider = _provider_for(incident)
    vocab = _PROVIDER_ACTIONS[provider]

    async def _d_propose_actions(args: dict) -> dict:
        new = _build_revised_actions(vocab, provider, args.get("actions") or [])
        e = dict(incident.enrichment or {})
        e["proposed_actions"] = new
        incident.enrichment = e
        await _emit(
            session,
            incident,
            "manager_revise_actions",
            display=f"Manager revised proposed actions → {len(new)}",
            payload={"proposed_actions": new},
            level="info",
            step="synthesis",
        )
        return {"proposed_actions": new}

    async def _d_set_verdict(args: dict) -> dict:
        e = dict(incident.enrichment or {})
        p = dict(e.get("proposal") or {})
        if args.get("verdict"):
            p["proposed_verdict"] = args["verdict"]
        if args.get("reasoning"):
            p["reasoning"] = args["reasoning"]
        e["proposal"] = p
        incident.enrichment = e
        await _emit(
            session,
            incident,
            "manager_set_verdict",
            display=f"Manager set proposed verdict → {p.get('proposed_verdict')}",
            payload=p,
            level="info",
            step="synthesis",
        )
        return {"proposal": p}

    async def _d_run_hunt(args: dict) -> dict:
        l2 = ((incident.enrichment or {}).get("stages") or {}).get("l2") or {}
        return await _run_hunt(
            session, incident, l2, instruction=args.get("instruction"), focus=args.get("focus")
        )

    async def _d_run_forensics(args: dict) -> dict:
        l2 = ((incident.enrichment or {}).get("stages") or {}).get("l2") or {}
        return await _run_forensics(session, incident, l2, instruction=args.get("instruction"))

    dispatch = {
        "propose_actions": _d_propose_actions,
        "set_proposed_verdict": _d_set_verdict,
        "run_hunt": _d_run_hunt,
        "run_forensics": _d_run_forensics,
        "lookup_ioc_history": lambda a: store_adapter.lookup_ioc_history(a.get("indicator", "")),
    }

    # Swap in the provider-specific propose_actions for this incident's EDR.
    tools = [_propose_actions_tool(vocab)] + [
        t for t in MANAGER_TOOLS if t["function"]["name"] != "propose_actions"
    ]
    result = await complete_with_tools(
        system=prompts.MANAGER_CHAT_SYSTEM,
        user=_user_prompt(incident, message),
        tools=tools,
        dispatch=dispatch,
        model=DEEP,
        gated=False,
        max_rounds=5,
    )
    session.add(_llm_call_row(incident_id=incident.id, purpose="manager_chat", result=result))
    reply = result.text if result.status == "ok" else f"(manager unavailable: {result.error})"

    e = dict(incident.enrichment or {})
    chat = list(e.get("manager_chat") or [])
    ts = datetime.now(timezone.utc).isoformat()
    chat.append({"role": "analyst", "text": message, "ts": ts})
    chat.append({"role": "manager", "text": reply, "ts": ts})
    e["manager_chat"] = chat[-40:]
    incident.enrichment = e
    return reply
