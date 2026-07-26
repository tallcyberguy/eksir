"""F8 — persona synthesis phases as standalone, composable steps.

Each function is one stage of the agent-persona synthesis, factored out of the
legacy ``orchestrator._step_synthesis`` so that BOTH the legacy inline sequence
and the LangGraph orchestration (``synthesis_graph``) can drive the same logic.

Behaviour is intended to be identical to the legacy body. The leaf utilities
(``_emit``, ``_persona_stage_*``, ``_llm_call_row``, hallucination check, etc.)
are reused from ``orchestrator`` via a lazy import to avoid a module-load cycle.

NOTE: while ``settings.isoc_use_langgraph`` is False (the default), the legacy
path in ``orchestrator._step_synthesis`` runs unchanged and these functions are
NOT exercised — so the existing pipeline carries zero regression risk until the
flag is flipped and the graph path is validated on the stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..db.enums import CaseStatus, Confidence, Verdict
from ..llm import tools as llm_tools
from ..llm.client import complete, complete_with_tools
from ..llm.prompts import (
    FAST_CLASSIFIER_SYSTEM,
    FORENSIC_SYSTEM,
    HUNT_SYSTEM,
    L2_SYSTEM,
    build_fast_classifier_prompt,
    build_forensic_prompt,
    build_hunt_prompt,
    build_user_prompt,
)
from ..settings import settings
from . import agent_routing, briefing, contracts, sensitive_rules, temporal


@dataclass
class SynthCtx:
    """In-memory working state threaded across the synthesis phases.

    The Incident row remains the system of record; this just carries the
    intermediate persona outputs so each phase can build on the previous one
    without re-reading the DB.
    """

    incident: Any
    force_deep: bool
    enrichment: dict
    normalized: dict
    temporal_ctx: dict | None
    sensitive_ctx: dict | None
    stages: dict = field(default_factory=dict)
    fast_verdict: dict | None = None
    analysis: Any = None  # contracts.AnalysisVerdict
    hunt: Any = None  # contracts.HuntResult | None
    deep_briefing: str = ""

    def render(self, extra: dict | None = None) -> str:
        inc = self.incident
        return briefing.render(
            normalized=inc.normalized or {},
            autoclose_pre=(inc.autoclose_match or {}).get("pre"),
            autoclose_post=(inc.autoclose_match or {}).get("post"),
            exact_match=self.enrichment.get("exact_match"),
            n_way=self.enrichment.get("n_way"),
            similar=self.enrichment.get("similar_top5") or [],
            kb_hits=self.enrichment.get("kb_hits") or [],
            triage_results=self.enrichment.get("triage") or [],
            ip_enrichments=self.enrichment.get("ipinfo") or [],
            threat_intel_matches=self.enrichment.get("threat_intel_matches") or [],
            excluded_iocs=self.enrichment.get("excluded_iocs") or [],
            fast_classifier=(extra or {}).get("fast_classifier"),
            temporal=self.temporal_ctx,
            sensitive=self.sensitive_ctx,
            deobfuscation=self.enrichment.get("deobfuscation"),
            v1_enrichment=self.enrichment.get("v1"),
            ms_reputation=(self.enrichment.get("ms") or {}).get("reputation"),
        )


async def build_synth_ctx(session: Any, incident: Any, force_deep: bool) -> SynthCtx:
    """Compute the deterministic context the personas need and persist it.

    Mirrors the setup block at the top of the legacy ``_step_synthesis``.
    """
    from . import orchestrator as _orch

    enrichment = incident.enrichment or {}
    normalized = incident.normalized or {}
    temporal_ctx = temporal.derive(normalized.get("timestamp"))
    sens_match, sens_kw = sensitive_rules.is_sensitive(
        incident.rule_name,
        normalized.get("event_name"),
        normalized.get("event_description"),
    )
    sensitive_ctx = {"matched": sens_match, "keyword": sens_kw} if sens_match else None

    if temporal_ctx:
        enrichment["temporal"] = temporal_ctx
    if sensitive_ctx:
        enrichment["sensitive_rule"] = sensitive_ctx
    incident.enrichment = enrichment

    if sensitive_ctx:
        await _orch._emit(
            session,
            incident,
            "sensitive_rule_match",
            display=(
                f"Sensitive rule pattern matched (`{sens_kw}`) — fast-tier short-circuit disabled"
            ),
            payload=sensitive_ctx,
        )

    return SynthCtx(
        incident=incident,
        force_deep=force_deep,
        enrichment=enrichment,
        normalized=normalized,
        temporal_ctx=temporal_ctx,
        sensitive_ctx=sensitive_ctx,
    )


async def run_l1(session: Any, incident: Any, ctx: SynthCtx) -> None:
    """Tier-1 fast classifier (skipped on force_deep)."""
    from . import orchestrator as _orch

    if ctx.force_deep:
        incident.short_circuit = None
        await _orch._emit(
            session,
            incident,
            "deep_forced",
            display="Analyst bypass — running deep model directly, skipping fast tier and gates",
            payload={},
        )
        return

    l1_t0 = await _orch._persona_stage_start(session, incident, "l1")
    fast_briefing = ctx.render()
    fast_result = await complete(
        system=FAST_CLASSIFIER_SYSTEM,
        user=build_fast_classifier_prompt(fast_briefing),
        model=settings.isoc_model_fast,
        max_tokens=200,
        temperature=0.0,
    )
    session.add(
        _orch._llm_call_row(incident_id=incident.id, purpose="analyst_fast", result=fast_result)
    )

    if fast_result.status == "ok":
        ctx.fast_verdict = _orch._parse_fast_classifier(fast_result.text)
        ctx.enrichment["fast_classifier"] = ctx.fast_verdict
        _stages = dict(ctx.enrichment.get("stages") or {})
        _stages["l1"] = _orch._triage_result_from_fast(ctx.fast_verdict, incident.severity)
        ctx.enrichment["stages"] = _stages
        incident.enrichment = ctx.enrichment
        await _orch._persona_stage_done(
            session,
            incident,
            "l1",
            l1_t0,
            display=(
                f"L1 triage: {ctx.fast_verdict.get('verdict', '?')} / "
                f"{ctx.fast_verdict.get('confidence', '?')}"
            ),
            payload=ctx.fast_verdict,
        )
    else:
        await _orch._persona_stage_done(
            session,
            incident,
            "l1",
            l1_t0,
            display=f"L1 fast classifier {fast_result.status}; escalating to L2",
            level="warn",
        )


async def maybe_short_circuit(session: Any, incident: Any, ctx: SynthCtx) -> bool:
    """HIGH-confidence FP/benign short-circuit gate. Returns True if it fired
    (incident set to DECIDED_SHORT_CIRCUIT)."""
    from . import orchestrator as _orch

    if not ctx.fast_verdict:
        return False
    v = (ctx.fast_verdict.get("verdict") or "").upper()
    c = (ctx.fast_verdict.get("confidence") or "").upper()
    if not (c == "HIGH" and v in ("FP", "BENIGN")):
        return False

    block_reason = _orch._short_circuit_block_reason(
        verdict_str=v,
        sensitive=ctx.sensitive_ctx,
        exact_match=ctx.enrichment.get("exact_match"),
        n_way=ctx.enrichment.get("n_way"),
        autoclose_match=incident.autoclose_match or {},
    )
    if block_reason:
        await _orch._emit(
            session,
            incident,
            "short_circuit_blocked",
            display=f"Fast-tier HIGH ignored — {block_reason}",
            payload={"reason": block_reason, "fast_verdict": ctx.fast_verdict},
        )
        return False

    incident.verdict = Verdict.FP if v == "FP" else Verdict.BENIGN
    incident.confidence = Confidence.HIGH
    incident.short_circuit = {"gate": "fast_classifier", "reason": ctx.fast_verdict.get("reason")}
    incident.status = CaseStatus.DECIDED_SHORT_CIRCUIT
    await _orch._emit(
        session,
        incident,
        "decision_gate",
        display=f"Fast-tier short-circuit → {v} / HIGH",
        payload=ctx.fast_verdict,
    )
    return True


async def run_l2(session: Any, incident: Any, ctx: SynthCtx) -> bool:
    """Tier-2 deep synthesis. Returns False if the deep call failed."""
    from . import orchestrator as _orch

    ctx.stages = dict(ctx.enrichment.get("stages") or {})
    if "l1" not in ctx.stages and ctx.fast_verdict:
        ctx.stages["l1"] = _orch._triage_result_from_fast(ctx.fast_verdict, incident.severity)

    l2_t0 = await _orch._persona_stage_start(session, incident, "l2")
    # ADR-0009 PR-1: deterministic pre-L2 Microsoft enrichment (parity with the
    # legacy path). Fail-soft; escalated-only (maybe_short_circuit already ran).
    from . import prefetch

    if await prefetch.prefetch_ms_enrichment(incident) is not None:
        ctx.enrichment = incident.enrichment or ctx.enrichment
    ctx.deep_briefing = ctx.render(extra={"fast_classifier": ctx.fast_verdict})
    user_prompt = build_user_prompt(ctx.deep_briefing)
    result = await complete_with_tools(
        system=L2_SYSTEM,
        user=user_prompt,
        model=settings.isoc_model_deep,
        tools=llm_tools.DEEP_TIER_TOOLS,
        dispatch=llm_tools.DISPATCH,
    )
    session.add(
        _orch._llm_call_row(
            incident_id=incident.id,
            purpose=("analyst_deep_forced" if ctx.force_deep else "analyst_deep"),
            result=result,
        )
    )

    if result.status != "ok":
        incident.status = CaseStatus.FAILED
        await _orch._persona_stage_done(
            session,
            incident,
            "l2",
            l2_t0,
            display=f"L2 analysis {result.status}: {result.error}",
            level="error",
        )
        return False

    incident.llm_report_markdown = result.text
    incident.llm_input_tokens = result.input_tokens
    incident.llm_output_tokens = result.output_tokens
    incident.llm_model_used = result.model
    ctx.analysis = (
        contracts.parse_into(contracts.AnalysisVerdict, result.text) or contracts.AnalysisVerdict()
    )
    ctx.stages["l2"] = ctx.analysis.model_dump()
    ctx.enrichment["stages"] = ctx.stages
    incident.enrichment = ctx.enrichment
    await _orch._persona_stage_done(
        session,
        incident,
        "l2",
        l2_t0,
        display=f"L2 verdict: {ctx.analysis.verdict} / {ctx.analysis.confidence}",
        payload={"verdict": ctx.analysis.verdict, "confidence": ctx.analysis.confidence},
    )
    await _orch._check_hallucinations(session, incident, result.text, ctx.deep_briefing)
    return True


def should_hunt(ctx: SynthCtx) -> bool:
    return agent_routing.should_hunt(ctx.analysis)


def should_forensics(ctx: SynthCtx) -> bool:
    return agent_routing.should_run_forensics(ctx.analysis, ctx.hunt)


async def run_hunt(session: Any, incident: Any, ctx: SynthCtx) -> None:
    from . import orchestrator as _orch

    h_t0 = await _orch._persona_stage_start(session, incident, "hunt")
    hunt_res = await complete(
        system=HUNT_SYSTEM,
        user=build_hunt_prompt(
            ctx.deep_briefing, ctx.analysis.model_dump(), _orch._hunt_iocs(ctx.enrichment)
        ),
        model=settings.isoc_model_deep,
    )
    session.add(
        _orch._llm_call_row(incident_id=incident.id, purpose="analyst_hunt", result=hunt_res)
    )
    if hunt_res.status == "ok":
        ctx.hunt = contracts.parse_into(contracts.HuntResult, hunt_res.text)
    if ctx.hunt:
        ctx.stages["hunt"] = ctx.hunt.model_dump()
        ctx.enrichment["stages"] = ctx.stages
        incident.enrichment = ctx.enrichment
    await _orch._persona_stage_done(
        session,
        incident,
        "hunt",
        h_t0,
        display=f"Hunt: {ctx.hunt.spread_assessment if ctx.hunt else 'no result'}"
        f"{f' ({len(ctx.hunt.queries)} queries)' if ctx.hunt else ''}",
    )


async def skip_hunt(session: Any, incident: Any) -> None:
    from . import orchestrator as _orch

    await _orch._emit(
        session,
        incident,
        "hunt_skipped",
        display="Threat hunt not warranted",
        level="info",
        step="hunt",
    )


async def run_forensic(session: Any, incident: Any, ctx: SynthCtx) -> None:
    from . import orchestrator as _orch

    f_t0 = await _orch._persona_stage_start(session, incident, "forensics")
    fz_res = await complete(
        system=FORENSIC_SYSTEM,
        user=build_forensic_prompt(
            ctx.deep_briefing,
            ctx.analysis.model_dump(),
            ctx.hunt.model_dump() if ctx.hunt else None,
        ),
        model=settings.isoc_model_deep,
    )
    session.add(
        _orch._llm_call_row(incident_id=incident.id, purpose="analyst_forensics", result=fz_res)
    )
    fz = (
        contracts.parse_into(contracts.ForensicResult, fz_res.text)
        if fz_res.status == "ok"
        else None
    )
    if fz:
        ctx.stages["forensics"] = fz.model_dump()
        ctx.enrichment["stages"] = ctx.stages
        incident.enrichment = ctx.enrichment
    await _orch._persona_stage_done(
        session,
        incident,
        "forensics",
        f_t0,
        display=f"Forensics scope: {fz.scope if fz else 'no result'}",
    )


async def skip_forensic(session: Any, incident: Any) -> None:
    from . import orchestrator as _orch

    await _orch._emit(
        session,
        incident,
        "forensics_skipped",
        display="Forensics not warranted",
        level="info",
        step="forensics",
    )


async def run_manager(session: Any, incident: Any, ctx: SynthCtx) -> None:
    """Deterministic manager: map verdict, build proposal + actions, park at the
    human gate (AWAITING_SIGNOFF). Verdict stays PENDING until analyst sign-off."""
    from . import orchestrator as _orch

    m_t0 = await _orch._persona_stage_start(session, incident, "synthesis")
    proposed_verdict = agent_routing.map_verdict_to_isoc(ctx.analysis.verdict)
    proposed_actions = agent_routing.propose_response_actions(
        ctx.analysis, ctx.enrichment, ctx.normalized
    )
    ctx.enrichment["proposal"] = {
        "proposed_verdict": proposed_verdict,
        "confidence": ctx.analysis.confidence,
        "reasoning": ctx.analysis.reasoning,
        "hunt_focus": ctx.analysis.hunt_focus,
    }
    ctx.enrichment["proposed_actions"] = [a.model_dump() for a in proposed_actions]
    incident.enrichment = ctx.enrichment
    conf = _orch._map_confidence(ctx.analysis.confidence)
    if conf is not None:
        incident.confidence = conf
    incident.status = CaseStatus.AWAITING_SIGNOFF
    await _orch._persona_stage_done(
        session,
        incident,
        "synthesis",
        m_t0,
        display=f"Proposed {proposed_verdict} — awaiting analyst sign-off",
        payload={"proposed_verdict": proposed_verdict, "action_count": len(proposed_actions)},
    )
    await _orch._emit(
        session,
        incident,
        "awaiting_signoff",
        display=f"Gate: analyst sign-off required → propose {proposed_verdict}",
        level="warn",
        step="synthesis",
        payload={
            "proposed_verdict": proposed_verdict,
            "proposed_actions": ctx.enrichment["proposed_actions"],
        },
    )
