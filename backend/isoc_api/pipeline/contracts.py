"""Typed handoff contracts for the agent-persona pipeline.

Ported from agentic-soc/schemas/contracts.json. Each persona LLM call returns
ONE of these as a fenced ```json block (plus, for L2, a markdown report). The
orchestrator parses + validates here, persists the dict under
`incident.enrichment["stages"][<persona>]`, and routes on the typed fields.

Persona verdict vocabulary stays in the agentic-soc form
(true_positive/false_positive/benign/inconclusive); the manager stage maps it
to isoc's Verdict enum (TP/FP/benign) when it builds the proposal.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from ..logging_config import get_logger

logger = get_logger("isoc.pipeline.contracts")


# ── Tolerant JSON-block extraction ──────────────────────────────────────────
_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def parse_json_block(text: str | None) -> dict[str, Any] | None:
    """Extract the last JSON object from an LLM response.

    Order of attempts: (1) a fenced ```json {...} ``` block (last one wins — L2
    emits a markdown report THEN the machine block), (2) brace-balanced scan
    from the first `{`. Returns None if nothing parses. Handles nested objects/
    arrays, unlike the legacy `\\{[^{}]*\\}` fast-classifier regex.
    """
    if not text:
        return None
    fenced = _FENCE_RE.findall(text)
    candidates = list(reversed(fenced)) if fenced else []
    balanced = _balanced_object(text)
    if balanced:
        candidates.append(balanced)
    for cand in candidates:
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def _balanced_object(text: str) -> str | None:
    start = text.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


# ── Stage contracts ─────────────────────────────────────────────────────────
class TriageResult(BaseModel):
    """L1 → manager. (isoc's fast classifier, recast.)"""

    model_config = {"extra": "ignore"}
    initial_severity: str = "medium"
    obvious_disposition: str = "needs_analysis"  # likely_fp | likely_tp | needs_analysis
    enrichment_needed: list[str] = Field(default_factory=list)
    reasoning: str = ""


class AttackStep(BaseModel):
    model_config = {"extra": "ignore"}
    step: int = 0
    technique: str = ""
    evidence: str = ""


class AnalysisVerdict(BaseModel):
    """L2 → manager."""

    model_config = {"extra": "ignore"}
    verdict: str = "inconclusive"  # true_positive | false_positive | benign | inconclusive
    confidence: str = "low"  # high | medium | low
    attack_chain: list[AttackStep] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    hunt_recommended: bool = False
    hunt_focus: str | None = None  # lateral_movement | persistence | exfil | c2 | null
    reasoning: str = ""


class HuntQuery(BaseModel):
    model_config = {"extra": "ignore"}
    platform: str = "s1ql"  # tmv1 | s1ql | sigma | kql
    query: str = ""
    rationale: str = ""


class HuntResult(BaseModel):
    """Threat hunter → manager. Query-building + reasoned spread assessment;
    `executed` is True only on an analyst-triggered hunt that ran the live V1
    endpoint-activity search."""

    model_config = {"extra": "ignore"}
    queries: list[HuntQuery] = Field(default_factory=list)
    executed: bool = False
    spread_assessment: str = "unknown"  # isolated | lateral_confirmed | unknown
    affected_hosts: list[str] = Field(default_factory=list)  # concrete hosts found in the search
    reasoning: str = ""


class HuntDecision(BaseModel):
    """Manager-owned hunt-routing decision (ADR-0009 D5). The manager decides
    WHETHER a hunt is warranted from L2 plus the pre-L2 Microsoft enrichment; the
    operator runs the live hunt at the gate. `run` gates the query-building hunt
    persona and surfaces the recommendation to the analyst. There is no `live`
    field: live execution stays operator-triggered (ADR-0009 Amendment 2)."""

    model_config = {"extra": "ignore"}
    run: bool = False
    focus: str | None = None  # carried from L2: lateral_movement | persistence | exfil | c2
    reason: str = ""


class TimelineEntry(BaseModel):
    model_config = {"extra": "ignore"}
    timestamp: str = ""
    event: str = ""
    source: str = ""


class ForensicResult(BaseModel):
    """Forensic analyst → manager. v1: reasoning over telemetry on hand."""

    model_config = {"extra": "ignore"}
    timeline: list[TimelineEntry] = Field(default_factory=list)
    root_cause: str = ""
    scope: str = "unknown"  # single_host | multi_host | unknown
    reasoning: str = ""


class ProposedAction(BaseModel):
    """A response action the manager PROPOSES. Never executed by the pipeline —
    only the approve endpoint runs the analyst-checked ones via v1_adapter."""

    model_config = {"extra": "ignore"}
    id: str
    kind: str  # blocklist_ioc | isolate_host | collect_file
    # Which EDR the gate dispatches this to. Defaults to vision_one for back-compat
    # (every existing proposal was V1); the Defender proposer sets microsoft_defender.
    provider: str = "vision_one"
    params: dict[str, Any] = Field(default_factory=dict)
    justification: str = ""
    status: str = "pending"  # pending | approved | rejected | executed | failed
    # Autonomy guardrails (3.9) — recommendation badge only; never auto-executes.
    blast_radius: str = "unknown"
    autonomy: str = "review"  # auto | review | escalate
    autonomy_reason: str = ""


class ManagerProposal(BaseModel):
    """Manager synthesis → the human gate."""

    model_config = {"extra": "ignore"}
    proposed_verdict: str = "pending"  # TP | FP | benign
    confidence: str = "low"
    summary: str = ""
    reasoning: str = ""
    proposed_actions: list[ProposedAction] = Field(default_factory=list)


def parse_into(model: type[BaseModel], text: str | None) -> BaseModel | None:
    """Parse an LLM response into a contract model, tolerant of fences/prose.
    Returns None on no-JSON or validation failure (logged, never raised)."""
    obj = parse_json_block(text)
    if obj is None:
        return None
    try:
        return model.model_validate(obj)
    except ValidationError as e:
        logger.warning("contracts.validation_failed", model=model.__name__, error=str(e)[:300])
        return None


# ── L2 verdict recovery — the report header when the JSON block is missing ────
_REC_RE = re.compile(
    r"\*\*\s*Recommendation:\s*(TRUE\s+POSITIVE|FALSE\s+POSITIVE|BENIGN|INCONCLUSIVE)\s*\*\*",
    re.IGNORECASE,
)
_CONF_RE = re.compile(r"Confidence:\s*\**\s*(HIGH|MEDIUM|LOW)", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_REC_MAP = {
    "truepositive": "true_positive",
    "falsepositive": "false_positive",
    "benign": "benign",
    "inconclusive": "inconclusive",
}


def recover_analysis_verdict(text: str | None) -> AnalysisVerdict | None:
    """Recover an L2 verdict from the markdown report header.

    The deep report ends with a fenced ``AnalysisVerdict`` JSON block, but if the
    model runs out of output tokens the block is truncated/absent and
    ``parse_into`` returns None. Rather than default to *inconclusive* and throw
    away a usable report, pull the verdict from the ``**Recommendation: ...**``
    and ``Confidence: ...`` headers the canonical template always emits first.
    """
    if not text:
        return None
    m = _REC_RE.search(text)
    if not m:
        return None
    verdict = _REC_MAP.get(re.sub(r"\s+", "", m.group(1)).lower())
    if not verdict:
        return None
    cm = _CONF_RE.search(text)
    confidence = cm.group(1).lower() if cm else "low"
    mitre = sorted(set(_MITRE_RE.findall(text)))
    return AnalysisVerdict(
        verdict=verdict,
        confidence=confidence,
        mitre_techniques=mitre,
        reasoning="Recovered from the markdown report header (the verdict JSON block "
        "was missing or truncated).",
    )


def parse_analysis_verdict(text: str | None) -> AnalysisVerdict | None:
    """L2 verdict parse: the fenced JSON block first, then the markdown-header
    fallback for a report that was truncated before its verdict block."""
    return parse_into(AnalysisVerdict, text) or recover_analysis_verdict(text)
