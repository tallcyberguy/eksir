"""End-to-end pipeline orchestrator.

This is the function the ARQ worker invokes when an alert is ingested.
It is also callable synchronously (for tests) — no FastAPI dependency.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters import (
    autoclose_adapter,
    cluster_store,
    entity_store,
    ipinfo_adapter,
    parser_adapter,
    store_adapter,
    triage_adapter,
)
from ..adapters.connectors import severity as _connector_severity
from ..auth.tenancy import ensure_tenant_for_customer
from ..db.enums import CaseStatus, Confidence, Severity, Verdict
from ..db.models import Incident, IOCRecord, TimelineEvent
from ..exclusions import filter as exclusions_filter
from ..logging_config import get_logger
from ..settings import settings
from ..threat_intel import lookup as ti_lookup
from ..threat_intel import scoring as ti_scoring
from . import (
    briefing,
    budget,
    decision,
    deobfuscate,
    guardrails,
    ioc_extract,
    ocsf,
    rerank,
    scoring,
    sensitive_rules,
    sla,
    temporal,
    yara_scan,
)

logger = get_logger("isoc.pipeline")

# ── n_way agreement thresholds (intentionally different per use) ──────────
# These three are NOT the same number on purpose; keeping them named makes the
# asymmetry explicit instead of looking like a bug:
#   POPULATE     — min verified priors needed to even build an n_way block for
#                  the briefing (informational; the LLM still decides).
#   CORROBORATE  — min verified agreement that lets a fast-tier HIGH FP/benign
#                  verdict be honored (the LLM already gave HIGH; this is just
#                  supporting evidence).
# The strictest threshold — the one that closes a case with NO LLM at all —
# lives in decision.py as N_WAY_CLOSE_MIN / N_WAY_CLOSE_TOTAL_MIN.
N_WAY_POPULATE_MIN = 3
N_WAY_CORROBORATE_MIN = 3


async def _emit(
    session: AsyncSession,
    incident: Incident,
    event_type: str,
    display: str | None = None,
    payload: dict | None = None,
    actor: str = "system",
    level: str = "info",
    step: str | None = None,
    duration_ms: int | None = None,
) -> None:
    session.add(
        TimelineEvent(
            incident_id=incident.id,
            ts=datetime.now(timezone.utc),
            actor=actor,
            event_type=event_type,
            display=display,
            payload=payload,
            level=level,
            step=step,
            duration_ms=duration_ms,
        )
    )
    await session.flush()


def _make_tool_emitter(
    session: AsyncSession, incident: Incident, step: str
) -> Callable[[str, dict, Any], Awaitable[None]]:
    """Build an ``on_tool_call`` hook for ``complete_with_tools`` that logs each tool
    invocation (name + args + a truncated result) to the incident timeline, so an
    analyst can see which API ran with which parameters. Best-effort."""
    import json

    async def _emit_tool(name: str, args: dict, result: Any) -> None:
        arg_str = ", ".join(f"{k}={str(v)[:60]}" for k, v in (args or {}).items())
        await _emit(
            session,
            incident,
            "tool_call",
            display=f"{name}({arg_str})"[:200],
            payload={
                "tool": name,
                "args": args,
                "result_preview": json.dumps(result, default=str)[:600],
            },
            step=step,
        )

    return _emit_tool


async def run_pipeline(session: AsyncSession, incident_id: uuid.UUID) -> None:
    """Drive an incident from RECEIVED → CLOSED (or AWAITING_REVIEW).

    Soft-failure model: each step is independently wrapped, so a parser miss
    or an embedder-empty error doesn't kill the run. The case still reaches
    LLM synthesis with whatever data we have, and the analyst can review.
    A hard-failure (e.g. DB error) still flips the case to FAILED.
    """
    incident = await session.get(Incident, incident_id)
    if incident is None:
        logger.error("pipeline.missing_incident", id=str(incident_id))
        return

    # BYOK: bind this incident's tenant so synthesis LLM calls resolve the
    # tenant's per-tenant provider override (if any). Reset in `finally`.
    from ..llm.client import request_tenant

    _tenant_token = request_tenant.set(incident.tenant_id)
    try:
        # F1 — SLA lifecycle: case detected (system). Best-effort.
        sla.record_sla_event(session, incident, sla.DETECTED)
        # Commit after each step so the timeline is durable and a single
        # SQLAlchemy transaction isn't held open across slow network I/O
        # (triage ~120s + the LLM call). expire_on_commit=False keeps the
        # incident usable across commits.
        for step_fn, label in (
            (_step_parse, "parse"),
            (_step_autoclose_pre, "auto_close_pre"),
            (_step_dedup, "dedup"),
            (_step_enrich, "enrich"),
            (_step_entities, "entities"),
            (_step_correlate, "correlate"),
            (_step_decision, "decision"),
        ):
            await _safe_step(session, incident, step_fn, label)
            await session.commit()

        if incident.status == CaseStatus.AWAITING_SYNTHESIS:
            # The persona pipeline emits its own per-stage events (l1/l2/hunt/
            # forensics/synthesis), so it is NOT wrapped in a single "synthesis"
            # _safe_step. A hard failure inside is caught by the outer try below.
            await _step_synthesis(session, incident)
            await session.commit()

        # DECIDED_SHORT_CIRCUIT → auto-closed (obvious FP, no gate).
        # AWAITING_SIGNOFF → manager parked at the human gate; leave it.
        # Anything else with a pending verdict still needs analyst eyes.
        if incident.status not in (CaseStatus.CLOSED, CaseStatus.AWAITING_SIGNOFF):
            incident.status = (
                CaseStatus.AWAITING_REVIEW
                if incident.verdict == Verdict.PENDING
                else CaseStatus.CLOSED
            )
        # F1 — auto-closed / short-circuit cases never reach the human gate, so
        # emit their resolved+closed SLA events here (system-attributed). Analyst-
        # gated cases are AWAITING_SIGNOFF now and get theirs at _commit_verdict.
        if incident.status == CaseStatus.CLOSED:
            # Ensure a resolution timestamp exists for SLA (the human gate sets
            # closed_at; auto-closed/short-circuit cases set it here).
            if incident.closed_at is None:
                incident.closed_at = datetime.now(timezone.utc)
            sla.record_sla_event(session, incident, sla.RESOLVED)
            sla.record_sla_event(
                session,
                incident,
                sla.CLOSED,
                meta={"auto": True, "verdict": str(incident.verdict)},
            )
            # ADR-0005: mirror the auto/short-circuit verdict to V1 (fail-soft, flag-gated).
            # Auto-closed FPs are the high-volume tenant-score-inflating case, so this matters
            # here as much as at the human gate. mirror_verdict_to_v1 never raises.
            from ..adapters import v1_adapter

            await v1_adapter.mirror_verdict_to_v1(incident, incident.verdict)
        # Terminal stage event — the checklist's final "Pipeline complete" row.
        await _emit(
            session,
            incident,
            "pipeline_done",
            display=f"Pipeline complete → {incident.status.value}",
            level="ok",
            step="complete",
        )
        await session.commit()
    except Exception as e:
        logger.exception("pipeline.failed", incident_id=str(incident_id), error=str(e))
        incident.status = CaseStatus.FAILED
        await _emit(
            session,
            incident,
            "pipeline_failed",
            display=str(e)[:200],
            level="error",
            step="complete",
        )
        await audit.log(
            session,
            action="pipeline.failed",
            target_type="incident",
            target_id=incident.id,
            tenant_id=incident.tenant_id,
            diff={
                "case_number": incident.case_number,
                "error": str(e)[:500],
                "error_type": type(e).__name__,
            },
        )
        await session.commit()
    finally:
        request_tenant.reset(_tenant_token)


# Canonical pipeline stages → human label. Drives the stage-checklist Timeline:
# the wrapper emits a `running` event on entry and an `ok`/`error` event on
# exit (with duration), so EVERY stage is visible — even ones that find nothing.
# Detail events emitted inside a step nest under the currently-open stage.
STAGE_LABELS = {
    "parse": "Parse & normalize",
    "auto_close_pre": "Auto-close check",
    "dedup": "RAG retrieve (similar cases)",
    "enrich": "Enrichment",
    "entities": "Entity resolution",
    "correlate": "Correlation",
    "decision": "Decision gate",
    # Persona stages (emitted from within _step_synthesis):
    "l1": "L1 triage",
    "l2": "L2 analysis",
    "hunt": "Threat hunt",
    "forensics": "Forensics",
    "synthesis": "Manager synthesis & gate",
}


async def _safe_step(session, incident, step_fn, label: str) -> None:
    """Run a step. Emit running→ok/error stage events with timing. Log + record
    on failure, but don't abort the run."""
    nice = STAGE_LABELS.get(label, label)
    await _emit(
        session, incident, f"{label}_running", display=f"{nice}…", level="running", step=label
    )
    t0 = time.monotonic()
    try:
        await step_fn(session, incident)
    except Exception as e:
        dur = int((time.monotonic() - t0) * 1000)
        logger.warning(
            "pipeline.step_failed", step=label, incident_id=str(incident.id), error=str(e)
        )
        await _emit(
            session,
            incident,
            f"{label}_failed",
            display=f"{nice} failed: {str(e)[:140]}",
            payload={"error": str(e)[:500]},
            level="error",
            step=label,
            duration_ms=dur,
        )
        await audit.log(
            session,
            action="pipeline.step_failed",
            target_type="incident",
            target_id=incident.id,
            tenant_id=incident.tenant_id,
            diff={
                "case_number": incident.case_number,
                "step": label,
                "error": str(e)[:500],
                "error_type": type(e).__name__,
            },
        )
        return
    dur = int((time.monotonic() - t0) * 1000)
    await _emit(
        session,
        incident,
        f"{label}_done",
        display=f"{nice} — done ({dur} ms)",
        level="ok",
        step=label,
        duration_ms=dur,
    )


# ── Steps ───────────────────────────────────────────────────────────────
async def _step_parse(session: AsyncSession, incident: Incident) -> None:
    payload = incident.raw_payload or {}
    raw = payload.get("raw") or ""
    if isinstance(payload, dict) and "text" in payload:
        raw = payload["text"]
    normalized = parser_adapter.parse_to_normalized(
        raw,
        source_hint=payload.get("source_hint") if isinstance(payload, dict) else None,
        field_map=payload.get("field_map") if isinstance(payload, dict) else None,
    )
    incident.normalized = normalized
    incident.rule_name = normalized.get("rule_name") or incident.rule_name
    incident.customer = normalized.get("customer") or incident.customer
    incident.source_product = normalized.get("source_product") or incident.source_product

    # ADR-0006 P1c (option B): drive the incident's initial severity from the alert's OCSF
    # severity_id, so a high/critical alert starts high/critical instead of the medium default.
    # (severity_id 0/Unknown maps to medium — the prior baseline; _bump_severity may still raise
    # it later in the low-confidence-but-real path.) SLA due times + queue order are severity-based,
    # so this makes both alert-aware from ingest.
    sev_id = normalized.get("severity_id")
    if isinstance(sev_id, int):
        incident.severity = Severity(_connector_severity.ocsf_to_severity_word(sev_id))

    # Always set the title — the route stub ("(pending parse)") is a placeholder.
    incident.title = _derive_title(incident.rule_name, incident.customer, raw)

    # Phase-1 tenancy: bind the incident to a tenant (create one if needed).
    if incident.customer and not incident.tenant_id:
        incident.tenant_id = await ensure_tenant_for_customer(session, incident.customer)

    incident.status = CaseStatus.PARSED
    await _emit(
        session,
        incident,
        "parse",
        display=f"Parsed as {incident.source_product or 'unknown'}",
        payload={"fields_extracted": list(normalized.keys())},
    )


def _derive_title(rule_name: str | None, customer: str | None, raw: str) -> str:
    """Best-effort title in order of preference:
    1) parsed rule_name (+ customer if present)
    2) first line of raw that looks like a rule/alert label
    3) first non-empty line of raw, truncated
    4) generic timestamped fallback
    """
    if rule_name:
        return f"{rule_name} — {customer}" if customer else rule_name

    raw = (raw or "").strip()
    if raw:
        # Heuristics — try to spot the rule/alert label in the raw text.
        # All patterns are line-anchored (^…) so they don't match inside embedded
        # message bodies (e.g. the "Subject:\r\nSecurity ID:…" block in EventID 4722).
        # Order matters: more specific formats first.
        import re

        patterns = [
            # Wazuh ossec-monitord email: Rule: <id> fired (level N) -> "<desc>"
            r'^Rule:\s*\d+\s*fired\s*\(level\s*\d+\)\s*->\s*"([^"]+)"',
            # QRadar / Wazuh email header lines
            r"^Rule\s*Name\s*:\s*(.+)",
            # PAN-OS / LEEF inline (rare standalone, more common inside QRadar payload)
            r"^RuleName\s*=\s*([^|]+)",
            # Wazuh native JSON: "rule": { ... "description": "..." ...
            r'"rule"\s*:\s*\{[^}]*"description"\s*:\s*"([^"]+)"',
            # SentinelOne / generic SOAR
            r"^alert_name\s*[:=]\s*(.+)",
            r"^Threat\s*Name\s*:\s*(.+)",
            # Email-style alerts — last resort, line-anchored so we don't pick
            # up "Subject:" from inside an embedded Windows event message.
            r"^Subject\s*:\s*(.+)",
        ]
        for pat in patterns:
            m = re.search(pat, raw, re.IGNORECASE | re.MULTILINE)
            if m:
                cand = m.group(1).strip().splitlines()[0].strip().rstrip(",")
                if cand and not cand.startswith("\\"):  # skip escaped-newline garbage
                    return cand[:140] + (" — " + customer if customer else "")

        # Fall back to the first non-empty line, truncated.
        for line in raw.splitlines():
            line = line.strip()
            if line:
                return (line[:120] + "…") if len(line) > 120 else line

    from datetime import datetime, timezone

    return f"Unparsed alert — {datetime.now(timezone.utc).isoformat(timespec='seconds')}"


async def _step_autoclose_pre(session: AsyncSession, incident: Incident) -> None:
    fields = _alert_fields(incident.normalized or {})
    # autoclose_adapter.check() is now async — it merges DB-stored rules
    # (admin UI) with YAML rules before evaluating. No more `to_thread`.
    result = await autoclose_adapter.check(fields, None)
    if result:
        incident.autoclose_match = {"pre": result}
        incident.status = CaseStatus.AUTO_CLOSED_CANDIDATE
        await _emit(
            session,
            incident,
            "auto_close_pre",
            display=f"YAML rule `{result.get('rule_id')}` → {result.get('verdict')}",
            payload=result,
        )


async def _step_dedup(session: AsyncSession, incident: Incident) -> None:
    normalized = incident.normalized or {}
    customer = incident.customer
    # Two parallel calls only — n_way is computed locally from `sim` below,
    # so it inherits the min_score filter and we save a network round-trip
    # (Phase-RAG-C). Field name `similar_top5` kept for backward compat with
    # downstream readers (decision/briefing/customer_cases).
    exact, sim = await asyncio.gather(
        store_adapter.find_exact_match(normalized, customer),
        store_adapter.search_similar(normalized, customer, top_k=10),
    )
    # Heuristic re-rank: bias toward human-verified, recent, well-reasoned
    # prior cases. Original Qdrant score preserved in `score`; new field
    # `adjusted_score` drives the order.
    sim_ranked = rerank.rerank(sim or [], customer)
    nway = _compute_n_way(sim_ranked, customer, min_agreement=N_WAY_POPULATE_MIN)

    enrichment = incident.enrichment or {}
    enrichment.update(
        {
            "exact_match": exact,
            "n_way": nway,
            "similar_top5": sim_ranked,
        }
    )
    incident.enrichment = enrichment
    if exact:
        await _emit(
            session,
            incident,
            "exact_match",
            display=f"Vector DB exact-match score {exact.get('score')} → {exact.get('verdict')}",
            payload={"alert_id": exact.get("alert_id")},
        )
    if nway:
        await _emit(
            session,
            incident,
            "n_way",
            display=f"N-way agreement {nway.get('agreement')} → {nway.get('verdict')}",
        )


def _compute_n_way(
    matches: list[dict], customer: str | None, min_agreement: int = N_WAY_POPULATE_MIN
) -> dict | None:
    """Tally verdicts across `matches` and return the majority if ≥ min_agreement.

    Operates on whatever survived the min_score filter — so 5 matches all
    scoring < 0.55 are already gone, and we don't fabricate "3/5 → benign"
    from boilerplate collisions (the bug that motivated Phase-RAG-C).

    Only analyst-verified priors are counted: an unverified pool (e.g. earlier
    *automated* verdicts) must never be allowed to drive an auto-close. If the
    verified subset is too small, we return None and the case escalates to the
    LLM — the safe direction.
    """
    if not matches:
        return None

    # Only count analyst-verified priors from the SAME tenant. A different customer's
    # FP must never form a majority for this one (that produced the "3/7 EMINEVIM" noise
    # on INC-001140), and a null-customer query matches only null-customer priors.
    q_cust = store_adapter.canonical_customer(customer)
    verified = [
        m
        for m in matches
        if m.get("human_verified") and store_adapter.canonical_customer(m.get("customer")) == q_cust
    ]
    if len(verified) < min_agreement:
        return None

    counts: dict[str, int] = {}
    for m in verified:
        v = m.get("verdict")
        if v:
            counts[v] = counts.get(v, 0) + 1
    if not counts:
        return None

    winner, count = max(counts.items(), key=lambda kv: kv[1])
    if count < min_agreement:
        return None

    return {
        "verdict": winner,
        "agreement": f"{count}/{len(verified)}",
        "matches": [m for m in verified if m.get("verdict") == winner],
    }


async def _step_enrich(session: AsyncSession, incident: Incident) -> None:
    incident.status = CaseStatus.ENRICHING
    await _emit(session, incident, "enrich_start", display="Parallel enrichment started")

    # Extract IOCs
    raw_text = (
        (incident.raw_payload or {}).get("text") or (incident.raw_payload or {}).get("raw") or ""
    )
    iocs_raw = ioc_extract.extract(incident.normalized or {}, raw_text)

    # ── Deobfuscation: decode hidden payloads, surface their IOCs ───────────
    # Cheap pure-Python pass. Decoded artifacts are re-run through ioc_extract
    # so a C2 hidden inside a base64 -EncodedCommand gets MERGED into the IOC
    # set here — BEFORE exclusions/triage — and thus receives the full
    # threat-intel treatment. The decoded text + obfuscation score are stashed
    # in enrichment for the briefing, the LLM report, and the UI panel.
    deob = deobfuscate.analyze(incident.normalized or {}, raw_text)
    if deob is not None:
        original_values = {v.lower() for (_, v) in iocs_raw}
        decoded_iocs: list[dict[str, Any]] = []
        for art in deob.get("artifacts", []):
            for t, v in ioc_extract.extract({}, art.get("decoded_text") or ""):
                key = v.lower()
                is_new = key not in original_values
                if is_new:
                    iocs_raw.append((t, v))
                    original_values.add(key)
                decoded_iocs.append(
                    {
                        "type": t.value,
                        "value": v,
                        "encoding": art.get("encoding"),
                        "layer": art.get("layer"),
                        "new": is_new,
                    }
                )
        deob["decoded_iocs"] = decoded_iocs
        enrichment = incident.enrichment or {}
        enrichment["deobfuscation"] = deob
        incident.enrichment = enrichment
        obf = deob.get("obfuscation", {})
        await _emit(
            session,
            incident,
            "deobfuscation",
            display=(
                f"Decoded {len(deob.get('artifacts', []))} payload layer(s); "
                f"obfuscation {obf.get('band', '?')} ({obf.get('score', 0)}); "
                f"{sum(1 for d in decoded_iocs if d['new'])} new IOC(s)"
            ),
            payload={
                "artifacts": len(deob.get("artifacts", [])),
                "obfuscation": obf,
                "new_iocs": [d["value"] for d in decoded_iocs if d["new"]][:10],
            },
        )

    # ── YARA-Forge on alert content (script/command fields + decoded payloads) ─
    # Bounded, cached, fail-soft (see pipeline/yara_scan.py). Matches are stashed
    # under deobfuscation so the briefing, LLM, and UI panel all see them. We
    # create a minimal deobfuscation entry if decoding found nothing but a
    # script/command field still produced a signature hit.
    try:
        yara_matches = await yara_scan.scan_alert_content(incident.normalized or {}, deob)
    except Exception as e:  # never let YARA break enrichment
        logger.warning("pipeline.yara_content_failed", incident_id=str(incident.id), error=str(e))
        yara_matches = []
    if yara_matches:
        enrichment = incident.enrichment or {}
        deob_entry = enrichment.get("deobfuscation") or {
            "artifacts": [],
            "obfuscation": {"score": 0.0, "band": "none", "encoded_layers": 0},
            "decoded_iocs": [],
        }
        deob_entry["yara_matches"] = yara_matches
        enrichment["deobfuscation"] = deob_entry
        incident.enrichment = enrichment
        await _emit(
            session,
            incident,
            "yara_content_match",
            display=f"YARA-Forge matched {len(yara_matches)} rule(s) on decoded/command content",
            payload={"rules": [m.get("rule") for m in yara_matches[:10]]},
        )

    # Apply analyst exclusions BEFORE any downstream step. `excluded` is stashed
    # in enrichment and surfaced to the LLM so the analyst's judgement is visible.
    iocs_typed_for_filter = [(t.value, v) for (t, v) in iocs_raw]
    kept_pairs, excluded = await exclusions_filter.apply(
        session, iocs_typed_for_filter, customer=incident.customer
    )
    # Re-key kept_pairs back to the (IOCType, value) tuple the rest of the
    # pipeline expects.
    type_lookup = {t.value: t for (t, _) in iocs_raw}
    iocs = [(type_lookup[t_str], v) for (t_str, v) in kept_pairs if t_str in type_lookup]

    if excluded:
        enrichment = incident.enrichment or {}
        enrichment["excluded_iocs"] = excluded
        incident.enrichment = enrichment
        await _emit(
            session,
            incident,
            "iocs_excluded",
            display=f"Excluded {len(excluded)} IOC(s) by allowlist",
            payload={"count": len(excluded), "values": [e["value"] for e in excluded[:10]]},
        )

    for t, v in iocs:
        # Idempotent insert — uniqueness constraint will reject duplicates silently
        session.add(
            IOCRecord(
                incident_id=incident.id,
                ioc_type=t,
                value=v,
                tenant=incident.customer,
            )
        )
    await session.flush()

    # Local threat-intel match — cheap DB lookup, one query for all extracted
    # (and kept) IOCs. A hit is a "soft signal": severity bumped one notch,
    # confidence raised to HIGH, matches stashed in enrichment for the LLM.
    ti_matches = await ti_lookup.match_iocs(
        session,
        [(t.value, v) for (t, v) in iocs],
    )
    if ti_matches:
        await _apply_threat_intel_signal(session, incident, ti_matches)

    triage_args = ioc_extract.to_triage_args(iocs)
    public_ips = [v for (t, v) in iocs if t.value.startswith("ipv") and ioc_extract.is_public_ip(v)]
    kb_query = " ".join(filter(None, [incident.rule_name, incident.customer]))

    triage_task = (
        triage_adapter.triage_many(triage_args, timeout=120) if triage_args else _empty_list()
    )
    ipinfo_task = (
        asyncio.gather(*[ipinfo_adapter.enrich_ip(ip) for ip in public_ips])
        if public_ips
        else _empty_list()
    )
    # Skip KB search when there's nothing to embed. An empty query makes the
    # bge-m3 embedder raise "Cannot embed empty text"; with a plain gather that
    # one failure aborted the WHOLE enrich step, silently discarding triage and
    # ipinfo too. Guard the query AND isolate failures below.
    kb_task = (
        store_adapter.search_kb(kb_query, incident.customer, incident.rule_name)
        if kb_query.strip()
        else _empty_list()
    )

    # ── Vision One workbench detail (ADR-0005, read-only, fail-soft) ────────
    # Only for a visionone alert with a WB id, behind v1_autofetch_enabled.
    # Joins the SAME gather so a dead/slow V1 API can never abort its siblings.
    v1_task = _empty_list()
    if (
        settings.v1_autofetch_enabled
        and (incident.normalized or {}).get("source_product") == "visionone"
    ):
        _wb_id, _ = _v1_alert_ref(incident)
        if _wb_id:
            v1_task = _fetch_v1(incident, _wb_id)

    # return_exceptions=True so a single failing branch can't nuke its siblings.
    triage_results, ip_enrichments, kb_hits, v1_result = await asyncio.gather(
        triage_task, ipinfo_task, kb_task, v1_task, return_exceptions=True
    )

    enrich_failures: list[tuple[str, str]] = []

    def _ok(res: Any, label: str) -> list:
        if isinstance(res, BaseException):
            logger.warning(
                "pipeline.enrich_subtask_failed",
                subtask=label,
                incident_id=str(incident.id),
                error=str(res),
            )
            enrich_failures.append((label, str(res)))
            return []
        return res or []

    triage_results = _ok(triage_results, "triage")
    ip_enrichments = _ok(ip_enrichments, "ipinfo")
    kb_hits = _ok(kb_hits, "kb_search")
    v1_result = _ok(v1_result, "v1_fetch")

    # Surface swallowed subtask failures on the timeline (was log-only) so the
    # analyst can see when triage / IP-info / KB lookups didn't actually run.
    _subtask_labels = {
        "triage": "Threat-intel triage",
        "ipinfo": "IP/rDNS enrichment",
        "kb_search": "Knowledge-base search",
        "v1_fetch": "Vision One workbench fetch",
    }
    for label, err in enrich_failures:
        await _emit(
            session,
            incident,
            "enrich_subtask_failed",
            display=f"{_subtask_labels.get(label, label)} failed — {err[:120]}",
            payload={"subtask": label, "error": err[:300]},
            level="warn",
            step="enrich",
        )

    enrichment = incident.enrichment or {}
    enrichment.update(
        {
            "triage": triage_results,
            "ipinfo": ip_enrichments,
            "kb_hits": kb_hits,
        }
    )
    incident.enrichment = enrichment

    # Vision One workbench/OAT detail (capped dict from _fetch_v1, or [] on failure).
    if v1_result:
        enrichment["v1"] = v1_result
        incident.enrichment = enrichment
        wb = v1_result.get("workbench") or {}
        await _emit(
            session,
            incident,
            "v1_workbench",
            display=(
                f"Vision One detail fetched: {wb.get('model') or '—'} "
                f"(score {wb.get('score', '?')}); {len(v1_result.get('oat') or [])} OAT row(s)"
            ),
            payload={
                "workbench_id": v1_result.get("workbench_id"),
                "region": v1_result.get("region"),
                "mitre": wb.get("mitreTechniqueIds"),
                "oat_count": len(v1_result.get("oat") or []),
            },
            step="enrich",
        )

    # Post-enrichment auto-close pass
    post_fields = _alert_fields(incident.normalized or {})
    post_enrichment = {
        "dst_asn": (ip_enrichments[0]["org"] if ip_enrichments else None),
        "dst_hostnames": [
            h.get("name") for r in triage_results for h in (r.get("hostnames") or [])
        ][:10],
        # triage.py is inconsistent about the field name (vt_malicious vs
        # virustotal_malicious) — read both so a malicious score under the
        # alternate key can't be misread as clean.
        "vt_clean": all(
            max(
                _int(r.get("summary", {}).get("vt_malicious")),
                _int(r.get("summary", {}).get("virustotal_malicious")),
            )
            <= 1
            for r in triage_results
        ),
        "abuseipdb_score": max(
            (_int(r.get("summary", {}).get("abuseipdb")) for r in triage_results), default=0
        ),
    }
    post_match = await autoclose_adapter.check(post_fields, post_enrichment)
    if post_match:
        incident.autoclose_match = {**(incident.autoclose_match or {}), "post": post_match}
        await _emit(
            session,
            incident,
            "auto_close_post",
            display=f"Post-enrich YAML rule `{post_match.get('rule_id')}` → {post_match.get('verdict')}",
            payload=post_match,
        )

    await _emit(
        session,
        incident,
        "enrich_done",
        display=f"Enriched {len(triage_results)} IOCs, {len(ip_enrichments)} IPs, {len(kb_hits)} KB hits",
        payload={"triage_count": len(triage_results)},
    )


async def _step_entities(session: AsyncSession, incident: Incident) -> None:
    """Resolve OCSF-shaped entities from the normalized alert and link them.

    Deterministic: `ocsf.to_entities` extracts device/user/network_endpoint/
    file/observable candidates. Each is UPSERTed on (customer, entity_type,
    canonical_key) — file + file-hash observables are GLOBAL (customer=None) —
    via PG ON CONFLICT and linked to this incident idempotently. A compact
    projection is stashed in `enrichment['entities']` for the briefing.

    Best-effort by construction: each candidate runs inside its own SAVEPOINT
    (`begin_nested`), so a bad row (an over-long value, a rare DB error) rolls
    back only that savepoint and never deactivates the run's transaction. The
    outer `_safe_step` wrapper is the final guard.
    """
    normalized = incident.normalized or {}
    enrichment = incident.enrichment or {}
    ents = ocsf.to_entities(normalized, incident.customer)
    if not ents:
        return

    now = datetime.now(timezone.utc)
    links: list[dict] = []
    for e in ents:
        try:
            async with session.begin_nested():  # SAVEPOINT — contains any per-row failure
                entity_id = await entity_store.upsert_entity(session, e, now)
                if entity_id is None:
                    continue
                await entity_store.link_incident_entity(
                    session, incident.id, entity_id, e["role"] or "observable"
                )
            links.append(
                {
                    "kind": e["entity_type"],
                    "value": e["display_name"],
                    "role": e["role"],
                    "entity_id": str(entity_id),
                }
            )
        except Exception as ex:  # noqa: BLE001 — one bad candidate must not drop the rest
            logger.warning(
                "pipeline.entity_resolve_failed",
                incident_id=str(incident.id),
                entity_type=e.get("entity_type"),
                error=str(ex),
            )

    # Annotate prior entity risk (confirmed-TP history from EARLIER incidents) so
    # the briefing can tell the personas "this host already has a track record".
    # Best-effort — risk is advisory and never blocks the step.
    if links:
        try:
            risk_map = await entity_store.get_risk_scores(
                session, [uuid.UUID(link["entity_id"]) for link in links]
            )
            for link in links:
                risk = risk_map.get(uuid.UUID(link["entity_id"]))
                if risk is not None:
                    link["risk"] = round(risk)
        except Exception as ex:  # noqa: BLE001
            logger.warning(
                "pipeline.entity_risk_annotate_failed",
                incident_id=str(incident.id),
                error=str(ex),
            )

    if links:
        enrichment["entities"] = links
        # ADR-0006 P1c: additively stash the OCSF Detection Finding envelope (severity_id +
        # product + observables) alongside the entities. Best-effort; never blocks the step.
        try:
            event = ocsf.to_ocsf_event(normalized, incident.customer)
            if event:
                enrichment["ocsf_event"] = event
        except Exception as ex:  # noqa: BLE001
            logger.warning(
                "pipeline.ocsf_event_failed", incident_id=str(incident.id), error=str(ex)
            )
        incident.enrichment = enrichment
        await _emit(
            session,
            incident,
            "entities_resolved",
            display=f"Resolved {len(links)} entity link(s)",
            payload={"entities": links[:20]},
            step="entities",
        )


async def _step_correlate(session: AsyncSession, incident: Incident) -> None:
    """Group this incident with same-tenant siblings that share a strong entity.

    Off by default (``settings.correlation_enabled``). Best-effort: the outer
    ``_safe_step`` wraps it and the inner try guards the union so a failure here
    never aborts the run or blocks the decision gate. Only emits + stashes when a
    real (>1-member) cluster results — a lone incident is a no-op.
    """
    if not settings.correlation_enabled:
        return
    try:
        # SAVEPOINT: any unprotected statement inside correlate_incident (cluster
        # create/merge/delete, reconcile, the advisory-lock SELECT) rolls back only
        # this savepoint on failure, so a correlation error can never leave the run's
        # transaction in a pending-rollback state and abort the gate. The advisory
        # lock is transaction-scoped and stays held by the outer txn regardless, so
        # cross-incident serialization is preserved. Correlation is advisory.
        async with session.begin_nested():
            result = await cluster_store.correlate_incident(
                session,
                incident,
                window_hours=settings.correlation_window_hours,
                fanout_cap=settings.correlation_fanout_cap,
                min_shared=settings.correlation_min_shared,
            )
    except Exception as ex:  # noqa: BLE001 — correlation is advisory, never fatal
        logger.warning("pipeline.correlate_failed", incident_id=str(incident.id), error=str(ex))
        return

    if not result or int(result.get("member_count") or 0) <= 1:
        return

    enrichment = incident.enrichment or {}
    enrichment["cluster"] = {
        "cluster_id": result["cluster_id"],
        "member_count": result["member_count"],
    }
    incident.enrichment = enrichment
    await _emit(
        session,
        incident,
        "cluster_linked",
        display=f"Correlated into a cluster of {result['member_count']} incidents",
        payload=enrichment["cluster"],
        step="correlate",
    )


async def _step_decision(session: AsyncSession, incident: Incident) -> None:
    enrichment = incident.enrichment or {}

    # Sensitive-rule guard MUST run here — BEFORE any deterministic short-circuit.
    # Previously it only protected the fast-tier LLM gate inside _step_synthesis,
    # so a sensitive rule (admin login, lateral movement, …) with a benign prior
    # could be auto-closed with no LLM and no human. Compute + persist once so
    # _step_synthesis and the briefing stay consistent.
    normalized = incident.normalized or {}
    sens_match, sens_kw = sensitive_rules.is_sensitive(
        incident.rule_name,
        normalized.get("event_name"),
        normalized.get("event_description"),
    )
    if sens_match:
        enrichment["sensitive_rule"] = {"matched": True, "keyword": sens_kw}
        incident.enrichment = enrichment
        incident.status = CaseStatus.AWAITING_SYNTHESIS
        await _emit(
            session,
            incident,
            "decision_gate",
            display=(
                f"Sensitive rule (`{sens_kw}`) — deterministic short-circuit "
                "disabled, escalating to LLM synthesis"
            ),
            payload={"sensitive": True, "keyword": sens_kw},
        )
        return

    # Honor an admin auto-close rule whether it matched pre- OR post-enrichment.
    # (The pre-enrichment match previously set AUTO_CLOSED_CANDIDATE but was
    # never consumed by the gate — effectively dead. The _ti_clean check inside
    # decision.evaluate still applies, using post-enrichment triage.)
    autoclose_match = incident.autoclose_match or {}
    autoclose = autoclose_match.get("post") or autoclose_match.get("pre")

    verdict, confidence, sc = decision.evaluate(
        exact_match=enrichment.get("exact_match"),
        n_way=enrichment.get("n_way"),
        autoclose=autoclose,
        triage_results=enrichment.get("triage") or [],
    )
    if verdict and confidence and sc:
        incident.verdict = verdict
        incident.confidence = confidence
        incident.short_circuit = sc
        # Fused scores for the short-circuit path too (no L2 analysis on hand).
        try:
            enrichment["scores"] = scoring.compute_scores(
                scoring.build_bundle(
                    enrichment,
                    proposed_verdict=verdict.value,
                    llm_band=confidence.value,
                    severity=incident.severity,
                    vendor_score=(incident.normalized or {}).get("vendor_score"),
                )
            ).as_payload()
        except Exception:
            logger.warning("scoring.compute_failed", incident_id=str(incident.id))
        incident.enrichment = enrichment
        incident.status = CaseStatus.DECIDED_SHORT_CIRCUIT
        await _emit(
            session,
            incident,
            "decision_gate",
            display=f"Short-circuit ({sc['gate']}) → {verdict.value} / {confidence.value}",
            payload=sc,
        )
    else:
        incident.status = CaseStatus.AWAITING_SYNTHESIS
        await _emit(
            session, incident, "decision_gate", display="Inconclusive — escalating to LLM synthesis"
        )


async def _step_synthesis(
    session: AsyncSession,
    incident: Incident,
    *,
    force_deep: bool = False,
) -> None:
    """Two-tier LLM synthesis.

    Tier 1 (fast): cheap classifier returns {verdict, confidence, reason}.
      - HIGH-conf FP/benign  → short-circuit, skip deep model entirely
      - HIGH-conf TP         → still run deep (we want the full report)
      - MEDIUM / LOW         → run deep, with fast verdict surfaced in briefing
    Tier 2 (deep): canonical Senior Tier-3 analyst report.

    When `force_deep=True` (analyst-initiated regenerate), the fast tier and
    every short-circuit gate are skipped — we go straight to deep. This is
    the escape hatch when the analyst disagrees with an automatic verdict.

    After deep runs, a hallucination check compares IOCs in the report against
    the IOCs the briefing actually carried.
    """
    # F8: when enabled, the LangGraph StateGraph owns the synthesis control flow.
    # It calls the SAME phase logic (pipeline.synthesis_steps), so behaviour is
    # identical — only the orchestration + checkpointing differ. Default off; the
    # legacy inline sequence below remains the fallback until the graph path is
    # validated on the stack.
    if settings.isoc_use_langgraph:
        from .synthesis_graph import run_synthesis_graph

        await run_synthesis_graph(session, incident, force_deep=force_deep)
        return

    from ..db.enums import Confidence
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
    from . import agent_routing, contracts

    enrichment = incident.enrichment or {}

    # Compute deterministic context that the LLM needs to see explicitly.
    # These are NOT signals the LLM has to extract from the raw — we want
    # them in their own briefing sections so they're impossible to overlook.
    normalized = incident.normalized or {}
    temporal_ctx = temporal.derive(normalized.get("timestamp"))
    sens_match, sens_kw = sensitive_rules.is_sensitive(
        incident.rule_name,
        normalized.get("event_name"),
        normalized.get("event_description"),
    )
    sensitive_ctx = {"matched": sens_match, "keyword": sens_kw} if sens_match else None

    # Persist for transparency in the UI / audit log.
    if temporal_ctx:
        enrichment["temporal"] = temporal_ctx
    if sensitive_ctx:
        enrichment["sensitive_rule"] = sensitive_ctx
    incident.enrichment = enrichment

    if sensitive_ctx:
        await _emit(
            session,
            incident,
            "sensitive_rule_match",
            display=f"Sensitive rule pattern matched (`{sens_kw}`) — fast-tier short-circuit disabled",
            payload=sensitive_ctx,
        )

    def _render(extra: dict | None = None) -> str:
        return briefing.render(
            normalized=incident.normalized or {},
            autoclose_pre=(incident.autoclose_match or {}).get("pre"),
            autoclose_post=(incident.autoclose_match or {}).get("post"),
            exact_match=enrichment.get("exact_match"),
            n_way=enrichment.get("n_way"),
            similar=enrichment.get("similar_top5") or [],
            kb_hits=enrichment.get("kb_hits") or [],
            triage_results=enrichment.get("triage") or [],
            ip_enrichments=enrichment.get("ipinfo") or [],
            threat_intel_matches=enrichment.get("threat_intel_matches") or [],
            excluded_iocs=enrichment.get("excluded_iocs") or [],
            fast_classifier=(extra or {}).get("fast_classifier"),
            temporal=temporal_ctx,
            sensitive=sensitive_ctx,
            deobfuscation=enrichment.get("deobfuscation"),
            v1_enrichment=enrichment.get("v1"),
            entities=enrichment.get("entities") or [],
            cluster=enrichment.get("cluster"),
            ms_reputation=(enrichment.get("ms") or {}).get("reputation"),
            ms_endpoint=(enrichment.get("ms") or {}).get("endpoint"),
            ms_identity=(enrichment.get("ms") or {}).get("identity"),
        )

    # ── Tier 1: fast classifier ─────────────────────────────────────────
    # Skipped entirely on force_deep — saves a fast-tier call and avoids any
    # chance of an analyst-overridden case bouncing back through a gate.
    fast_verdict: dict | None = None
    if not force_deep:
        l1_t0 = await _persona_stage_start(session, incident, "l1")
        fast_briefing = _render()
        fast_result = await complete(
            system=FAST_CLASSIFIER_SYSTEM,
            user=build_fast_classifier_prompt(fast_briefing),
            model=settings.isoc_model_fast,
            max_tokens=200,
            temperature=0.0,
        )
        session.add(
            _llm_call_row(
                incident_id=incident.id,
                purpose="analyst_fast",
                result=fast_result,
            )
        )

        if fast_result.status == "ok":
            fast_verdict = _parse_fast_classifier(fast_result.text)
            enrichment["fast_classifier"] = fast_verdict
            _stages = dict(enrichment.get("stages") or {})
            _stages["l1"] = _triage_result_from_fast(fast_verdict, incident.severity)
            enrichment["stages"] = _stages
            incident.enrichment = enrichment
            await _persona_stage_done(
                session,
                incident,
                "l1",
                l1_t0,
                display=(
                    f"L1 triage: {fast_verdict.get('verdict', '?')} / "
                    f"{fast_verdict.get('confidence', '?')}"
                ),
                payload=fast_verdict,
            )
        else:
            await _persona_stage_done(
                session,
                incident,
                "l1",
                l1_t0,
                display=f"L1 fast classifier {fast_result.status}; escalating to L2",
                level="warn",
            )
    else:
        # Clear any short-circuit metadata from a prior pipeline run so the
        # post-deep state cleanly reflects the bypass.
        incident.short_circuit = None
        await _emit(
            session,
            incident,
            "deep_forced",
            display="Analyst bypass — running deep model directly, skipping fast tier and gates",
            payload={},
        )

    # ── Short-circuit gate on HIGH-conf FP/benign ───────────────────────
    # Trust ladder (each step must pass):
    #   1. Fast tier said HIGH + FP/benign
    #   2. Rule is NOT in the sensitive-pattern allowlist
    #   3. Briefing has actual corroborating evidence (exact_match, n_way,
    #      or autoclose). Self-rated HIGH alone is not enough.
    # Any failure → fall through to deep synthesis with a timeline note
    # explaining why we ignored the fast verdict.
    if fast_verdict:
        v = (fast_verdict.get("verdict") or "").upper()
        c = (fast_verdict.get("confidence") or "").upper()
        if c == "HIGH" and v in ("FP", "BENIGN"):
            block_reason = _short_circuit_block_reason(
                verdict_str=v,
                sensitive=sensitive_ctx,
                exact_match=enrichment.get("exact_match"),
                n_way=enrichment.get("n_way"),
                autoclose_match=incident.autoclose_match or {},
            )
            if block_reason:
                # Fast tier was over-confident — escalate to deep, surface why.
                await _emit(
                    session,
                    incident,
                    "short_circuit_blocked",
                    display=f"Fast-tier HIGH ignored — {block_reason}",
                    payload={"reason": block_reason, "fast_verdict": fast_verdict},
                )
            else:
                incident.verdict = Verdict.FP if v == "FP" else Verdict.BENIGN
                incident.confidence = Confidence.HIGH
                incident.short_circuit = {
                    "gate": "fast_classifier",
                    "reason": fast_verdict.get("reason"),
                }
                incident.status = CaseStatus.DECIDED_SHORT_CIRCUIT
                await _emit(
                    session,
                    incident,
                    "decision_gate",
                    display=f"Fast-tier short-circuit → {v} / HIGH",
                    payload=fast_verdict,
                )
                return

    # ── L2: deep technical verdict (recast deep synthesis) ──────────────
    stages: dict = dict(enrichment.get("stages") or {})
    if "l1" not in stages and fast_verdict:
        stages["l1"] = _triage_result_from_fast(fast_verdict, incident.severity)

    l2_t0 = await _persona_stage_start(session, incident, "l2")

    # Cost governance: if a USD cap is hit, skip the (expensive) deep call and
    # park for a human — never auto-decide. No-op unless a cap is configured.
    budget_block = await budget.over_budget(session, incident.id)
    if budget_block:
        await _persona_stage_done(
            session,
            incident,
            "l2",
            l2_t0,
            display=f"L2 skipped — {budget_block}. Raise the cap or regenerate later.",
            level="error",
        )
        incident.status = CaseStatus.AWAITING_REVIEW
        return

    # ADR-0009 PR-1: deterministic pre-L2 Microsoft enrichment (reputation of the
    # alert's IOCs). Read-only, fail-soft, gated (ms_autoenrich_enabled + creds).
    # Escalated-only by construction: short-circuited alerts already returned above.
    from . import prefetch

    ms = await prefetch.prefetch_ms_enrichment(incident)
    if ms is not None:
        enrichment = incident.enrichment or enrichment  # refresh local binding for _render
        _parts: list[str] = []
        _rep = ms.get("reputation") or {}
        _n = sum(len(_rep.get(k) or []) for k in ("files", "domains", "ips"))
        if _n:
            _parts.append(f"{_n} indicator(s)")
        if ms.get("endpoint"):
            _parts.append("endpoint")
        if ms.get("identity"):
            _parts.append("identity")
        await _emit(
            session,
            incident,
            "ms_autoenrich",
            display="Pre-L2 Microsoft enrichment: " + (", ".join(_parts) or "none"),
            payload={"slices": [k for k in ("reputation", "endpoint", "identity") if ms.get(k)]},
            step="l2",
        )

    deep_briefing = _render(extra={"fast_classifier": fast_verdict})
    user_prompt = build_user_prompt(deep_briefing)
    # Deep tier may call read-only enrichment tools (e.g. lookup_ioc_history).
    # Gated inside complete_with_tools by settings.isoc_enable_llm_tools — when
    # off this is byte-identical to complete(). L2_SYSTEM = the report PLUS a
    # machine-readable AnalysisVerdict json block we parse below.
    tools = list(llm_tools.DEEP_TIER_TOOLS)
    dispatch = dict(llm_tools.DISPATCH)
    # Microsoft Defender read tools (hunt + machine/file/ip detail): merged in only
    # when enabled AND this customer has microsoft_defender creds. They still respect
    # isoc_enable_llm_tools via complete_with_tools' default gate.
    if settings.defender_tools_enabled:
        from ..adapters import integration_store

        def_creds = await integration_store.get_creds("microsoft_defender", incident.customer)
        if def_creds is not None:
            tools += llm_tools.DEFENDER_TOOLS
            dispatch = {**dispatch, **llm_tools.make_defender_handlers(def_creds)}
    result = await complete_with_tools(
        system=L2_SYSTEM,
        user=user_prompt,
        model=settings.isoc_model_deep,
        max_tokens=settings.deep_max_tokens,  # report + verdict block must fit (was 4096 -> truncated)
        tools=tools,
        dispatch=dispatch,
        on_tool_call=_make_tool_emitter(session, incident, "l2"),
    )
    session.add(
        _llm_call_row(
            incident_id=incident.id,
            purpose=("analyst_deep_forced" if force_deep else "analyst_deep"),
            result=result,
        )
    )

    if result.status != "ok":
        incident.status = CaseStatus.FAILED
        await _persona_stage_done(
            session,
            incident,
            "l2",
            l2_t0,
            display=f"L2 analysis {result.status}: {result.error}",
            level="error",
        )
        return

    incident.llm_report_markdown = result.text
    incident.llm_input_tokens = result.input_tokens
    incident.llm_output_tokens = result.output_tokens
    incident.llm_model_used = result.model
    analysis = contracts.parse_analysis_verdict(result.text) or contracts.AnalysisVerdict()
    stages["l2"] = analysis.model_dump()
    enrichment["stages"] = stages
    incident.enrichment = enrichment
    await _persona_stage_done(
        session,
        incident,
        "l2",
        l2_t0,
        display=f"L2 verdict: {analysis.verdict} / {analysis.confidence}",
        payload={"verdict": analysis.verdict, "confidence": analysis.confidence},
    )
    # Hallucination check: IOC-shaped strings in the report not in the briefing.
    await _check_hallucinations(session, incident, result.text, deep_briefing)

    # ── Threat hunt (routing.yaml: hunt_if) ─────────────────────────────
    hunt: contracts.HuntResult | None = None
    if agent_routing.should_hunt(analysis):
        h_t0 = await _persona_stage_start(session, incident, "hunt")
        hunt_res = await complete(
            system=HUNT_SYSTEM,
            user=build_hunt_prompt(
                deep_briefing,
                analysis.model_dump(),
                _hunt_iocs(enrichment),
                source_product=(incident.normalized or {}).get("source_product"),
            ),
            model=settings.isoc_model_deep,
        )
        session.add(_llm_call_row(incident_id=incident.id, purpose="analyst_hunt", result=hunt_res))
        if hunt_res.status == "ok":
            hunt = contracts.parse_into(contracts.HuntResult, hunt_res.text)
        if hunt:
            stages["hunt"] = hunt.model_dump()
            enrichment["stages"] = stages
            incident.enrichment = enrichment
        await _persona_stage_done(
            session,
            incident,
            "hunt",
            h_t0,
            display=f"Hunt: {hunt.spread_assessment if hunt else 'no result'}"
            f"{f' ({len(hunt.queries)} queries)' if hunt else ''}",
        )
    else:
        await _emit(
            session,
            incident,
            "hunt_skipped",
            display="Threat hunt not warranted",
            level="info",
            step="hunt",
        )

    # ── Forensics (routing.yaml: forensics_if_any) ──────────────────────
    if agent_routing.should_run_forensics(analysis, hunt):
        f_t0 = await _persona_stage_start(session, incident, "forensics")
        fz_res = await complete(
            system=FORENSIC_SYSTEM,
            user=build_forensic_prompt(
                deep_briefing, analysis.model_dump(), hunt.model_dump() if hunt else None
            ),
            model=settings.isoc_model_deep,
        )
        session.add(
            _llm_call_row(incident_id=incident.id, purpose="analyst_forensics", result=fz_res)
        )
        fz = (
            contracts.parse_into(contracts.ForensicResult, fz_res.text)
            if fz_res.status == "ok"
            else None
        )
        if fz:
            stages["forensics"] = fz.model_dump()
            enrichment["stages"] = stages
            incident.enrichment = enrichment
        await _persona_stage_done(
            session,
            incident,
            "forensics",
            f_t0,
            display=f"Forensics scope: {fz.scope if fz else 'no result'}",
        )
    else:
        await _emit(
            session,
            incident,
            "forensics_skipped",
            display="Forensics not warranted",
            level="info",
            step="forensics",
        )

    # ── Manager synthesis + human gate ──────────────────────────────────
    # The manager is deterministic: the L2 report is the analyst-grade summary;
    # the proposed verdict maps from L2; response actions are proposals only
    # (executed solely on approval). The incident parks at AWAITING_SIGNOFF —
    # the verdict stays PENDING until an analyst signs off at the gate.
    m_t0 = await _persona_stage_start(session, incident, "synthesis")
    proposed_verdict = agent_routing.map_verdict_to_isoc(analysis.verdict)
    proposed_actions = agent_routing.propose_response_actions(analysis, enrichment, normalized)
    enrichment["proposal"] = {
        "proposed_verdict": proposed_verdict,
        "confidence": analysis.confidence,
        "reasoning": analysis.reasoning,
        "hunt_focus": analysis.hunt_focus,
    }
    # Fused confidence/threat scores (deterministic; llm band is one input only).
    # Best-effort — a scoring bug must never break the gate (like guardrails below).
    try:
        enrichment["scores"] = scoring.compute_scores(
            scoring.build_bundle(
                enrichment,
                proposed_verdict=proposed_verdict,
                llm_band=analysis.confidence,
                severity=incident.severity,
                attack_chain_len=len(analysis.attack_chain or []),
                hunt_focus=analysis.hunt_focus,
                vendor_score=(incident.normalized or {}).get("vendor_score"),
            )
        ).as_payload()
    except Exception:
        logger.warning("scoring.compute_failed", incident_id=str(incident.id))
    enrichment["proposed_actions"] = [a.model_dump() for a in proposed_actions]
    # Autonomy guardrails (3.9): annotate each proposed action with an
    # auto/review/escalate RECOMMENDATION. Pure annotation — no execution, no
    # behavior change. Effect/containment kinds are hard-clamped to escalate.
    try:
        policy = await guardrails.load_policy(session, incident.tenant_id)
        enrichment["proposed_actions"] = guardrails.apply(
            enrichment["proposed_actions"], analysis.confidence, policy
        )
    except Exception:  # guardrails must never break synthesis
        pass
    # Always nudge the analyst to open a customer case at the gate so the customer
    # notification isn't forgotten. Appended AFTER guardrails so it keeps its fixed
    # autonomy='review' (pre-checked) regardless of confidence; created idempotently
    # only if approved. Never auto-runs.
    enrichment["proposed_actions"].append(
        agent_routing.create_case_action(len(enrichment["proposed_actions"])).model_dump()
    )
    incident.enrichment = enrichment
    conf = _map_confidence(analysis.confidence)
    if conf is not None:
        incident.confidence = conf
    incident.status = CaseStatus.AWAITING_SIGNOFF
    await _persona_stage_done(
        session,
        incident,
        "synthesis",
        m_t0,
        display=f"Proposed {proposed_verdict} — awaiting analyst sign-off",
        payload={"proposed_verdict": proposed_verdict, "action_count": len(proposed_actions)},
    )
    await _emit(
        session,
        incident,
        "awaiting_signoff",
        display=f"Gate: analyst sign-off required → propose {proposed_verdict}",
        level="warn",
        step="synthesis",
        payload={
            "proposed_verdict": proposed_verdict,
            "proposed_actions": enrichment["proposed_actions"],
        },
    )


# ── Persona-stage helpers ────────────────────────────────────────────────
async def _persona_stage_start(session, incident, label: str) -> float:
    nice = STAGE_LABELS.get(label, label)
    await _emit(
        session, incident, f"{label}_running", display=f"{nice}…", level="running", step=label
    )
    return time.monotonic()


async def _persona_stage_done(
    session,
    incident,
    label: str,
    t0: float,
    *,
    display: str | None = None,
    payload: dict | None = None,
    level: str = "ok",
) -> None:
    nice = STAGE_LABELS.get(label, label)
    dur = int((time.monotonic() - t0) * 1000)
    await _emit(
        session,
        incident,
        f"{label}_done",
        display=display or f"{nice} — done ({dur} ms)",
        level=level,
        step=label,
        duration_ms=dur,
        payload=payload,
    )


def _triage_result_from_fast(fast_verdict: dict, severity) -> dict:
    """Map the fast classifier's {verdict,confidence,reason} to an L1 TriageResult."""
    v = (fast_verdict.get("verdict") or "").upper()
    c = (fast_verdict.get("confidence") or "").upper()
    if v in ("FP", "BENIGN") and c == "HIGH":
        disp = "likely_fp"
    elif v == "TP":
        disp = "likely_tp"
    else:
        disp = "needs_analysis"
    return {
        "initial_severity": str(
            severity.value if hasattr(severity, "value") else severity or "medium"
        ),
        "obvious_disposition": disp,
        "enrichment_needed": [],
        "reasoning": fast_verdict.get("reason", ""),
    }


def _hunt_iocs(enrichment: dict) -> list[dict]:
    """Flatten triaged indicators for the hunt prompt (capped)."""
    out: list[dict] = []
    for r in enrichment.get("triage") or []:
        q = r.get("query") or {}
        val = q.get("ioc") if isinstance(q, dict) else q
        typ = (q.get("type") if isinstance(q, dict) else None) or r.get("type")
        if val:
            out.append({"type": typ, "value": val, "verdict": r.get("verdict")})
    return out[:25]


# ── Vision One workbench/OAT enrichment helpers (ADR-0005, read-only) ──────
_MAX_V1_INDICATORS = 30
_V1_CMD_TRUNC = 600
_RISK_ORDER = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _v1_alert_ref(incident: Incident) -> tuple[str | None, str | None]:
    """(workbench_id, region) for a visionone incident — from the normalized
    fields the parser carried, falling back to a regex over the raw payload."""
    n = incident.normalized or {}
    wb = n.get("v1_workbench_id")
    region = n.get("v1_region")
    if not wb:
        raw = (
            (incident.raw_payload or {}).get("text")
            or (incident.raw_payload or {}).get("raw")
            or ""
        )
        m = re.search(r"\bWB-\d+-\d{8}-\d+\b", raw)
        wb = m.group(0) if m else None
    return wb, region


async def _fetch_v1(incident: Incident, wb_id: str) -> dict:
    """Read-only V1 enrichment: workbench detail (always) + OAT (optional).

    Returns a capped dict for enrichment['v1']. Raises only on a total workbench
    failure — caught by the gather's return_exceptions, surfaced as a warn event.
    """
    from ..adapters import integration_store, v1_adapter

    creds = await integration_store.get_creds("vision_one", incident.customer)
    if creds is None:
        raise RuntimeError("Vision One not configured")
    region = creds.region

    detail = await v1_adapter.get_workbench_alert(wb_id, region=region, api_key=creds.api_key)
    out: dict[str, Any] = {
        "workbench_id": wb_id,
        "region": region,
        "console_host": (incident.normalized or {}).get("v1_console_host"),
        "workbench": _cap_workbench(detail),
    }

    # OAT is optional + best-effort — a failure must NOT lose the workbench detail.
    if settings.v1_oat_enabled:
        try:
            host = _v1_host(detail)
            start, end = _v1_oat_window(detail.get("createdDateTime"))
            rows = await v1_adapter.get_oat_detections(
                start=start,
                end=end,
                endpoint=host,
                region=region,
                api_key=creds.api_key,
                top=max(settings.v1_oat_max_items * 3, 50),
            )
            out["oat"] = _cap_oat(rows, host)
        except Exception as e:  # noqa: BLE001 — OAT must never sink the workbench detail
            logger.warning("pipeline.v1_oat_failed", incident_id=str(incident.id), error=str(e))
            out["oat_error"] = str(e)[:200]
    return out


def _cap_workbench(d: dict) -> dict:
    """Curate + bound the workbench alert before it's persisted/rendered."""
    if not isinstance(d, dict):
        return {}
    scope = d.get("impactScope") or {}
    entities = []
    for e in (scope.get("entities") or [])[:20]:
        ev = e.get("entityValue")
        if isinstance(ev, dict):  # host entity → {name, ips, guid}
            # Keep guid: it's the agentGuid used by response actions (collect_file
            # etc.) and is the identifier required on FedRAMP tenants.
            ev = {"name": ev.get("name"), "ips": ev.get("ips"), "guid": ev.get("guid")}
        entities.append({"type": e.get("entityType"), "value": ev})
    techniques: list[str] = []
    for r in d.get("matchedRules") or []:
        for f in r.get("matchedFilters") or []:
            techniques.extend(f.get("mitreTechniqueIds") or [])
    indicators = []
    for ind in (d.get("indicators") or [])[:_MAX_V1_INDICATORS]:
        val = ind.get("value")
        if isinstance(val, str) and len(val) > _V1_CMD_TRUNC:
            val = val[:_V1_CMD_TRUNC] + "…"
        indicators.append({"field": ind.get("field"), "type": ind.get("type"), "value": val})
    return {
        "id": d.get("id"),
        "model": d.get("model"),
        "score": d.get("score"),
        "severity": d.get("severity"),
        "status": d.get("status"),
        "investigationResult": d.get("investigationResult"),
        "description": d.get("description"),
        "createdDateTime": d.get("createdDateTime"),
        "incidentId": d.get("incidentId"),
        "impactScope": {
            "desktopCount": scope.get("desktopCount"),
            "serverCount": scope.get("serverCount"),
            "accountCount": scope.get("accountCount"),
            "entities": entities,
        },
        "mitreTechniqueIds": sorted(set(techniques)),
        "indicators": indicators,
    }


def _v1_host(d: dict) -> str | None:
    """Best endpoint host name from the workbench detail (for OAT scoping)."""
    for e in (d.get("impactScope") or {}).get("entities") or []:
        if e.get("entityType") == "host":
            ev = e.get("entityValue")
            if isinstance(ev, dict) and ev.get("name"):
                return ev["name"]
    for ind in d.get("indicators") or []:
        if ind.get("field") == "endpointHostName" and ind.get("value"):
            return ind["value"]
    return None


def _v1_oat_window(created_iso: str | None) -> tuple[str, str]:
    """RFC3339-Z (start, end) bracketing the alert time by ±v1_oat_window_hours."""
    from datetime import timedelta

    h = settings.v1_oat_window_hours
    base = None
    if created_iso:
        try:
            base = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
        except ValueError:
            base = None
    if base is None:
        base = datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = (base - timedelta(hours=h)).astimezone(timezone.utc).strftime(fmt)
    end = (base + timedelta(hours=h)).astimezone(timezone.utc).strftime(fmt)
    return start, end


def _cap_oat(rows: list, host: str | None) -> list:
    """Risk-floor filter + host guard + dedupe + cap the OAT detection stream."""
    floor = _RISK_ORDER.get((settings.v1_oat_risk_floor or "medium").lower(), 2)
    out: list[dict] = []
    seen: set = set()
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        detail = r.get("detail") or {}
        # Defense-in-depth: drop wrong-host rows even if the server filter slipped.
        if host and detail.get("endpointHostName") and detail["endpointHostName"] != host:
            continue
        for f in r.get("filters") or []:
            if _RISK_ORDER.get(str(f.get("riskLevel", "")).lower(), 0) < floor:
                continue
            key = (f.get("name"), tuple(sorted(f.get("mitreTechniqueIds") or [])))
            if key in seen:
                continue
            seen.add(key)
            highlighted = []
            for h in (f.get("highlightedObjects") or [])[:4]:
                v = h.get("value")
                if isinstance(v, str) and len(v) > 300:
                    v = v[:300] + "…"
                highlighted.append({"field": h.get("field"), "value": v})
            out.append(
                {
                    "name": f.get("name"),
                    "riskLevel": f.get("riskLevel"),
                    "mitreTacticIds": f.get("mitreTacticIds"),
                    "mitreTechniqueIds": f.get("mitreTechniqueIds"),
                    "detectedDateTime": r.get("detectedDateTime"),
                    "endpoint": detail.get("endpointHostName"),
                    "highlighted": highlighted,
                }
            )
            if len(out) >= settings.v1_oat_max_items:
                return out
    return out


def _map_confidence(c: str):
    from ..db.enums import Confidence

    return {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}.get(
        (c or "").lower()
    )


# ── LLM transcript persistence ──────────────────────────────────────────
def _llm_call_row(
    *,
    incident_id: uuid.UUID,
    purpose: str,
    result,  # llm.client.LLMResult — typed loosely to dodge circular import
) -> "LLMCall":  # noqa: F821 — LLMCall imported lazily below to dodge circular import
    """Build an LLMCall ORM row from a fresh LLMResult.

    The transcript fields (system_prompt / user_prompt / response_text /
    error) are populated only if `settings.log_llm_transcripts` is true. The
    settings flag is the single switch ops use to opt out of storing raw
    prompts for data-residency reasons.
    """
    from ..db.enums import LLMStatus
    from ..db.models import LLMCall
    from ..llm import pricing

    keep = bool(getattr(settings, "log_llm_transcripts", True))
    return LLMCall(
        incident_id=incident_id,
        purpose=purpose,
        model=result.model,
        provider=result.provider,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        # Imputed USD cost so the daily/incident budget guard is a cheap SUM and
        # the costs dashboard stops showing NULL. $0 for local/self-hosted models.
        cost_usd=pricing.impute_cost_usd(result.model, result.input_tokens, result.output_tokens),
        latency_ms=result.latency_ms,
        status=LLMStatus(result.status),
        prompt_hash=result.prompt_hash,
        created_at=datetime.now(timezone.utc),
        system_prompt=(result.system_prompt if keep else None),
        user_prompt=(result.user_prompt if keep else None),
        response_text=(result.text if keep else None),
        error=getattr(result, "error", None),
    )


# ── Short-circuit corroboration gate ────────────────────────────────────
def _short_circuit_block_reason(
    *,
    verdict_str: str,
    sensitive: dict | None,
    exact_match: dict | None,
    n_way: dict | None,
    autoclose_match: dict,
) -> str | None:
    """Return a human-readable blocker string when the fast tier's HIGH
    FP/benign verdict should NOT be honored, or None when it's safe to fire.

    Three independent gates — any one blocks:
      1. Sensitive rule pattern matched (admin login, lateral movement, etc.)
      2. No corroborating signal: exact_match, n_way, and autoclose are all
         empty or don't agree with the verdict
      3. (Implicitly handled by the gate above) — caller must already have
         checked that confidence == HIGH and verdict ∈ {FP, BENIGN}.
    """
    if sensitive and sensitive.get("matched"):
        return f"sensitive rule pattern (`{sensitive.get('keyword')}`)"

    verdict_lo = verdict_str.lower()

    # Strong corroboration #1: exact-match prior with the same verdict at high
    # cosine (exact_match["score"] is the TRUE cosine, not the RRF fusion score).
    em_verdict = (exact_match or {}).get("verdict", "").lower()
    em_score = (exact_match or {}).get("score") or 0
    if exact_match and em_score >= 0.9 and em_verdict == verdict_lo:
        return None

    # Strong corroboration #2: n_way majority matching this verdict.
    nway_verdict = (n_way or {}).get("verdict", "").lower()
    if n_way and nway_verdict == verdict_lo:
        try:
            agreed_str, total_str = (n_way.get("agreement") or "").split("/")
            if int(agreed_str) >= N_WAY_CORROBORATE_MIN:
                return None
        except (ValueError, AttributeError):
            pass

    # Strong corroboration #3: autoclose YAML hit (pre or post) for this verdict.
    for key in ("pre", "post"):
        ac = autoclose_match.get(key) if isinstance(autoclose_match, dict) else None
        if ac and (ac.get("verdict") or "").lower() == verdict_lo:
            return None

    return "no corroborating prior (exact_match / n_way / autoclose all absent or disagree)"


# ── Tier-1 classifier output parser ─────────────────────────────────────
def _parse_fast_classifier(text: str) -> dict:
    """Tolerant JSON extraction — strip code fences, find first {...} block."""
    import json
    import re

    s = (text or "").strip()
    # Drop markdown code fences if the fast model added them despite instructions.
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```\s*$", "", s)
    # Grab the first balanced-looking JSON object.
    m = re.search(r"\{[^{}]*\}", s, re.DOTALL)
    if m:
        s = m.group(0)
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return {"verdict": "?", "confidence": "?", "reason": "(fast classifier returned non-JSON)"}
    return {
        "verdict": str(obj.get("verdict") or "?").upper(),
        "confidence": str(obj.get("confidence") or "?").upper(),
        "reason": str(obj.get("reason") or "")[:300],
    }


# ── Hallucination check ────────────────────────────────────────────────
_IOC_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IOC_RE_HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_IOC_RE_URL = re.compile(r"https?://[^\s\"'<>`)\]]+")
# Domain regex deliberately conservative — doesn't match every TLD, just the
# common ones we'd actually see in an alert.
_IOC_RE_DOM = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|us|uk|de|tr|ru|cn|info|xyz|top|biz|me|app|dev|local|onion)\b"
)


def _extract_iocs_from_text(text: str) -> set[str]:
    out: set[str] = set()
    if not text:
        return out
    out.update(_IOC_RE_IP.findall(text))
    out.update(_IOC_RE_HASH.findall(text))
    out.update(_IOC_RE_URL.findall(text))
    out.update(m.lower() for m in _IOC_RE_DOM.findall(text))
    return out


async def _check_hallucinations(
    session: AsyncSession,
    incident: Incident,
    report_text: str,
    briefing_text: str,
) -> None:
    """Compare IOCs mentioned in the LLM report against IOCs in the briefing.
    Anything net-new is flagged on the timeline — analyst decides if it's a
    smart inference or a hallucination."""
    report_iocs = _extract_iocs_from_text(report_text)
    briefing_iocs = _extract_iocs_from_text(briefing_text)
    # Normalise case for fair set diff.
    report_norm = {x.lower() for x in report_iocs}
    briefing_norm = {x.lower() for x in briefing_iocs}
    # Decoded-payload IOCs are legitimate even if a briefing snippet truncated
    # them — they were deterministically extracted from a decoded blob, not
    # invented. Add them to the allowed set so the report isn't penalised for
    # correctly citing a C2 it found inside an encoded payload.
    deob = (incident.enrichment or {}).get("deobfuscation") or {}
    for d in deob.get("decoded_iocs") or []:
        v = d.get("value")
        if v:
            briefing_norm.add(v.lower())
    novel = sorted(report_norm - briefing_norm)
    if not novel:
        return
    enrichment = incident.enrichment or {}
    enrichment["llm_novel_iocs"] = novel[:30]
    incident.enrichment = enrichment
    await _emit(
        session,
        incident,
        "llm_hallucination",
        display=f"LLM report mentioned {len(novel)} IOC(s) not in briefing",
        payload={"count": len(novel), "values": novel[:15]},
    )
    logger.warning(
        "pipeline.llm_hallucination",
        incident_id=str(incident.id),
        count=len(novel),
        values=novel[:15],
    )


# ── helpers ─────────────────────────────────────────────────────────────
def _alert_fields(normalized: dict) -> dict:
    """Project the normalized alert into the field-name shape auto_close expects.

    auto_close.py does `.upper() / .lower()` directly on these values, so we
    coalesce string fields to "" rather than passing None.
    """

    def _s(k: str) -> str:
        v = normalized.get(k)
        return v if isinstance(v, str) else ""

    return {
        "customer": _s("customer"),
        "rule_name": _s("rule_name"),
        "src_ip": _s("src_ip"),
        "dst_ip": _s("dst_ip"),
        "application": _s("application"),
        "url_category": _s("url_category"),
        "src_zone": _s("src_zone"),
        "dst_zone": _s("dst_zone"),
        "dst_port": normalized.get("dst_port"),
    }


def _int(v: Any) -> int:
    try:
        if isinstance(v, str):
            return int(v.rstrip("%"))
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


async def _empty_list() -> list:
    return []


# Severity ladder for the threat-intel "soft signal" bump. Caps at CRITICAL.
_SEVERITY_LADDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _bump_severity(current: Severity | None) -> Severity:
    if not current:
        return Severity.MEDIUM  # unscored → medium baseline
    try:
        idx = _SEVERITY_LADDER.index(current)
    except ValueError:
        return Severity.MEDIUM
    return _SEVERITY_LADDER[min(idx + 1, len(_SEVERITY_LADDER) - 1)]


_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


async def _apply_threat_intel_signal(
    session: AsyncSession,
    incident: Incident,
    matches: list[dict],
) -> None:
    """Graded signal off the local threat DB. Every match still escalates
    severity one notch (a known-bad IOC is always worth a closer look — no
    regression), but the *confidence* is now scored by corroboration + recency
    + match kind rather than blanket-HIGH:
      * high band  → confidence HIGH
      * medium band→ confidence ≥ MEDIUM
      * low band   → severity bumped, confidence left as-is (a lone, stale,
                     parent-domain hit shouldn't masquerade as high confidence).
    Never lowers an already-higher confidence. The scored matches + the rolled-up
    score are stashed in enrichment for the LLM and the UI."""
    before_sev = incident.severity
    before_conf = incident.confidence

    summary = ti_scoring.summarize(matches, now=datetime.now(timezone.utc))
    band = summary["band"]

    incident.severity = _bump_severity(incident.severity)
    target_conf = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM}.get(band)
    if (
        target_conf is not None
        and _CONFIDENCE_RANK.get(incident.confidence, -1) < _CONFIDENCE_RANK[target_conf]
    ):
        incident.confidence = target_conf

    enrichment = incident.enrichment or {}
    enrichment["threat_intel_matches"] = summary["matches"]
    enrichment["threat_intel_score"] = {
        k: summary[k] for k in ("score", "band", "match_count", "exact_matches", "distinct_sources")
    }
    incident.enrichment = enrichment

    await _emit(
        session,
        incident,
        "threat_intel_match",
        display=(
            f"{len(matches)} IOC(s) match local threat DB "
            f"({band} confidence, {summary['distinct_sources']} feed(s)) "
            f"→ severity {before_sev or '—'} → {incident.severity}"
        ),
        payload={
            "count": len(matches),
            "score": summary["score"],
            "band": band,
            "distinct_sources": summary["distinct_sources"],
            "exact_matches": summary["exact_matches"],
            "before": {
                "severity": str(before_sev) if before_sev else None,
                "confidence": str(before_conf) if before_conf else None,
            },
            "after": {"severity": str(incident.severity), "confidence": str(incident.confidence)},
            "values": [m["value"] for m in summary["matches"][:10]],  # cap payload
        },
    )
