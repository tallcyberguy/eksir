# ISOC Investigation Pipeline

This is the deterministic state machine the backend runs for every alert.
The LLM is reached **only at step 6**, and only if step 5's decision gate
returns `inconclusive`. Step 6 is no longer a flat "two-tier" call — it is the
**agent-persona pipeline** (L1 → L2 → hunt? → forensics? → manager), and step 7
is now an explicit **human sign-off gate** (`awaiting_signoff`). The ASCII
diagram below shows the **seven deterministic code steps** accurately (parse,
auto-close, dedup, enrich, entity resolution, correlation, decision; the last
three are `_step_entities`/`_step_correlate`/`_step_decision` in
`orchestrator.py`); steps 6–8 are detailed in "Agent personas & human gate"
below.

> **Diagram:** see `docs/rag-pipeline-sequence.png` for the full sequence,
> including the RAG retrieval and feedback-loop touch-points.
> **Default LLM:** the shipped config routes both tiers to **Claude** via LiteLLM
> (`isoc-deep` → `claude-sonnet-4-5`, `isoc-fast` → `claude-haiku-4-5`; see
> `config/litellm.config.yaml`). A local model (Seneca 8B via Ollama) or vLLM are
> optional swap-ins behind the same routing (see ADR-0002).

```
┌───────────────────────────────────────────────────────────────────────┐
│ INPUT: raw alert (paste / webhook JSON / file upload / email body)    │
└──────────────────────────────┬────────────────────────────────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 1. INGEST (parse)            │   adapters/parser_adapter.py  NO LLM
                │   parse_to_normalized()      │   (parsers + normalizer are
                │   → NormalizedAlert          │    vendored: vendor/alert-memory-mcp/)
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 2. AUTO-CLOSE (pre-enrich)   │   adapters/autoclose_adapter.py
                │   YAML rule match            │   NO LLM
                │   → matched_rule | None      │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 3. DEDUP: EXACT + N-WAY      │   adapters/store_adapter.py
                │   store.find_exact_match()   │   NO LLM
                │   store.n_way_agreement()    │
                │   store.search_similar(top5) │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 4. PARALLEL ENRICHMENT       │   orchestrator._step_enrich
                │   ├ triage.py (TI lookup)    │   NO LLM
                │   ├ ipinfo / rDNS            │
                │   ├ KB search (kb_v2)        │
                │   └ Auto-close post-enrich   │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 4b. ENTITY RESOLUTION (OCSF) │   pipeline/ocsf.py
                │   ocsf.to_entities()         │   adapters/entity_store.py
                │   → upsert device/user/ip/   │   NO LLM
                │     file/observable entities │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 4c. CORRELATION              │   adapters/cluster_store.py
                │   cluster_store.correlate_   │   opt-in: correlation_enabled
                │     incident() groups by     │   NO LLM
                │     shared strong entity     │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ 5. DECISION GATE             │   pipeline/decision.py
                │                              │   NO LLM
                │   if (exact_match.score≥0.9  │
                │       AND human_verified)    │
                │       → suggest verdict      │
                │                              │
                │   elif (n_way ≥4/5 agree)    │
                │       → suggest verdict      │
                │                              │
                │   elif (auto_close fired     │
                │       AND ti_clean)          │
                │       → suggest verdict      │
                │                              │
                │   else → inconclusive ──────┐│
                └──────────────┬─────────────┐ ││
                               │ confident   │ ││ inconclusive
                               ▼             │ ▼▼
                  ┌────────────────────┐  ┌──────────────────────────┐
                  │ 5b. STUB REPORT    │  │ 6. LLM SYNTHESIS          │
                  │   render markdown  │  │   render markdown brief   │
                  │   from templates   │  │   send to litellm/isoc-deep│
                  │   NO LLM           │  │   parse response          │
                  └──────────┬─────────┘  │   1 LLM CALL              │
                             │            └──────────┬───────────────┘
                             └──────────────────────►│
                                                     ▼
                                  ┌──────────────────────────────┐
                                  │ 7. ANALYST REVIEW (UI)       │
                                  │   shown in incident detail   │
                                  │   tabs. Analyst approves /    │
                                  │   edits / overrides verdict.  │
                                  │   NO LLM                      │
                                  └──────────────┬───────────────┘
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │ 8. INDEX                     │
                                  │   store.index_alert(         │
                                  │     human_verified=True,     │
                                  │     source='isoc',           │
                                  │     feedback_source=         │
                                  │       'analyst_decision'     │
                                  │   )                          │
                                  │   NO LLM                     │
                                  └──────────────────────────────┘
```

## Agent personas & human gate (steps 6–8, current implementation)

When step 5 returns `inconclusive`, `_step_synthesis` runs the agent personas.
Deterministic-first still holds — enrichment is code; the LLM runs only here.
Each persona stage emits `<step>_running`/`_done` timeline events (and
`<step>_skipped` when routing skips it), which drive the UI progress rail.

1. **L1** (`FAST_CLASSIFIER_SYSTEM`) — fast triage, recorded as a `TriageResult`.
   A HIGH obvious FP/benign still short-circuits — code-enforced corroboration
   (`exact_match ≥0.9`, `n_way ≥3/5`, or an auto-close hit; sensitive rules never
   short-circuit) → `decided_short_circuit` → auto-closed with **no gate**.
2. **L2** (`L2_SYSTEM`, via `complete_with_tools`) — full markdown SOC report
   **plus** a fenced `AnalysisVerdict` JSON block (verdict / confidence / MITRE /
   hunt_recommended / hunt_focus). May call read-only tools — `lookup_ioc_history`
   always, and (behind `DEFENDER_TOOLS_ENABLED` + a `microsoft_defender` connector
   row for the customer) the live Defender read tools `defender_get_machine` /
   `file_stats` / `ip_stats` / `run_hunt`. Followed by the hallucination check
   (report IOCs ⊆ briefing).
3. **Threat hunt** (`HUNT_SYSTEM`) — only if L2 = true_positive and hunt_recommended.
   Builds S1QL/Sigma/KQL queries + a reasoned spread assessment. **The automatic hunt
   does not execute**; the analyst-triggered manager-chat re-task CAN run live queries
   (Trend Vision One activity search / Defender `runHuntingQuery`), gated + read-only.
4. **Forensics** (`FORENSIC_SYSTEM`) — only if L2 = inconclusive OR the hunt found
   lateral spread. Timeline + root cause from the data on hand. **Reasoning only.**
   (Distinct from the static-file forensics subsystem in `routes/forensics.py`.)
5. **Manager** — deterministic (no LLM): maps the verdict to TP/FP/benign, builds
   `enrichment.proposal` + **provider-aware `proposed_actions`** (routed by the
   incident's EDR — V1 blocklist/isolate/collect, or Defender `isolate_host` /
   `scan_endpoint` / `blocklist_ioc` / `disable_user`, each tagged with `provider`),
   computes the fused
   **confidence/threat scores** (`pipeline/scoring.py` → `enrichment['scores']`;
   best-effort, wrapped so a scoring bug can never break the gate), and parks the
   case at `awaiting_signoff`. Verdict stays `pending`.

**Case scores** (`pipeline/scoring.py`) — two orthogonal 0-100 numbers fused
deterministically from the retrieval/TI signals the pipeline already computed:
`confidence` (certainty of the verdict, any verdict) and `threat` (EFFECTIVE =
inherent impact × P(malicious), so a confident FP sinks toward 0). The
`AnalysisVerdict` band is one input, treated as a **prior capped at 0.75** — hard
corroboration (exact-match cosine, n-way agreement, IOC history) adds on top with
contradiction penalties and caps that mirror the fast-classifier prompt rules.
Also computed on the **short-circuit path** (`decision.evaluate` gate), so
auto-closed cases carry scores too. Each contributing term is recorded under
`contributions` for the "why this score" UI. Displayed as chips on the incidents
list and tiles in the detail Sidecar.

Routing thresholds (`escalate_to_l2` / `hunt_if` / `forensics_if`) live in
`pipeline/agent_routing.py` (ported from agentic-soc `routing.yaml`); the typed
stage contracts live in `pipeline/contracts.py`. Personas share the **same
markdown briefing** (`briefing.py`); only the system prompt and output shape
differ. With LiteLLM routing the deep tier maps to `isoc-deep`. See ADR-0002.

### Human gate (step 7)

The case sits at `awaiting_signoff` until an analyst acts (`routes/cases.py`):

- `POST /incidents/{id}/approve` — commits the verdict (→ Qdrant index +
  FP/benign auto-tune, step 8), executes only the analyst-checked `proposed_actions`
  — dispatched by `action.provider` to `v1_adapter` or `defender_adapter`, resolving
  that customer's creds — and mirrors the verdict back to the source alert
  (`mirror_verdict_to_v1` / `mirror_verdict_to_defender`, gated + fail-soft).
- `POST /incidents/{id}/reject` — clears the proposal; `requeue=true` re-runs
  synthesis (`pipeline_synthesize_only`), else drops to `awaiting_review`.
- `POST /incidents/{id}/manager` — converse with the Incident Manager
  (`pipeline/manager_chat.py`): its tools revise the proposed verdict/actions (the
  `propose_actions` tool offers the incident's EDR action vocabulary and stamps
  `provider` from the incident) and re-task the hunt/forensic personas — including a
  live Defender/V1 hunt execution — with the analyst's directive.

**Invariant:** personas + manager only *propose*; Approve is the only thing that
commits a verdict or fires a response action. Every action resolves credentials by
`(provider, incident.customer)` — with `STRICT_TENANT_CREDS` an unmapped customer
fails closed rather than borrowing a shared/`default` key.

## Token budget per investigation

| Path | LLM calls | Approx. tokens |
|---|---|---|
| Exact-match short-circuit | 0 | ~0 |
| N-way agreement short-circuit | 0 | ~0 |
| Auto-close + clean TI | 0 | ~0 |
| L1 only (short-circuit FP/benign) | 1 | briefing in / ~50 out |
| L1 + L2 (most escalations) | 2 | ~3-8K in / ~1-2K out |
| L1 + L2 + hunt (+ forensics) on a TP | 3-4 | +~1-2K out per persona |

Compared to the original SKILL.md loop (~15-30K tokens/investigation), this is
roughly **70-90 % cheaper** per alert — and ~0 API cost on the local Seneca path.

## State machine in Postgres

```sql
CREATE TYPE case_status AS ENUM (
    'received', 'parsed', 'auto_closed_candidate', 'enriching',
    'decided_short_circuit', 'awaiting_synthesis', 'synthesized',
    'awaiting_review', 'awaiting_signoff', 'closed', 'failed'
);
-- 'awaiting_signoff' = parked at the human gate with a manager proposal;
-- the analyst approves/rejects/chats before the verdict is committed.
```

Each step writes a `timeline_event` row, giving an audit trail identical to
the Actions tab in the UI.

## Failure handling

- Any ARQ task retry is bounded (max 3 attempts, exponential backoff).
- A parser failure routes to an "edit raw" UI panel — the analyst can
  hand-fix fields and resume.
- An LLM timeout flips the case to `synthesis_pending_retry` and emits a
  toast notification.
