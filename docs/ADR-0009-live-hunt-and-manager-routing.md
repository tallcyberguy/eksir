# ADR 0009: Pre-gate live hunt, expanded read tools & manager-owned hunt routing

**Date:** 2026-07-24
**Status:** **Proposed (design only, not implemented).** Awaiting review before any code.
**Amended 2026-07-24** (competitor gap analysis, Amendment 1): D3 split by data locality, plus new
decisions D7 to D9 (reputation reads, richer identity, out-of-band confirmation).
**Amended again 2026-07-24** (autonomy pivot, Amendment 2): reputation/endpoint/identity move from
model-choice L2 tools to deterministic pre-L2 enrichment; the hunt is fully operator-gated (the
manager-owned hunt decision D5 / decide_hunt is dropped, D6 removed).
**Amends:** ADR-0007 decision #2 ("Live-query execution point = **Gate-only**"). This ADR is the
realization of ADR-0007's own *"Revisit when: gate-only proves too restrictive (analysts want
auto-hunt with live queries) → promote read-only queries into the hunt persona behind a separate
budget guard."*
**Builds on:** ADR-0007 (multi-tenant EDR creds + read tools + the analyst-gate invariant),
ADR-0005 (V1 read-only enrichment), ADR-0006 (connector framework).
**Relates to:** `docs/PIPELINE.md` (agent-persona synthesis + human gate), `pipeline/orchestrator.py`
(`_step_synthesis`), `pipeline/synthesis_steps.py`, `pipeline/agent_routing.py`, `llm/tools.py`,
`adapters/defender_adapter.py`, `adapters/v1_adapter.py`.

## Amendment 2026-07-24 (competitor gap analysis)

A competitor alert analysis (Exaforce, a CrowdStrike Intelligence-indicator FP) was compared against
this ADR via a multi-agent research + adversarial-verify pass. The Microsoft surface here had four
high-severity holes. New/revised decisions (granular build steps in
[BUILD-PLAN-ADR-0009.md](BUILD-PLAN-ADR-0009.md)):

- **D3 revised (split by data locality).** TELEMETRY reads (`run_hunt`, `get_endpoint`, `file_stats`,
  `ip_stats`) stay provider-routed by `(provider, customer)` because that data lives in the EDR.
  IDENTITY reads become **tenant-keyed** (Entra/Graph creds resolved by `customer`) and are callable
  for **any** incident regardless of `source_product`. A CrowdStrike, Vision One, or email alert
  about a user gets the same Entra enrichment (the exact competitor scenario), resolved by per-tenant
  multi-tenant-app creds + admin consent.
- **D7 reputation reads (the competitor's FP hinge, absent today).** `get_domain_stats`
  (`Url.Read.All`, held per the app-reg screenshot: MDE `/api/domains/{domain}/stats`), `get_file_info`
  (`File.Read.All`, held: MDE `/api/files/{id}` determination + signer/cert), and a tenant custom-IOC
  allow/block check (`Ti.ReadWrite`, held: `/api/indicators`). Near-zero new consent. Optional tier-2
  is licensed MDTI `hostReputation` for the literal global verdict.
- **D8 richer `get_user`.** Pin an explicit `$select` (`accountEnabled`, `department`, `jobTitle`,
  `onPremisesSecurityIdentifier` = the Windows SID); add `$expand=manager`; add `riskDetections`
  (why the user is risky); add `userRegistrationDetails` (the MFA factor-enrollment count, the
  "6-9 factors" signal). Blind spot to document: Graph `/auditLogs/signIns` v1.0 is interactive-only,
  so non-interactive sign-ins need `/beta` + a `signInEventTypes` filter.
- **D9 out-of-band dual confirmation** as a gated `request_confirmation` proposed action (email-first
  via the existing `graph_mail_adapter` + `Mail.Send` scoped to one SOC mailbox; manager from the D8
  expand). The persona only proposes; `routes/cases.py` dispatches only on the analyst-checked id
  (sending is an outbound WRITE); the reply is out-of-band EVIDENCE surfaced to the analyst, never an
  auto-commit. Two gates preserved.

**Scope deltas:** `AuditLog.Read.All` unlocks BOTH sign-ins AND the MFA registration report (one
consent, two capabilities); `IdentityRiskEvent.Read.All` (new) for `riskDetections`; `Mail.Send`
(new, one mailbox) for D9. `Url.Read.All` / `File.Read.All` / `Ti.ReadWrite` (D7) are already held.

## Amendment 2, 2026-07-24 (autonomy pivot: pre-enrichment over model-choice tools)

Follow-up decision. To avoid a second LLM round-trip per read and make the pipeline more autonomous,
the bounded point-lookups move from **model-choice L2 tools** to **deterministic pre-L2 enrichment**,
and live threat hunting stays **operator-gated**. This supersedes the DELIVERY MECHANICS of D1, D2,
D6, D7, D8 (the Microsoft APIs/scopes/capabilities they name are unchanged; only HOW they reach L2
changes). Build detail in [BUILD-PLAN-ADR-0009.md](BUILD-PLAN-ADR-0009.md).

- **D1 reversed.** No auto-executed live hunt (the old PR-4 is dropped). The open-ended
  threat-hunting APIs (Defender advanced-hunting KQL, V1 endpoint-activity search) run ONLY when the
  operator triggers them via the conversational manager at the gate (`manager_chat._run_hunt`,
  unchanged). The pipeline hunt persona stays query-building only.
- **D2 reversed.** Reputation (file/hash/domain/IP), endpoint detail, and identity are fetched
  deterministically in code BEFORE the L2 call and injected into the briefing, not exposed as L2
  tools. One richer prompt instead of repeated tool round-trips. L2's auto tool set shrinks to
  `lookup_ioc_history`; its live Defender tools are removed.
- **D6 removed.** With everything pre-fetched into `enrichment`, the manager's `decide_hunt` reads
  asset criticality + user risk directly. The read-cache / targeted-manager-read machinery is gone.
- **D7/D8 become enrichment, not tools.** Same Microsoft APIs (domain/file stats + file info +
  custom-IOC; Graph identity), same scopes, now called by a deterministic enrichment step. Trend
  Micro `get_endpoint_details` (resolved from the endpoint name) is pre-fetched the same way.
- **Scope: escalated-only.** The pre-enrichment runs just before L2 (after the L1 short-circuit), so
  alerts that auto-close never hit the Microsoft/Graph APIs (throttling + cost). By design it does
  NOT feed the deterministic auto-close gate.
- **Identity: full.** Profile + Entra risk + `riskDetections` + MFA registration + manager + a
  bounded sign-in slice, all pre-fetched, cross-provider (any incident with a user + Entra creds).
- **Latency/context:** the enrichment calls run concurrently (`asyncio.gather`), fail-soft (never
  block L2), and each slice stays compact so the briefing does not bloat.

**Hunt fully operator-gated (D5 reversed).** The manager does NOT own a hunt decision; `decide_hunt`
is dropped. L2's `hunt_recommended` gates the existing query-building hunt persona (`should_hunt`,
unchanged), and the operator runs the live hunt APIs at the gate via the conversational manager. The
pre-enriched criticality/risk still inform L2's reasoning, just not an automated hunt gate.

## Context

Three gaps in the current Defender + Vision One synthesis path motivated this ADR. They surfaced
while optimizing the workbench for the two live providers:

1. **The auto-hunt persona writes homework, it doesn't answer the question.** When a hunt is
   warranted (`agent_routing.should_hunt` → `run_hunt`), the automated path runs `complete()` with
   **no tools**, it *builds* queries but never *runs* them. Live execution exists only when an
   analyst re-tasks a hunt at the gate (`manager_chat._run_hunt`, `gated=False`). So the analyst
   reaches sign-off seeing "here is a KQL to check for spread" instead of "already confirmed on 3
   other hosts." (ADR-0007 decision #2 confined live queries to the gate for token-cost reasons.)

2. **L2's live read surface is asymmetric and incomplete.** Defender exposes four read tools to L2
   (`defender_run_hunt` / `get_machine` / `file_stats` / `ip_stats`); Vision One exposes **none**
   (its Workbench/OAT data is *passive* pre-fetched context in the briefing, not model-callable).
   Neither provider exposes a **user/identity read**, though both can *write* `disable_user`. For
   identity alerts (impossible travel, risky sign-in, MFA fatigue) L2 analyzes the user blind.

3. **The hunt decision belongs to the wrong actor.** Today `should_hunt(l2)` is `verdict ==
   true_positive AND l2.hunt_recommended`, pure code reading a boolean the L2 model set. The model
   both analyzes *and* decides its own next step, and asset criticality never enters the decision.
   The product intent is that the **incident manager** decides whether the hunter is tasked, from
   L2's evidence **plus** asset criticality and IOC verdicts.

This ADR closes all three **without touching the core invariant**: personas + the manager only
*propose*; the analyst's Approve in `routes/cases.py` is the only thing that writes a verdict or
fires a response action. The change here is entirely on the **read** side.

## The load-bearing principle: read is not one thing

Letting reads run before the gate forces a distinction ADR-0007 didn't need to make. "Read-only
tool" splits into two classes with opposite treatments:

| | **Deterministic read** | **Agentic (exploratory) read** |
|---|---|---|
| Examples | endpoint criticality, user risk for the impacted device/user | `run_hunt`, follow-the-thread pivots |
| Runs | when a decision depends on it (manager routing) | only if the model chooses to call it |
| Cost shape | one cheap object GET, cacheable | model iterates; needs a budget |
| Guardrail | none (fixed call) | query linter + call budget + timeout |

**Decision D0, the read/write split is formalized, replacing "gate-only live tools."**
Pre-gate, **any read may run** (deterministic or agentic); **every write stays gate-only and
analyst-approved.** A hunt reads telemetry; it does not commit a verdict or fire containment, so
auto-executing it pre-gate does **not** breach the ADR-0007 invariant, which governs *writes*
(verdicts + response actions). This reframing is what makes the rest safe.

## Decisions

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D0 | Live-execution boundary | **Read/write split** (amends ADR-0007 #2): reads may run pre-gate; writes stay gate-only | A read cannot violate the write-gate invariant. |
| D1 | Auto-hunt execution | **Bounded live, tiered.** Warranted hunts execute read-only when the tier says urgent; otherwise stay query-only | Real spread evidence at the gate for the cases that matter; latency/cost bounded elsewhere. |
| D2 | L2 read architecture | **Tools only.** Endpoint/user/file/IP reads are model-choice tools at L2 (not blanket pre-fetch) | Keeps L2 agentic; avoids paying reads on every escalated alert. |
| D3 | Provider symmetry | **One provider-agnostic read interface**; Defender + V1 handlers resolved by `(provider, incident.customer)` | The next connector inherits the surface for free (ADR-0006). |
| D4 | User/identity read | **Full user-read** (profile + `accountEnabled` + risky-user state + sign-in timeline), per-scope graceful degradation | Highest analytical lift; identity alerts are where endpoint telemetry is useless. |
| D5 | Hunt decision owner | **Manager owns it fully.** L2's `hunt_recommended`/`hunt_focus` become *advisory inputs*; a deterministic manager routing step decides run/live/focus from L2 + asset criticality + IOC verdicts | "LLMs decide verdicts, CODE decides flow" (`agent_routing.py`). The model can no longer veto a hunt on a confirmed critical. |
| D6 | Manager's decision inputs | The manager **deterministically reads** the specific signals its decision needs (endpoint criticality, user risk), reusing a per-incident read cache so L2's tool calls aren't duplicated | Reconciles D2 (tools-only) with D5 (manager needs criticality): see the tension below. |

## The D2 ↔ D5 tension, and how D6 resolves it

D5 says the manager decides the hunt using **asset criticality + user risk**. D2 says those reads
are **model-discretionary tools**, so L2 might never call them, and the manager would decide blind.
These conflict.

**Resolution (D6):** L2's reads stay model-choice tools (D2 holds), **but** the manager's routing
step, at the moment it decides, performs a *targeted deterministic read* of exactly the signals it
needs, `get_machine` for the impacted device(s), the user-read for the impacted user(s), and
nothing else. A per-incident **read cache** (`enrichment["reads"]`, keyed by `(tool, arg)`,
write-through from both the L2 tool dispatch and the manager's direct reads) guarantees each live
object is fetched at most once. Net effect: "tools only" is true for L2's *exploration*; the
manager's *decision inputs* are guaranteed without a blanket pre-fetch on every alert.

> **Reviewer check:** this is the sharpest design call in the ADR. The alternative is to demote D2 to
> "pre-fetch endpoint+user for L2-bound alerts" (deterministic, simpler, but pays the read on every
> escalation). D6 was chosen to honor the tools-only decision; flag on review if you'd rather pay the
> pre-fetch and delete the cache machinery.

## Design

### 1. Manager-owned hunt routing (D5, D6)

Split the manager's role into two deterministic touchpoints (both code, no new LLM hop):

- **Manager routing decision** (new, *before* the hunt): `agent_routing.decide_hunt(l2, enrichment,
  asset, user) -> HuntDecision{run: bool, live: bool, focus: str｜None, reason: str}`. Replaces the
  current one-line `should_hunt`. L2's `hunt_recommended`/`hunt_focus` are inputs, not the verdict.
- **Manager finalization** (existing `synthesis_steps.run_manager` / `_step_synthesis` tail):
  unchanged, builds `enrichment["proposal"]` + `proposed_actions`, parks at `AWAITING_SIGNOFF`.

`AnalysisVerdict.hunt_recommended` / `hunt_focus` (`contracts.py`) stay in the contract as advisory;
no contract break. `decide_hunt` logic (initial proposal, tune on review):

```
run  = l2.verdict == "true_positive" AND (
          l2.hunt_recommended                       # L2's opinion (advisory)
          OR any_malicious_ioc(enrichment)          # hard corroboration
          OR asset.criticality == "high"            # crown-jewel host
          OR threat_category in ESCALATE_… )         # ransomware/c2/lateral/…
live = run AND (
          severity in {high, critical}
          OR focus in {lateral_movement, persistence, c2}
          OR any_malicious_ioc(enrichment)
          OR asset.criticality == "high" )
# else: run==True, live==False → query-only (build the query, don't execute)
```

### 2. Bounded live auto-hunt (D1) + guardrails

When `HuntDecision.live`, the auto-hunt persona is handed the live read tool for the incident's
provider, `defender_run_hunt` (Graph `runHuntingQuery`) and/or V1 `get_endpoint_activity`, via
`complete_with_tools(..., gated=False)`, reusing the exact creds-bound handlers `manager_chat`
already builds (`make_defender_handlers`, `make_endpoint_activity_handler`). Results feed
`scoring.py` (spread confirmed → effective-threat score up) and the downloadable evidence log.

**A new query guard** (`pipeline/hunt_guard.py`) validates model-written queries in the handler
*before* the adapter call; on reject it returns `{"error": ...}` so the model self-corrects within
its budget (guardrail, not hard fail):

- **Defender KQL:** first operator must be an allowlisted hunting table (`Device*`; later
  `Identity*`/`Email*`); inject a `Timestamp >=` window if absent; require/inject `| limit <= cap`;
  reject `externaldata`, `evaluate`, `.show`, cross-cluster `cluster(...)`, unbounded `union *`.
- **V1 TMV1-Query:** a `field:value` filter DSL, inherently safer, enforce `top <= cap`, inject the
  alert time-window, keep `max_records` (already 200). *(V1 is the lower-risk surface to enable
  first.)*
- **Budget:** max *N* tool calls per hunt stage (a first hunt often returns nothing and needs a
  refine, allow ~3-5, not 1); per-call row cap (already 50); a total stage wall-clock timeout. On
  timeout: keep partial results, emit a `hunt_truncated` timeline event, fall through to the gate. A
  slow hunt must never wedge the synthesis path the analyst watches on the rail.

### 3. Expanded, symmetric read tools (D2, D3, D4)

A provider-agnostic tool surface, one schema each, handler resolved by provider:

| Tool | Defender (status) | Vision One (status) |
|---|---|---|
| `run_hunt` | `run_hunting_query`, **exists** | `get_endpoint_activity`, **exists** |
| `get_endpoint` | `get_machine` (risk/exposure/criticality), **exists** | **net-new**, no `get_machine`-equivalent wired (Endpoint Inventory API) |
| `get_user` | **net-new**, see below | **net-new**, account-activity / Workbench user entity |
| `file_stats` | `get_file_stats`, **exists** | (V1 has no direct equivalent; skip) |
| `ip_stats` | `get_ip_stats`, **exists** | (skip) |

**`get_user` (Defender/Graph), read-only, GET-only handler:**
- `GET /users/{id}` → profile + `accountEnabled` (scope `User.Read.All`; your app has
  `User.ReadWrite.All`).
- `GET /identityProtection/riskyUsers/{id}` → risk level/state (`IdentityRiskyUser.Read.All`,
  granted).
- `GET /auditLogs/signIns?$filter=userId eq …` → **last N sign-ins inside the alert window** only
  (locations/IPs/MFA results) (`AuditLog.Read.All`, **not yet granted; requires per-tenant admin
  consent**, see Prerequisites).
- **GET-only, physically.** The app holds `User.ReadWrite.All`; the read handler must call only the
  GET adapter functions and must **never** share a code path with `set_user_enabled`, so a
  prompt-injected model cannot PATCH a user through a "read" tool.
- **Per-scope graceful degradation.** In the MSSP fleet each customer's app registration may lack a
  scope, if `riskyUsers` or `signIns` 403s, drop that field and return what resolved (mirrors
  `manager_chat._hunt_live_state`'s honest reporting).

**V1 symmetry is not free:** `get_endpoint` and `get_user` for V1 are net-new adapter functions
(V1 Endpoint Inventory + account-activity APIs) needing API research, not just tool wiring. Enable
Defender's `get_user` first (surface already permissioned bar `AuditLog.Read.All`); V1 follows.

### 4. Fix the L2 tool-assembly drift (prerequisite)

`synthesis_steps.run_l2` (the F8/LangGraph path, `isoc_use_langgraph` default-off) passes only
`DEEP_TIER_TOOLS`, it does **not** merge the Defender tools and has no `on_tool_call` emitter, while
the legacy `orchestrator._step_synthesis` does. Adding tools to L2 in two places guarantees drift.
Factor L2's tool assembly into one `build_l2_tools(incident) -> (tools, dispatch)` helper both paths
call, so new reads can't silently vanish when the graph flag flips.

## Token-cost control

- Auto-hunt goes live **only** on the tiered subset (D1); non-urgent warranted hunts stay
  query-only (zero live calls).
- Live hunts are call-budgeted + row-capped + wall-clock-bounded (§2).
- L2 reads are model-choice (D2), paid only when the model calls them; the read cache (D6) prevents
  the manager re-fetching what L2 already pulled.
- `get_user` sign-in reads return a bounded window slice, not full history.

## Consequences

- The analyst sees **confirmed spread** (or a clean spread-check) at sign-off for urgent TPs, not a
  query to run later.
- Hunt depth becomes **deterministic and criticality-aware** again: a crown-jewel host is hunted
  even if L2 didn't flag it; the model can't veto a hunt on a confirmed critical.
- Identity alerts gain a real user dimension (risk + recent sign-ins).
- **New privacy surface:** sign-in data (IPs, locations, MFA results) and user profile flow into the
  LLM context + incident record. Return a bounded, relevant slice; note for the go-public review.
- One behavioral change to the write invariant: **none.** Every write remains analyst-gated; only the
  *read* boundary moved (D0).

## Prerequisites (operational, not code)

- **`AuditLog.Read.All` admin consent** on each tenant's app registration is required for the sign-in
  timeline in `get_user` (D4). This is an Azure action the operator performs per tenant; the tool
  degrades gracefully where it is absent. Risky-user state + profile need no new consent (granted).
- Backend/worker image rebuild to take effect (source is baked into the image).

## Build order (when picked up)

1. `build_l2_tools` helper, de-dupe L2 tool assembly across both synthesis paths. *No external I/O.*
2. `agent_routing.decide_hunt` + `HuntDecision` + the read cache (`enrichment["reads"]`), replacing
   `should_hunt`. Pure, unit-testable (`tests/test_agent_routing.py`).
3. `pipeline/hunt_guard.py` query linter (KQL + TMV1). Pure, unit-testable.
4. Wire bounded-live auto-hunt into `run_hunt` (both paths) behind the linter + budget. Flag-gated.
5. Defender `get_user` adapter + tool (risky-user + profile first; sign-ins behind consent).
6. V1 `get_endpoint` + `get_user` adapters (net-new API research) → provider-agnostic tool surface.

Steps 1-3 ship independently with no external calls. Step 4 is the first behavioral change.

## Open questions for review

- **D6 vs pre-fetch:** keep the read cache + targeted manager reads, or demote D2 to a deterministic
  endpoint+user pre-fetch on L2-bound alerts? (The reviewer check above.)
- **`decide_hunt` thresholds:** the `run`/`live` predicates in §1 are a starting point, tune the
  criticality/threat-category set against real alert volume.
- **Call budget N** for the live hunt stage (proposed 3-5) and the stage wall-clock timeout.
- **V1 endpoint/user API mapping**, confirm the exact Endpoint Inventory + account-activity
  endpoints before committing to the V1 half of D3.

## Flags (proposed)

- Reuse `defender_tools_enabled` / `v1_activity_search_enabled` (creds-gated as today).
- New `auto_hunt_live_enabled` (default off), the master switch for D1's pre-gate execution, so the
  read/write-boundary change ships dark and is turned on deliberately per deployment.
