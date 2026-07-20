# ADR 0005 — Vision One workbench/OAT auto-enrichment (read-only)

**Date:** 2026-06-22
**Status:** Implemented (read-only path, behind default-off flags) — 2026-06-22. Pending
backend image rebuild + test run in-env (host has no backend deps). Files: `parsers/visionone.py`
(+ `__init__.py`, `normalizer.py` V1 fields), `adapters/v1_adapter.py` (region-aware client +
`get_workbench_alert`/`get_oat_detections`), `adapters/integration_store.py` (`get_creds_v1`,
**DB-backed**: `integrations` table row → global env fallback, admin-managed via
`/admin/settings/integrations` — ADR-0007 Layer 1), `pipeline/orchestrator.py` (`_step_enrich` v1 branch + cap helpers),
`pipeline/briefing.py` (`v1_enrichment` section), `pipeline/manager_chat.py`. Flags:
`v1_autofetch_enabled` (workbench), `v1_oat_enabled` (OAT) — both default False. Tests:
`vendor/.../tests/test_visionone_parser.py` (5/5 pass locally), `backend/tests/test_v1_workbench.py`.
**Scope note:** the alert-status write-back (`PATCH`, the FP-close) is **deferred** at the
analyst's request (2026-06-22). This ADR now covers **read-only enrichment only**: pull the
Workbench alert detail and the Observed Attack Techniques and feed them to the personas. The
write-back design + its verified API contract are parked in **Deferred** below for when it's
picked up.
**Relates to:** ADR-0007 (multi-tenant EDR creds — this is the V1 instantiation of that
auto-enrich pattern), `docs/PIPELINE.md`, `pipeline/orchestrator.py`, `pipeline/briefing.py`,
`adapters/v1_adapter.py`
**Method:** synthesized from a 9-agent workflow (4 recon readers over the live code, a
3-lens design panel, a judge, an adversarial reviewer), then trimmed to the read-only slice.

## Context

Trend Micro Vision One Workbench alerts arrive as **information-poor emails** (sample below):
a Workbench ID, model name, score, impact-scope counts, a few highlighted `processCmd` lines,
and a technique id. The personas currently reason from that thin text alone. The fix is to
**auto-enrich at ingest**:

- `GET /v3.0/workbench/alerts/{id}` — the full Workbench alert detail. **Live-tested
  2026-06-22:** already carries the rich evidence the *email* omits — `indicators[]` with the
  actual `objectCmd`/`processCmd`/`parentCmd` command lines, SHA1/SHA256 hashes, file paths,
  the host + IPs + account in `impactScope.entities[]`, `matchedRules[].mitreTechniqueIds`,
  and a `description`. **This single call delivers the bulk of "the LLM needs more info."**
- `GET /v3.0/oat/detections` — the Observed Attack Techniques. **Correction (live-tested):**
  the command lines are NOT exclusive to OAT — they're in the workbench detail above. OAT adds
  the *broader stream* of technique detections on the host around the alert (each with its own
  highlighted cmds + MITRE tactic/technique ids + `riskLevel`). It's **complementary context,
  high-volume** (179 detections in a 7-day window on one host in the test tenant), so it needs
  host-scoping + a risk-level filter + caps to be useful rather than noise.

Both are **read-only**, so this whole feature lives in the deterministic enrichment stage and
never touches the analyst-gate invariant.

There is **no Trend Micro parser today** (recon confirmed: only `wazuh`, `qradar`,
`fortigate`, `syslog` exist in `vendor/alert-memory-mcp/parsers/`; a V1 email currently falls
through to the generic path). So this work also adds a `visionone` email parser.

```
Subject: ... | Workbench | Alert Severity: Medium | Score: 66 | Model: Multiple Identified
Failed Logon via NetworkCleartext | WB-18364-20260621-00001 | <guid> (do not reply)
  Score: 66 · Workbench ID: WB-18364-20260621-00001 · Model severity: Medium
  Impact Scope: Endpoint UNOEXCSRV01 · User UNMAS_WG\furkan.akkaya
  Highlighted: (processCmd) "...MSExchangeFrontendTransport.exe"   [repeated x10]
  Techniques: T1110 - Brute Force
  Console: https://portal.sg.xdr.trendmicro.com/index.html#/workbench/alerts/WB-18364-...
```

## Where it fits (and why it can't break the pipeline)

The deterministic pipeline is `parse → autoclose_pre → dedup → enrich → decision →
[synthesis → gate]`. This feature touches exactly **two** points, both read-only:

- **`parse`** — a new additive `visionone` parser (last detection branch, fallback-safe).
- **`enrich` (`_step_enrich`)** — the V1 fetch is a **4th branch of the existing
  `asyncio.gather(..., return_exceptions=True)`** (orchestrator.py:568), routed through the
  existing `_ok()` helper + `enrich_subtask_failed` timeline event. A dead/slow V1 API emits
  a warning and the case proceeds with partial enrichment — it can never abort the run.

The briefing is the shared user prompt for every persona, so one new `briefing.render`
section feeds L1/L2/hunt/forensics/manager at once. **No writes, no new gate logic** — the
invariant is untouched by construction.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Transport | **Reuse `v1_adapter` (`_client`/`_raise_for`)**; add **2** read-only methods | No new transport; no MCP client (see "MCP rejected"). |
| 2 | Where it runs | **4th fail-soft branch in `_step_enrich`'s gather**, behind a default-OFF flag | Inherits `return_exceptions` + `_ok()` + `enrich_subtask_failed` for free. |
| 3 | WB-alert-id carrier | **Three typed `NormalizedAlert` fields** (`v1_workbench_id`, `v1_console_host`, `v1_region`) | Rejected overloading `rule_id`. Typed fields survive `to_dict()`; no migration (ride the normalized JSONB). |
| 4 | Region + credentials | **Resolved together as a pair** via the ADR-0007 `integration_store.get_creds_v1(customer)` seam, global-key fallback | Email-parsed region is a *hint only* — see Hard corrections #1. |
| 5 | Multi-tenant table | **Use the seam now; defer the `Integration` table/migration/admin CRUD to ADR-0007** | Single-tenant-capable with a clean seam; building the table here is scope creep. |
| 6 | Rollout | **Phase-1 dark** (parser + methods, no gather wiring, flag default False) → flip on after OAT contract verified | Ships independently; zero pipeline impact until the flag flips. |
| 7 | Token control | **Dedupe-with-count + caps at fetch AND render** | The sample's `[repeated x10]` processCmd would otherwise bloat an 8k-window prompt (which silently drops the *system* prompt on overflow). |

## Hard corrections (from the adversarial pass — do these or the read path is unsafe)

1. **Resolve region and credentials from one source.** The global key belongs to a fixed
   tenant in a fixed region. If a forwarded/cross-region email yields `region='sg'` but the
   only key is an `eu` tenant key, threading the parsed region into the client → 401/403 or a
   wrong-region hit. **Fix:** `get_creds_v1(customer)` returns `(api_key, region)` as a pair;
   treat the email-derived region as a hint only when it matches, else prefer the credential's
   region and log the mismatch.

2. **Scope OAT or it floods the briefing.** Live-tested: the OAT filter header
   `TMV1-Filter: endpointName eq '<host>'` **works** and changes results, so the whole-tenant
   leak is avoidable — but it must be *applied*. The test host had **179 detections in 7 days**,
   most at `riskLevel` `info`/`low` (benign noise like "Uncommon File Path"). **Fix:** always
   pass the `endpointName` filter + a tight window + a `riskLevel` floor (medium+) + a `top`
   cap + dedupe; keep a client-side guard dropping items whose `detail.endpointHostName` ≠ the
   alert host as defense-in-depth. (Note: with no date params the endpoint returns empty, not
   an error — always pass explicit dates.) Confirm the naive email `Created:` timezone before
   trusting the window math.

## Design

### Parser (`vendor/alert-memory-mcp/parsers/visionone.py` + `__init__.py`)
- `parse(raw, customer=None) -> NormalizedAlert`: defensive, section-by-section (never raises;
  missing section → field `None`). Sets `source_product='visionone'`, `rule_name=<Model>`,
  severity from "Model severity", `hostname`/`username` (keep domain-prefixed verbatim pending
  RAG-matching confirmation), `mitre_technique` (tactic null — email gives id only), plus the
  three typed V1 fields.
- `detect_source`: V1 is the **last** product branch, requires **≥2 distinctive markers**
  (`"TrendAI Vision One"`, `Workbench ID: WB-`, `portal.<region>.xdr.trendmicro.com`,
  `| Workbench |` + `WB-\d+-\d{8}-\d+`) so it can't shadow wazuh/qradar/fortigate.
- **Regression test** (load-bearing): feed existing wazuh/qradar/fortigate/syslog/garbage
  samples through `detect_source`, assert routing **unchanged**.

### Adapter methods (`adapters/v1_adapter.py`) — read-only
- `_client(region=None)` — thread an optional region (`_base_url` already handles arbitrary
  regions, verified `sg` → `api.sg.xdr.trendmicro.com`). Existing callers unaffected.
- `get_workbench_alert(alert_id, *, region=None)` — GET, no Content-Type (existing quirk).
  **Live-verified** response (camelCase): `schemaVersion`, `id`, `investigationStatus`,
  `status`, `investigationResult`, `workbenchLink`, `alertProvider`, `model`/`modelId`/
  `modelType`, `score`, `severity`, `createdDateTime`, `updatedDateTime`, `incidentId`,
  `description`, `impactScope` (`{desktopCount, serverCount, accountCount, …, entities[]}`;
  host entity = `{guid, name, ips[]}`, account entity value is domain-prefixed `csv-04\user`),
  `matchedRules[]` (`{name, matchedFilters[{name, mitreTechniqueIds[], matchedEvents[{uuid,
  type}]}]}`), and **`indicators[]`** (`{id, type, field, value}` where `field` ∈
  `objectCmd`/`processCmd`/`parentCmd`/`objectFileHashSha1`/`objectFileHashSha256`/
  `processFilePath`/`endpointHostName`/… — the command lines, hashes, paths). The briefing
  reads these directly.
- `get_oat_detections(*, start, end, endpoint, region=None, top=50)` — **live-verified.**
  `GET /v3.0/oat/detections?detectedStartDateTime=<RFC3339Z>&detectedEndDateTime=<RFC3339Z>&top=N`,
  header `TMV1-Filter: endpointName eq '<host>'` (confirmed working). Response: `{totalCount,
  count, items[]}`; each item = `{source, uuid, detectedDateTime, filters[{id, name,
  description, highlightedObjects[{field, type, value}], mitreTacticIds[], mitreTechniqueIds[],
  riskLevel, type}], detail{endpointHostName, endpointIp, …}}`. Always pass dates (no dates ⇒
  empty result, not an error); filter to `riskLevel` medium+ and cap+dedupe before storing.

### Enrichment flow
`v1_task` is built only when `source_product=='visionone'` AND a WB id is present AND
`settings.v1_autofetch_enabled` AND creds resolve — else a no-op coroutine. It joins the
existing gather, passes through `_ok(res, 'v1_fetch')` (add `'v1_fetch'` to `_subtask_labels`),
and on success stores a **capped** `enrichment['v1']` (impact-scope → counts, OAT →
`_MAX_OAT_ROWS` with command lines truncated + deduped `cmd (xN)`, raw nested `details`
dropped) so the JSONB row and any later Qdrant index stay bounded. Inner `get_workbench_alert`
and `get_oat_detections` run under their **own** `return_exceptions` so an OAT failure still
yields the workbench detail. `briefing.render` gains a `v1_enrichment` kwarg; **both** call
sites (orchestrator `_render`, `manager_chat.render_case_briefing`) pass `enrichment.get('v1')`.
A render test asserts the section appears via both paths.

### Token control
Caps at fetch (before persistence) AND render, matching `briefing.py`'s `_MAX_KB_HITS=8` /
`_MAX_TRIAGE_BLOCKS=20` discipline: OAT to `_MAX_OAT_ROWS` with command lines truncated and
the sample's `[repeated x10]` processCmd collapsed to `cmd (x10)`; workbench detail kept to
scalar fields + impact-scope counts, raw nested blobs dropped before `enrichment['v1']` is
stored.

## Verified API contract (read path) — live-tested 2026-06-22

Tested against a real tenant (`WB-30189-20260526-00008`, region **eu**, model "Credential
Dumping via Mimikatz"). Both endpoints returned **HTTP 200**; field names + the OAT filter are
now confirmed (see the adapter section for the full shapes), with three findings that change
the plan:

1. **The workbench detail already carries the command lines** (`indicators[].field` =
   `objectCmd`/`processCmd`/`parentCmd` + hashes/paths) — so `get_workbench_alert` alone covers
   the core requirement; OAT is optional broader context.
2. **Real enum casing is title-case**, not XSOAR's snake_case: `status`="Open",
   `investigationStatus`="New", `investigationResult`="No Findings" (and `severity`="high",
   lowercase). The deferred write-back map is corrected for this below.
3. **Region is not in the API key** — the JWT has no region claim, and the token authenticated
   *only* on `eu` (401 elsewhere). So region must come from the console URL / the credential
   row, never from the token — reinforcing Decision #4.

## Open questions
- **Timestamp tz** — the email `Created:` is naive; affects the OAT window. (The *API* uses
  RFC3339 `Z`, so once we anchor on `createdDateTime` from the detail call this mostly resolves.)
- **Username normalization** — keep domain-prefixed `csv-04\user` / `UNMAS_WG\furkan.akkaya`
  verbatim, or strip/UPN? Confirm what RAG/exclusion matching expects.
- **OAT volume policy** — exact `riskLevel` floor + window width + `top` cap (179 detections/7d
  on one test host). A tuning choice, not a blocker.
- **`rule_id`** — typed fields avoid overloading it; a quick grep that `embed_text`/similar
  matching doesn't read `rule_id` is enough.

## Build order (when picked up)
1. **Parser + adapter methods + briefing plumbing — DARK.** No gather wiring; flag default
   False; section renders only if key present (always None in P1). Parser correctness +
   `detect_source` regression + adapter Content-Type/region tests. Zero pipeline impact.
2. **Read-only auto-enrich — workbench detail first.** Add `v1_task` + `_v1_alert_ref()` + the
   `integration_store` seam (global-fallback form) into `_step_enrich`'s gather; for now fetch
   **only `get_workbench_alert`** (it carries the cmds/hashes/host/MITRE — the bulk of the
   value), cap + store `enrichment['v1']`, wire the briefing section at both call sites. Flip
   `v1_autofetch_enabled` in staging. Integration test with a mocked adapter incl. failure paths.
3. **OAT context (optional).** Add `get_oat_detections` scoped to the alert host + a tight
   window around `createdDateTime`, `riskLevel` medium+ filtered, capped + deduped. Only worth
   it if analysts want the broader on-host technique stream; the contract is already verified.

## Alert-status write-back (FP-close to suppress tenant threat-score) — IMPLEMENTED 2026-07-13

**Status update:** built behind `v1_status_writeback_enabled` (default OFF). `v1_adapter`:
`verdict_to_v1_status` (the `_V1_STATUS_MAP` below), `patch_alert_status` (GET ETag → PATCH with
`If-Match` + `{status, investigationResult}`), and `mirror_verdict_to_v1(incident, verdict)` —
fail-soft, gated on source=`visionone` + a workbench id + resolvable `get_creds_v1` creds, and (in
a multi-tenant setup) `is_v1_customer`. Called from BOTH commit points: `routes/cases.py`
`_commit_verdict` (analyst Approve / manual close) AND the orchestrator `run()` CLOSED block
(auto-close / short-circuit — the high-volume score-inflating case). The original design notes
below are retained for the verified contract.

Parked at the analyst's request (2026-06-22); when picked up it is a clean add-on to the read path
above and does not change it.

- **Why it matters:** V1 accrues tenant threat-score from un-dispositioned alerts, so mirroring
  an FP/benign verdict back closes the alert and stops it inflating the customer's risk score.
- **Contract** (read AND write **live-verified** 2026-06-22 — a reversible test PATCH returned
  **HTTP 204**, accepted **title-case** `investigationResult:"False Positive"`, allowed setting
  `investigationResult` alone, and setting `status` synced the deprecated `investigationStatus`;
  the alert was restored to its original state):
  `PATCH /v3.0/workbench/alerts/{id}` with body `status` + **`investigationResult`**. The GET
  returns these **title-cased**: `status` ∈ {`Open`, `In Progress`, `Closed`},
  `investigationResult` ∈ {`No Findings`, `Noteworthy`, `True Positive`, `False Positive`,
  `Benign True Positive`}. (`investigationStatus`="New" still appears but is deprecated; use
  `status` + `investigationResult`.) **`investigationResult="False Positive"` is the
  score-relevant write.** Confirm the PATCH accepts the same casing before enabling (a read
  returns title-case; the write *should* match — verify with one test PATCH on a throwaway
  alert).
- **`_V1_STATUS_MAP` (corrected to live title-case):** TP → `In Progress` / `True Positive` ·
  **FP → `Closed` / `False Positive`** · benign → `Closed` / `Benign True Positive` ·
  inconclusive → `In Progress` / `Noteworthy`.
- **Placement (decided):** a `mirror_verdict_to_v1(incident)` helper called from **every**
  verdict commit — `_commit_verdict` (analyst Approve + manual close) **and** the auto-close
  short-circuit (`DECIDED_SHORT_CIRCUIT`, no human) — because auto-closed FPs are the
  high-volume score-inflating case and never reach a gate. It is status *reconciliation*, not
  a posture-changing action, so it follows the commit rather than being a checkable action.
- **Hard prerequisite when added:** `_run_proposed_actions` / the commit path is **NOT**
  customer-gated today (only `is_configured()`); the mirror MUST add an explicit
  `is_v1_customer(inc.customer)` guard and resolve creds+region as a pair, or a global key
  PATCHes the wrong tenant. Fully fail-soft (never blocks the close); value-idempotent.
- **Frontend:** surface the mirror outcome in `ProgressRail.tsx`; optional analyst override of
  the target status at the gate.

## Revisit when
- **FP-score sync becomes a priority** → pick up the Deferred section above (it's fully
  designed + contract-verified; needs the `is_v1_customer` guard and live casing check).
- Non-email V1 ingest appears → consider a dedicated `Incident.external_alert_id` column.
- The ADR-0007 `Integration` table lands → `get_creds_v1` swaps from fallback-stub to a table
  read with zero churn at the call sites.

## MCP rejected
Considered the Trend Micro Vision One MCP plugin (`trendmicro/vision-one-skills`) as the
transport. Rejected: it's a Claude-Code agent plugin wrapping a Dockerized MCP server,
authenticates with a **single API key + region per deployment** (no per-call creds → not
multi-tenant), is **read-only for workbench (no status PATCH)**, and targets the LLM
tool-calling runtime — not the deterministic backend. It would add a Docker/MCP-client layer
without reducing any of the real complexity (parser, multi-tenant, token caps) and can't do
the deferred write-back. The thin `httpx` adapter is simpler and multi-tenant-capable. (The
MCP plugin remains useful for an analyst querying V1 interactively *inside Claude Code* — just
not wired into ISOC.)
