# Build plan, ADR-0009 (pre-gate enrichment, manager-owned hunt routing)

**Date:** 2026-07-24
**Tracks:** [ADR-0009](ADR-0009-live-hunt-and-manager-routing.md) (see Amendment 1 = competitor gap
analysis; Amendment 2 = the autonomy pivot this plan implements).
**Status:** Plan (not started).

## The pivot this plan implements (Amendment 2)

Reputation, endpoint detail, and identity are fetched **deterministically before the L2 call** and
injected into the briefing, NOT exposed as model-choice L2 tools. Rationale: a tool per read means a
second LLM round-trip each time the model asks; pre-enrichment is one richer prompt, more autonomous,
and guarantees coverage. Live threat hunting stays **operator-triggered** at the gate. Two clean
consequences: the old auto-live-hunt PR is dropped, and the D6 read-cache machinery is deleted (the
manager reads pre-enriched signals directly).

**The clean split:**

| Class | Treatment |
|---|---|
| Bounded point-lookups (file/hash/domain/IP reputation, endpoint detail by id/name, identity) | **Auto-enrich just before L2** (this plan) |
| Open-ended hunt (advanced-hunting KQL, activity search) | **Operator-triggered** at the gate (`manager_chat._run_hunt`, unchanged) |
| Hunt *decision* (is a hunt warranted?) | Manager recommends at the gate from the pre-enriched signals (PR-4) |

**Where it runs:** a new sub-step in `_step_synthesis` (and `synthesis_steps`) AFTER the L1
short-circuit and BEFORE L2, so only escalated alerts hit the Microsoft/Graph APIs (throttling +
cost). It does not feed the deterministic auto-close gate, by design. Calls run concurrently
(`asyncio.gather`), fail-soft (never block L2), GET-only, per-tenant creds, per-scope 403 degradation,
each slice slimmed so the briefing does not bloat. This mirrors the existing ADR-0005 V1
workbench auto-fetch pattern.

## Shape

```
PR-1 pre-enrich scaffolding + reputation ─┬─► PR-2 endpoint detail ──┐
                                          └─► PR-3 identity ─────────┴─► PR-4 decide_hunt ─► (operator runs hunt at gate)
                                                                         └─► PR-6 confirmation (needs PR-3 manager)
PR-5 L2 tool cleanup (after PR-1/2/3)
```

**Highest-value-first:** PR-1 (reputation, near-zero new consent) + PR-3 (identity) close the
high-severity competitor gaps. PR-2 feeds criticality into the hunt decision. PR-6 (confirmation) is
the differentiator.

**Preserved invariants (every PR):**
- Only the analyst's Approve in `routes/cases.py` writes a verdict or fires a response action. This
  plan is read-only except PR-6, whose single outbound send is analyst-gated and whose reply is
  evidence, never an auto-commit.
- Pre-enrichment handlers are physically GET-only and never share a code path with any write adapter fn.
- Every new capability is flag-gated and creds-gated; off equals byte-identical to today.

**No new Alembic migration** (enrichment slices live in `enrichment` JSONB; `HuntDecision` in-memory;
identity sign-in baseline reuses existing tables). Confirm per PR.

**After each PR:** `cd deploy && docker compose build backend worker && docker compose up -d backend
worker`. Tests on the host: `cd backend && pytest -q` + `ruff check isoc_api`.

## Flags (settings.py)

| Flag | Default | PR | Purpose |
|---|---|---|---|
| `isoc_enable_llm_tools` | off | (exists) | Master gate inside `complete_with_tools` |
| `defender_tools_enabled` | off | (exists) | Defender creds/adapter (reused by pre-enrichment) |
| `v1_activity_search_enabled` | off | (exists) | V1 operator-gate hunt |
| `ms_autoenrich_enabled` | off | PR-1 | Master switch for the pre-L2 deterministic enrichment step |
| `confirmation_workflow_enabled` | off | PR-6 | Gated out-of-band user/manager confirmation |

(The old `auto_hunt_live_enabled` / `auto_hunt_max_rounds` / `auto_hunt_timeout_s` and
`entra_identity_enabled` flags are dropped: no auto-live-hunt, and identity is part of
`ms_autoenrich_enabled`.)

---

## PR-1, pre-enrichment scaffolding + Defender reputation

**Goal:** the foundation step plus the reputation reads that were the competitor's FP hinge.

**Changes**
- New sub-step `pipeline/prefetch.py::prefetch_entity_enrichment(session, incident)`: resolves the
  alert's IOCs/entities from `normalized` + `enrichment`, runs the provider reads concurrently
  (`asyncio.gather`), fail-soft, writes results under `enrichment["ms"]` (e.g. `reputation`,
  `endpoint`, `identity`). Insert it in `orchestrator._step_synthesis` AFTER `maybe_short_circuit`
  and BEFORE the L2 call, and the mirror in `synthesis_steps` (between `maybe_short_circuit` and
  `run_l2`). Gated by `ms_autoenrich_enabled` + creds.
- `defender_adapter.py` new GET reads (reuse the `_mde_get` pattern):
  - `get_file_info(id)`: MDE `GET /api/files/{id}` (`determinationType`/`determinationValue`,
    `signer`/`issuer`/`isValidCertificate`/`filePublisher`). Scope `File.Read.All` (held).
    Complements the existing `get_file_stats` (prevalence).
  - `get_domain_stats(domain)`: MDE `GET /api/domains/{domain}/stats` (org prevalence + first/last
    seen). Scope `Url.Read.All` (held per app-reg screenshot; there is no `/api/urls` endpoint, a
    "URL profile" IS domain stats). High prevalence + old first-seen is a strong benign prior.
  - `check_custom_indicator(value, type)`: `GET /api/indicators` filtered to the tenant custom
    allow/block list. Scope `Ti.ReadWrite` (held). "Already Allowed as official CDN" is a decisive
    local FP; "on the blocklist" a decisive TP.
  - (existing `get_ip_stats` for IPs; existing `ipinfo_adapter` already gives ASN/org owner.)
- `briefing.py`: render an `ms_reputation` section from `enrichment["ms"]["reputation"]`.

**Tests** `tests/test_prefetch_reputation.py` (mock securitycenter): each read; concurrent gather;
one provider 403 does not sink the others; slices are slimmed; GET-only guard; the step is a no-op on
a short-circuited alert (never reached).

**Prerequisite:** `File.Read.All` + `Ti.ReadWrite` confirmed held; verify `Url.Read.All` per tenant.

---

## PR-2, endpoint-detail pre-enrichment

**Goal:** the impacted host's criticality/exposure, pre-fetched for L2 AND the hunt decision.

**Changes**
- Defender: call the existing `get_machine(device_id)` (scope `Machine.Read.All`, held) from the
  device id in the alert evidence; write `enrichment["ms"]["endpoint"]`.
- Trend Micro: `v1_adapter.get_endpoint_details(endpoint_name)` (NET-NEW, V1 Endpoint Inventory API,
  needs a short spike to confirm the endpoint + fields for criticality). Resolve from the endpoint
  name as the user asked.
- `briefing.py`: render an `ms_endpoint` section (risk/exposure/OS/last-seen/criticality).

**Tests** `tests/test_prefetch_endpoint.py`: Defender `get_machine` mapped from device id; V1 endpoint
detail from endpoint name (mock); criticality lands in `enrichment["ms"]["endpoint"]` for PR-4.

**Note:** if the V1 Endpoint Inventory API lacks a criticality field, document the reduced surface
rather than fake it (same rule as the old V1-symmetry spike).

---

## PR-3, identity pre-enrichment (tenant-keyed `get_user`, FULL)

**Goal:** the identity context the competitor leans on, fetched deterministically for ANY incident
(CrowdStrike, V1, email), keyed on the TENANT (Entra), not the EDR that fired the alert.

**Changes**
- `integration_store`: resolve Entra/Graph creds by `customer` under a provider key (e.g. `entra`),
  reusing the multi-tenant-app + admin-consent model. `STRICT_TENANT_CREDS` still fails closed.
- `graph_identity_adapter.py`, all GET, each field in its own try/except that drops on 403:
  - `GET /users/{id}?$select=id,displayName,userPrincipalName,accountEnabled,department,jobTitle,mail,officeLocation,userType,onPremisesSecurityIdentifier,city,country`
    (pin the `$select`; `accountEnabled`/`department`/`jobTitle` are NON-default;
    `onPremisesSecurityIdentifier` is the Windows SID). Scope `User.Read.All` (held).
  - `...&$expand=manager($select=id,displayName,mail,userPrincipalName)` header
    `ConsistencyLevel: eventual` (app-only is unsupported on the bare `/manager` nav). Feeds
    VIP/exec detection and PR-6.
  - `GET /identityProtection/riskyUsers/{id}` (state, `IdentityRiskyUser.Read.All`, held) +
    `GET /identityProtection/riskDetections?$filter=userId eq '{id}'` (why risky;
    `IdentityRiskEvent.Read.All`, NEW consent).
  - `GET /reports/authenticationMethods/userRegistrationDetails/{id}` (`methodsRegistered[]` count =
    the "6-9 factors" signal, `isAdmin`). Scope `AuditLog.Read.All` (NEW; same consent unlocks
    sign-ins too).
  - `GET /auditLogs/signIns?$filter=userId eq '{id}' and createdDateTime ge {window}&$top={N}`
    (bounded slice, last N in the alert window). BLIND SPOT to document: v1.0 is INTERACTIVE-only;
    non-interactive needs `/beta` + a `signInEventTypes` filter.
- `prefetch.py`: call it when the alert has a user principal + Entra creds; write
  `enrichment["ms"]["identity"]`. `briefing.py`: render an `identity` section.
- Guard: GET-only; must not import or call `set_user_enabled`.

**Tests** `tests/test_prefetch_identity.py` (mock httpx): composes all reads; drops
sign-ins/riskDetections on 403 and still returns profile+risk+manager; window-bounds sign-ins; a
CrowdStrike-source incident still gets identity enrichment; static guard that the handler has no path
to a write fn.

**Prerequisite (operator):** `AuditLog.Read.All` + `IdentityRiskEvent.Read.All` admin-consented per
tenant (profile + risky-user + manager need nothing new). Ship degrading gracefully where absent.

---

## PR-4, `decide_hunt` + `HuntDecision` (manager owns the hunt decision)

**Goal:** move the hunt decision off L2's boolean onto the manager (code), per ADR-0009 D5. The
manager RECOMMENDS a hunt + focus to the operator from the pre-enriched signals; the operator runs it
live at the gate. No auto-execution.

**Changes**
- `contracts.py`: add `HuntDecision(run, focus, reason)` (no `live` field: execution is
  operator-gated). Keep `AnalysisVerdict.hunt_recommended`/`hunt_focus` as advisory inputs.
- `agent_routing.py`: `decide_hunt(l2, enrichment) -> HuntDecision` reading the pre-enriched
  criticality (`enrichment["ms"]["endpoint"]`), user risk (`["identity"]`), reputation, and IOC
  verdicts. No read cache (everything is already in `enrichment`). Keep `should_hunt` as a shim, then
  delete.
- Call sites: `orchestrator._step_synthesis` (~1297) and `synthesis_steps.should_hunt(ctx)`. When
  `run`, the query-building hunt persona runs as today (`complete`, no live tools) and the
  recommendation + built queries surface at the gate for the operator.

**Tests** `tests/test_agent_routing.py`: truth table over verdict x hunt_recommended x malicious IOC
x severity x pre-enriched criticality x threat_category; confirm a high-criticality confirmed-TP with
`hunt_recommended=false` still yields `run=true`.

---

## PR-5, L2 tool cleanup + langgraph consistency

**Goal:** now that reputation/endpoint are pre-enriched and hunt is operator-gated, remove the live
Defender tools from L2's auto set and stop the two synthesis paths from drifting.

**Changes**
- L2's auto tool set shrinks to `lookup_ioc_history`. Remove `DEFENDER_TOOLS` from the L2 assembly in
  `orchestrator._step_synthesis` (~1240-1246). `defender_run_hunt` remains available only at the gate
  (`manager_chat`, unchanged).
- Route both `_step_synthesis` and `synthesis_steps.run_l2` through one small `build_l2_tools(incident)`
  helper (fixes the pre-existing regression where `run_l2` omitted tools + the `on_tool_call` emitter).

**Tests** `tests/test_l2_tools.py`: both paths return `[lookup_ioc_history]`; no Defender live tools
on the L2 path; the gate hunt still has `defender_run_hunt`.

**Sequencing:** land AFTER PR-1/2/3 so L2 gets the pre-enriched data before its live tools are removed.

---

## PR-6, out-of-band dual confirmation

**Goal:** the competitor's most distinctive move (user confirmed directly; manager independently
validated). Email-first, because it works today.

**Changes**
- New proposed action kind `request_confirmation` (`provider=graph_mail`, params `{recipient,
  manager_id, channel}`), built at the manager stage. Manager resolved via PR-3's `$expand=manager`.
- Dispatch in `routes/cases.py::_run_proposed_actions` ONLY when the analyst checks its id: send via
  the existing `graph_mail_adapter` (`Graph POST /users/{id}/sendMail`, `Mail.Send` app-only, scoped
  to one SOC mailbox via Exchange App RBAC). Sending is an OUTBOUND WRITE, so it is analyst-gated.
- The reply is captured as out-of-band EVIDENCE surfaced to the analyst, NEVER an auto-commit. Two
  gates: analyst gates the ask, analyst still gates the verdict.
- Defer: Outlook Actionable Messages / Teams Adaptive Card (app-only Graph `chatMessage` is
  migration-only, not usable for live sends).

**Tests** `tests/test_confirmation_action.py`: proposed but never auto-sent; sends only on analyst
check; a captured reply is stored as evidence and does not mutate the verdict.

**Prerequisite (operator):** `Mail.Send` (app-only) scoped to one SOC mailbox.

---

## Optional hardening, `hunt_guard` on the operator hunt

The operator-triggered gate hunt (`manager_chat._run_hunt`, `gated=False`) benefits from a query
linter, but it is lower priority now that no hunt auto-executes. If built: `pipeline/hunt_guard.py`
with `lint_kql` (allowlist `Device*` tables, inject `Timestamp` window + `| limit`, reject
`externaldata`/`evaluate`/`.show`/`cluster(`) and `lint_tmv1` (top cap + window), wrapped around the
gate hunt handlers. Pure, unit-testable. Not scheduled; fold in when convenient.

---

## Deterministic enrichment helpers (not PRs, cheap wins)

Fold into the pre-enrichment step, no extra Microsoft API:
- **RFC1918 private-vs-public IP classification** (`ipaddress.is_private`) so a report can state
  "internal RFC1918 source", the way the competitor did for `192.168.68.56`.
- **IP to ASN/org attribution** via the existing `ipinfo_adapter` (Defender `ip_stats` gives org
  PREVALENCE, not owner) so a report can say "resolves to GitHub Inc."
- **Per-user sign-in location baseline**: persist a `{country, city, ASN}` histogram in ISOC's own
  store (Graph sign-in logs retain only 30 days). Lean on Identity Protection
  `unfamiliarFeatures`/`unlikelyTravel` (from PR-3 riskDetections) as the primary "is this location
  established" signal.

## Gaps the verifier flagged as under-called (backlog, not scheduled)

- **MDO email hunting** (`EmailEvents`/`EmailUrlInfo`/`EmailAttachmentInfo` via advanced hunting):
  absent; relevant to ISOC's email-incident focus.
- **Model-callable alert/incident detail read** (`GET /security/incidents`, get-alert-by-id):
  `alerts_v2` is ingest-only today; the triggering alert's full evidence could be pre-enriched too.
- **TVM/vulnerability reads** + **machineActions history**: `get_machine` returns an exposure score,
  not the vuln list or live isolation/scan state.

## Prerequisites summary (operator, per tenant)

| Item | For | Status |
|---|---|---|
| `Url.Read.All`, `File.Read.All`, `Ti.ReadWrite` | PR-1 reputation | Held (verify `Url.Read.All` per tenant) |
| `Machine.Read.All` | PR-2 Defender endpoint | Held |
| V1 Endpoint Inventory API access | PR-2 Trend endpoint | Spike to confirm |
| `User.Read.All` / `User.ReadWrite.All` | PR-3 profile + manager | Held |
| `AuditLog.Read.All` | PR-3 sign-ins AND MFA registration report | New consent |
| `IdentityRiskEvent.Read.All` | PR-3 riskDetections | New consent |
| `Mail.Send` (one SOC mailbox) | PR-6 confirmation | New consent |

## Sequencing

- **Fastest parity:** PR-1 (reputation, near-zero consent) + PR-3 (identity).
- **Hunt decision:** PR-2 (endpoint criticality) then PR-4 (`decide_hunt`).
- **Cleanup:** PR-5 after PR-1/2/3.
- **Differentiator:** PR-6, needs PR-3's manager expand.

## Definition of done (per PR)

`pytest -q` green locally (CI will not catch a failing test, see CLAUDE.md), `ruff check isoc_api`
clean, no unplanned Alembic revision, flags default-off, image rebuilt, and the pre-enrichment step
proven a no-op on short-circuited alerts (never reached) with `ms_autoenrich_enabled` off equal to
today.
