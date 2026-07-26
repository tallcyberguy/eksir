# ADR 0007 — Multi-tenant EDR/XDR integrations & gate-only live tools

**Date:** 2026-06-21 (updated 2026-07-16)
**Status:** **Implemented** — the full design (Layers 1–3) now ships, realized for **Microsoft
Defender** (the SentinelOne examples below are the original design; the same architecture was built
against Microsoft Graph + the Defender for Endpoint API). The core invariant held throughout: only
the analyst's Approve fires a write. Delivered across PRs #118–#127 (needs a backend/worker + frontend
rebuild to take effect):

- **Layer 1 — per-tenant credential store.** `integrations` table + `adapters/integration_store.py`
  (`get_creds` / `get_creds_v1`), admin CRUD + Connectors UI (built 2026-06). **Strict isolation added
  (PR #124):** `STRICT_TENANT_CREDS` refuses the `default` row + `V1_API_KEY` env fallbacks for a NAMED
  customer, so an unmapped customer fails closed instead of borrowing a shared key. Creds resolve by
  `(provider, incident.customer)` at every action.
- **Layer 2 — connector ingest + read-only enrichment.** Microsoft Defender pull-ingest
  (`adapters/ingest/microsoft_defender.py` → Graph `alerts_v2`); native **OCSF** parser replacing the
  vendored one (`adapters/ocsf_defender.py`, recovers email/MDO evidence, PR #119); deep-tier + gate
  **read tools** `defender_run_hunt` (Graph `runHuntingQuery`) / `get_machine` / `file_stats` /
  `ip_stats` (`llm/tools.py`) behind `DEFENDER_TOOLS_ENABLED` (PRs #118, #120).
- **Layer 3 — provider- & tenant-aware response actions.** `ProposedAction.provider` + `_run_proposed_actions`
  routes by it (PR #123). Action kinds `isolate_host` / **`scan_endpoint`** / `blocklist_ioc` (Ti.ReadWrite) /
  `disable_user` (Graph `User.EnableDisableAccount.All`) — PRs #121, #125, #127 — plus ad-hoc analyst
  endpoints (`routes/defenderactions.py`) and a frontend action panel. Verdict write-back to the alert
  (`mirror_verdict_to_defender`, PR #122). The conversational manager offers the incident's provider
  vocabulary and stamps `provider` from the incident, not the model (PR #126).

Difference from the design below: the S1 per-console **ApiToken** is replaced by **two-audience OAuth
client-credentials** — a Graph `.default` token (alerts + hunting + user disable + alert write-back)
and a Defender-for-Endpoint `.default` token (machine/file/IP + isolate/scan/blocklist), selected per
call by `defender_adapter._token(scope=)`.

**Relates to:** `docs/PIPELINE.md` (agent-persona synthesis + human gate), ADR-0002 (#5 model routing),
ADR-0006 (connector framework), ADR-0005 (V1 workbench enrichment)

## Context

ISOC ingests EDR/XDR alerts (Trend Micro Vision One, SentinelOne) and parks them
at the analyst sign-off gate (`CaseStatus.AWAITING_SIGNOFF`). Two gaps motivated
this design:

1. **No live telemetry pull.** The hunt/forensic personas are *query-building +
   reasoning only* — their prompts explicitly state "you have NO live access to a
   SIEM/EDR". A SentinelOne alert carries only a console URL + threat id; the rich
   threat JSON the analyst needs is never fetched. (Vision One is the same: ISOC
   parses the alert text but does not call the V1 API at ingest.)

2. **Credentials are single-tenant.** Vision One auth is one global key
   (`settings.v1_api_key`) plus a `v1_customers` string map. There is no
   per-tenant credential store, so an MSSP fleet (many customers across several
   SentinelOne consoles) cannot be served, and a response action cannot be routed
   to the correct customer's endpoint.

This ADR records the design for closing both gaps **without touching the core
invariant**: personas + the conversational manager only *propose*; the analyst's
Approve in `routes/cases.py` is the only thing that writes a verdict or fires a
response action.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Transport | **Backend adapters registered in the existing tool `DISPATCH`** — *not* a backend MCP client | Matches `llm/tools.py`; no new process/transport surface. MCP-client transport deferred to a possible future ADR. |
| 2 | Live-query execution point | **Gate-only** (`pipeline/manager_chat.py`, already `gated=False`, `max_rounds`-bounded) | The open-ended query→analyze loop has unbounded token cost; confining it to an analyst-initiated turn caps spend and keeps it deliberate. The auto pipeline does only one cheap read-only fetch (decision #5). |
| 3 | Credential store | **New `integrations` table**, Fernet-encrypted, reusing `llm/config_store.py` encrypt/decrypt/cache pattern | Adding a customer/console = one DB row via an admin route. No restart. |
| 4 | Credential key | **`(provider, identifier)`** where `identifier` = customer (V1) or **console host** (S1) | S1 tokens are console-level (one token per console, e.g. `euce1-105`, covering all its sites). |
| 5 | S1 tenant resolution | **Resolve customer/site from the threat-details API response**, not from config | The alert email has only console host + threat id; `agentRealtimeInfo` in the API response yields `agentId` / `siteId` / `siteName`. |
| 6 | Endpoint targeting | Response actions use the **`agentId` resolved at ingest** (site-pinned); name lookup is a site-scoped fallback that **fails closed** | Prevents cross-customer endpoint-name collisions (`DGZ31D31275` in two sites). |
| 7 | Backward compatibility | V1 falls back to the global `settings.v1_api_key` when no per-customer `integrations` row exists | No migration pain for the current single-tenant deployment. |

## Onboarding model (the operational payoff)

S1 tokens being console-level + identity resolved from the API means:

- **New customer under an existing console → zero config.** The console token
  already covers their site; `incident.customer` + `site_id` are auto-resolved
  from the threat-details JSON on ingest.
- **New console (e.g. `euce1-107`) → one `integrations` row.** The only time
  anyone touches credentials.

Vision One stays per-customer: add an `integrations` row per V1 customer, or rely
on the global-key fallback.

## Design

> **Caveat: the sections below describe the ORIGINAL SentinelOne design, which was NOT built as written.**
> The code identifiers here (`adapters/s1_adapter.py`, the `ISOC_ENABLE_S1_ENRICH` flag, the
> `parsers/sentinelone.py` auto-enrich step, `ApiToken` auth) never shipped. This ADR was realized
> against **Microsoft Defender** instead (`adapters/defender_adapter.py`, `adapters/ocsf_defender.py`,
> `adapters/ingest/microsoft_defender.py`, the `defender_tools_enabled` flag, two-audience OAuth):
> see the **Implemented banner at the top** for exactly what shipped (PRs #118 to #127). Read the design
> below as the architecture (the layer model + the analyst-gate invariant held); read the banner for
> the actual code.

### Layer 1 — `integrations` table + `adapters/integration_store.py`

```python
class Integration(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("provider", "identifier", name="uq_provider_identifier"),)
    provider:   Mapped[str]          # "vision_one" | "sentinelone"
    identifier: Mapped[str]          # V1: customer name ; S1: console host
    enabled:    Mapped[bool] = mapped_column(default=True)
    region:     Mapped[str | None]   # V1 only
    api_key_encrypted: Mapped[str]   # Fernet — reuse config_store.encrypt_secret/decrypt_secret
    label:      Mapped[str | None]   # human note, e.g. "EU console 105"
```

`integration_store.py` mirrors `config_store.py`: a 60s cache behind an
`asyncio.Lock`, decrypt via `config_store.decrypt_secret`. Helpers:
`get_creds_v1(customer)` (with global-key fallback) and
`get_creds_s1(console_host)`. Admin CRUD lives in `routes/admin.py`; keys are
masked on read via `config_store.mask_key`.

### Layer 2 — SentinelOne parser, adapter, auto-enrich

**Parser** (vendored, per CLAUDE.md "extend in `alert-memory-mcp/parsers`"):
`vendor/alert-memory-mcp/parsers/sentinelone.py` extracts console host + threat id
from the `…/analyze/threats/<id>` URL, plus machine name, internal/external IPs,
threat name, timestamp. Registered in the normalizer's product detection.

**Adapter** `adapters/s1_adapter.py` — client built **per-credential** (not
module-global), `Authorization: ApiToken <token>`:

- Read-only: `get_threat_details`, `get_threat_timeline`,
  `powerquery(query, hours, max_rows)`, `find_agent(name, site_id)`.
- Write (gate-only, analyst-approved): `initiate_scan(agent_id)`,
  `disconnect(agent_id)`.

**Auto-enrich** — a new soft step in `orchestrator._step_enrich`, S1-only,
fail-soft, behind `ISOC_ENABLE_S1_ENRICH`:

```python
if normalized.get("source_product") == "sentinelone" and normalized.get("s1_threat_id"):
    creds  = await integration_store.get_creds_s1(normalized["s1_console_host"])
    threat = await s1_adapter.get_threat_details(creds, normalized["s1_threat_id"])
    info   = threat["agentRealtimeInfo"]
    enrichment["s1"] = {
        "console_host": normalized["s1_console_host"],
        "threat_id":    normalized["s1_threat_id"],
        "agent_id":     info["agentId"],     # pins the exact endpoint
        "site_id":      info["siteId"],
        "site_name":    info["siteName"],
        "details":      threat,              # full JSON → new briefing section
    }
    incident.customer  = incident.customer or info["siteName"]
    incident.tenant_id = await ensure_tenant_for_customer(session, incident.customer)
```

The fetched JSON flows into `briefing.render(...)` as a new section, so L2/hunt/
forensics reason over real EDR telemetry — all read-only, inside the invariant.

### Layer 3 — gate-only tools + tenant-aware response actions

**Gate tools** added to `manager_chat.MANAGER_TOOLS` (dispatch resolves creds from
`inc.customer` / `enrichment["s1"]`, results truncated to bound tokens):

- `run_powerquery {query, hours}` → `s1_adapter.powerquery` (read-only, row-capped)
- `get_threat_details {}` → returns `enrichment["s1"]` or fetches on demand

**Response actions become provider- and tenant-aware.** Each `ProposedAction`
gains a `provider`; `_run_proposed_actions` routes by it. New action kind
`scan_endpoint`:

```python
s1 = enrichment["s1"]
creds = await integration_store.get_creds_s1(s1["console_host"])
agent_id = s1.get("agent_id") or \
           (await s1_adapter.find_agent(creds, params["endpoint_name"], site_id=s1["site_id"]))["id"]
await s1_adapter.initiate_scan(creds, agent_id)
```

V1 actions resolve `get_creds_v1(inc.customer)` and fall back to the global client.

## Token-cost control

- Auto pipeline: one read-only `get_threat_details` call per S1 alert. Bounded.
- Open-ended query/analyze: **gate-only**, inside `complete_with_tools(..., gated=False,
  max_rounds=N)` — capped per analyst turn, and only fires when the analyst asks.
- `powerquery` results are row-capped (`max_rows`) before being handed to the LLM.

## Consequences

- An MSSP fleet (many customers, multiple S1 consoles + V1 tenants) is served
  from one credential table; new customers under a known console need no config.
- Response actions are pinned to the alert's resolved `agentId`/`site_id` →
  cross-customer endpoint-name collisions cannot mis-fire.
- One **new outbound behavior at ingest** (the S1 threat-details fetch) — gated,
  fail-soft, so a dead token never blocks the pipeline.
- The core invariant is untouched: only the analyst's Approve commits a verdict or
  fires a write action; all auto-pipeline and gate tools are read-only except the
  analyst-approved `scan_endpoint`/isolate path.

## Build order (when picked up)

1. `integrations` table + migration + `integration_store.py` + admin CRUD. *No external I/O; testable alone.*
2. `parsers/sentinelone.py` + normalizer registration. *Unit-testable against the sample alert.*
3. `s1_adapter.py` (read-only first) + S1 auto-enrich step + briefing section. Flag `ISOC_ENABLE_S1_ENRICH`.
4. Gate tools in `manager_chat` + provider-aware `_run_proposed_actions` + `scan_endpoint` kind.

Steps 1–2 ship independently (no external calls). Step 3 is the first live API call.

## Revisit when
- A second team wants to reuse community MCP servers directly → reconsider decision
  #1 (add a backend MCP-client transport alongside the adapters).
- Gate-only proves too restrictive (analysts want auto-hunt with live queries) →
  promote read-only queries into the hunt persona behind a separate budget guard.
  **→ taken up by ADR-0009 (proposed): the read/write split + bounded live auto-hunt.**
- A provider issues per-site (not per-console) S1 tokens → `identifier` semantics
  extend to `(console, site)` without a schema change (it's a free-form string).
