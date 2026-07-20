# EKSIR Data Model

PostgreSQL schema for case state, audit, and configuration.
Vectors live in Qdrant across three collections — `alerts_v2`, `iocs_v2`, and
`knowledge_base_v2` (shared with `alert-memory-mcp`).

> **Scope:** the schema has **42 tables** (see `backend/isoc_api/db/models.py` for
> the authoritative list). This document details the **core** case/audit tables in
> full and then summarizes the remaining table groups (tenancy/RBAC, integrations,
> exclusions, SLA, entities, correlation, threat feeds, ingest, reporting,
> notifications, case collaboration). For any column-level detail not shown here,
> read `models.py` — it is the source of truth.

## Entity diagram

```
users ──┐
        │  created_by / updated_by / assignee_id
        ▼
   incidents ──┬─► timeline_events
               ├─► investigation_artifacts
               ├─► forensics_jobs
               ├─► llm_calls
               └─► ioc_records ──► ioc_enrichments

webhook_sources ─► incidents      (each incident knows its ingest origin)
auto_close_rules                  (mirrored from YAML; editable in UI)
api_keys                          (machine-to-machine ingest tokens)
audit_log                         (every privileged action)
```

## Core tables

### `users`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| email | citext UNIQUE | |
| password_hash | text | bcrypt 12 rounds |
| role | enum('admin','analyst','viewer') | RBAC |
| status | enum('active','disabled') | |
| created_at | timestamptz | |
| last_login_at | timestamptz | |

### `incidents`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| case_number | text UNIQUE | e.g. `INC-000001` — generated from the `isoc_case_seq` sequence |
| title | text | rule name + customer + severity tag |
| status | case_status enum | see PIPELINE.md |
| severity | enum('low','medium','high','critical') | |
| verdict | enum('TP','FP','benign','pending','inconclusive') | PENDING until analyst confirms |
| confidence | enum('low','medium','high') | from decision gate or LLM |
| customer | text | legacy tenant label (kept alongside `tenant_id`) |
| tenant_id | UUID FK tenants.id | resolved tenant; NULL until backfilled/unmapped |
| rule_name | text | from normalizer |
| source_product | text | visionone / microsoft_defender / crowdstrike / qradar / wazuh / … |
| ingest_source | enum('paste','webhook','file','email','pull','batch') | |
| webhook_source_id | UUID FK | NULL if not via webhook |
| raw_payload | jsonb | original alert |
| normalized | jsonb | NormalizedAlert / OCSF as JSON |
| enrichment | jsonb | triage + ipinfo + vector_topK + KB + `scores` (see below) |
| autoclose_match | jsonb | matched YAML rule (pre + post enrichment) |
| short_circuit | jsonb | which gate fired (exact_match / n_way / autoclose) or null |
| llm_report_markdown | text | the synthesized report |
| llm_input_tokens | int | per-investigation cost tracking |
| llm_output_tokens | int | |
| llm_model_used | text | virtual model name |
| analyst_notes | text | free-form analyst additions |
| verdict_reason | text | the analyst's short "why", captured at verdict time; indexed to Qdrant |
| handoff_note | text | note left for the next shift (Shift Handoff board) |
| assignee_id | UUID FK users.id | NULL = unassigned |
| claimed_at | timestamptz | first claim (Investigation Queue); anchors the response SLA |
| snoozed_until | timestamptz | Investigation Queue snooze expiry; NULL = active |
| snoozed_by_id | UUID FK users.id | who snoozed it |
| approved_by_id | UUID FK users.id | who signed off the verdict at the human gate (NULL for auto-close) |
| signed_off_at | timestamptz | when the gate verdict was committed |
| created_at | timestamptz | |
| updated_at | timestamptz | |
| closed_at | timestamptz | NULL until verdict set |
| qdrant_alert_id | UUID | id returned by store.index_alert() |
| deleted_at | timestamptz | soft-delete (archive); NULL = visible. Hard delete removes the row |

Indexes: `case_number`, `status`, `severity`, `verdict`, `customer`, `tenant_id`,
`assignee_id`, `snoozed_until`, `approved_by_id`, `qdrant_alert_id`, `deleted_at`,
`created_at desc`, GIN on `normalized`, GIN on `enrichment`.

**`enrichment['scores']`** (written by `pipeline/scoring.py` at the manager stage
and the short-circuit path — no dedicated column, no migration):

```jsonc
{
  "confidence": 88,          // 0-100, certainty of the verdict
  "threat": 9,               // 0-100, EFFECTIVE = inherent × P(malicious)
  "threat_inherent": 78,     // 0-100, "if real, how bad"
  "p_malicious": 0.12,       // the modulator applied to inherent
  "confidence_band": "high", // low | medium | high
  "contributions": { "confidence": {…}, "threat": {…} }  // per-term "why", for the UI
}
```

Surfaced on the API as read-only `Incident.confidence_score` / `threat_score`
properties (Python `@property` reading `enrichment['scores']`), so list rows carry
the numbers without shipping the whole blob. See PIPELINE.md → "Case scores".

### `timeline_events`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| incident_id | UUID FK | |
| ts | timestamptz | |
| actor | text | 'system' / user email / 'webhook:s1' |
| event_type | text | 'ingest' / 'autoclose_pre' / 'enrich_done' / 'decision_gate' / 'llm_synthesis' / 'verdict' / 'note' / 'forensics' |
| payload | jsonb | event-specific data |
| display | text | one-line human description for the timeline UI |

The Actions tab in the UI reads directly from this table.

### `ioc_records`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| incident_id | UUID FK | |
| ioc_type | enum('ipv4','ipv6','sha256','md5','sha1','domain','url','email') | |
| value | text | |
| first_seen_at | timestamptz | |
| excluded | bool default false | backs the "Excluded" toggle in the UI |
| tenant | text | customer name |

UNIQUE (incident_id, ioc_type, value).

### `ioc_enrichments`

| Column | Type | Notes |
|---|---|---|
| ioc_id | UUID FK | |
| source | text | virustotal / abuseipdb / otx / threatfox / ipinfo |
| verdict | text | clean / suspicious / malicious |
| score | int | 0-100 normalized |
| raw | jsonb | full triage.py output for that source |
| fetched_at | timestamptz | |

### `forensics_jobs`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| incident_id | UUID FK | NULL allowed (standalone forensics) |
| kind | enum('triage','static','dynamic') | `dynamic` is retained for **legacy rows only** — the endpoint is a 410 tombstone (no new dynamic jobs are created) |
| ioc_or_file | text | hash / IP / URL / path-on-disk |
| status | enum('queued','running','completed','failed') | |
| result | jsonb | |
| started_at, finished_at | timestamptz | |
| arq_job_id | text | ARQ task reference for retry/cancel |

### `webhook_sources`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| name | text | "QRadar CONTOSO" |
| hmac_secret_hash | text | bcrypt(secret) — secret shown once at creation |
| ip_allowlist | inet[] | optional |
| customer_default | text | applied to ingested alerts if missing |
| created_at, last_seen_at | timestamptz | |

### `auto_close_rules` (mirrored from YAML, editable in UI)

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| rule_id | text UNIQUE | e.g. `contoso-xforce-miui-known-ip` |
| customer | text | NULL = any |
| match | jsonb | conditions (rule_name, dst_asn, application, …) |
| verdict | enum('FP','benign') | |
| reason | text | English summary |
| enabled | bool | |
| source | enum('yaml','ui') | yaml-imported vs user-created |
| created_at, updated_at | timestamptz | |

A daily background job exports any `source='ui'` rule to the on-disk YAML so
the SKILL workflow continues to see them.

### `llm_calls`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| incident_id | UUID FK | NULL if not case-bound |
| model | text | virtual model name (`isoc-deep`) |
| provider | text | resolved at LiteLLM (`anthropic` / `openai` / `vllm`) |
| input_tokens, output_tokens | int | |
| cost_usd | numeric(10,4) | optional |
| latency_ms | int | |
| status | enum('ok','timeout','error') | |
| prompt_hash | text | sha256 of prompt — for dedup / cache |
| created_at | timestamptz | |

### `audit_log`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| user_id | UUID FK | NULL for system actions |
| action | text | `incident.create`, `verdict.set`, `auto_close_rule.edit`, … |
| target_type | text | `incident` / `auto_close_rule` / `user` / `webhook_source` |
| target_id | UUID | |
| diff | jsonb | before/after |
| ts | timestamptz | |

## Migrations

Alembic auto-generated from SQLAlchemy 2.0 models in `backend/isoc_api/db/models.py`.
First migration creates everything; subsequent migrations are versioned and reversible.

## Why Postgres + Qdrant (not just one)

| Concern | Postgres | Qdrant |
|---|---|---|
| Audit log, foreign keys, joins | ✅ | ❌ |
| Semantic search over alerts | ❌ | ✅ |
| Transactional updates | ✅ | ⚠️ limited |
| Multi-tenant filtering | ✅ | ✅ |
| Backup story | mature | mature |

Both are needed. The `incidents.qdrant_alert_id` column links a Postgres row to
its Qdrant payload so the two stores stay coherent.
