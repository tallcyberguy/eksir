# EKSIR HTTP API (partial / preview reference)

> **Scope note:** this file documents the endpoints an integrator reaches for
> first (auth, incidents, ingest, forensics, admin, dashboard). It is **not**
> exhaustive: the running service ships many more router areas (listed at the
> bottom). The **authoritative, always-current surface is the live OpenAPI spec**
> at `/docs` (Swagger UI), `/redoc`, and `/openapi.json`. When this file and the
> spec disagree, the spec wins.

Base URL: `/api/v1` (frontend), `/v1` (webhook ingest — no auth prefix).
Auth: Bearer JWT (`Authorization: Bearer <token>`) except for `/v1/ingest`
(HMAC-signed) and `/api/v1/auth/login`.

## Auth

```
POST   /api/v1/auth/login              { email, password }            → { token, user }
POST   /api/v1/auth/refresh                                            → { token }
GET    /api/v1/auth/me                                                 → { user, role }
POST   /api/v1/auth/logout                                             → 204
```

## Incidents / Cases

```
GET    /api/v1/incidents
       ?status&severity&verdict&customer&q&sort&page&page_size         → paginated list
                                                                         (each row carries
                                                                          confidence_score /
                                                                          threat_score, 0-100)
GET    /api/v1/incidents/{id}                                          → full incident
                                                                         (+ enrichment.scores
                                                                          with contributions)
PATCH  /api/v1/incidents/{id}                                          → partial update
                                                                         (verdict, assignee,
                                                                          status, severity,
                                                                          analyst_notes,
                                                                          verdict_reason,
                                                                          handoff_note)
POST   /api/v1/incidents/{id}/assign     { assignee_id }               → claim / reassign
POST   /api/v1/incidents/{id}/regenerate-report                        → re-run synthesis
POST   /api/v1/incidents/{id}/approve   { verdict?, approve_action_ids?, notes? }
                                        → commit verdict (→ Qdrant) + run checked actions
POST   /api/v1/incidents/{id}/reject    { reason, requeue? }
                                        → clear proposal; requeue=true re-runs synthesis
POST   /api/v1/incidents/{id}/manager   { message }
                                        → converse with the Incident Manager at the gate
                                          (revise proposal / re-task hunt|forensics)
GET    /api/v1/incidents/{id}/timeline                                 → events list
GET    /api/v1/incidents/{id}/iocs                                     → IOC table
POST   /api/v1/incidents/{id}/iocs/exclude
                                        { ioc_type, value, scope?, notes? }
                                        → add the IOC to the exclusion list
                                          (scope: "customer" default | "global")
POST   /api/v1/incidents/{id}/archive                                  → soft delete (hide)
POST   /api/v1/incidents/{id}/restore                                  → un-archive
DELETE /api/v1/incidents/{id}                                          → hard delete
```

> **Notes are set through `PATCH /incidents/{id}`** (the `analyst_notes`,
> `verdict_reason`, and `handoff_note` fields). There is **no** `POST
> /incidents/{id}/timeline` — the timeline is read-only over HTTP (`GET`); the
> pipeline and the gate endpoints write its events server-side.

> **Human gate** (`require_analyst`): `/approve`, `/reject`, and `/manager` apply
> when an incident is parked at `awaiting_signoff` — the agent pipeline's manager
> has proposed a verdict + response actions and is awaiting sign-off. The manager
> and personas only *propose*; `/approve` is the **only** call that commits a
> verdict (→ Qdrant) or fires a response action. Response actions are
> **provider-aware**: each proposed action carries its own `provider`, so approving
> it dispatches to **Trend Micro Vision One** or **Microsoft Defender** depending on
> where the alert came from (isolate / scan / blocklist / disable-user + verdict
> write-back). `PATCH` still sets a verdict directly for legacy/manual close.
> See `docs/PIPELINE.md`.

### Live updates (transport)

There is **no WebSocket / SSE transport.** The UI keeps an incident view fresh by
**HTTP polling** on a ~3.5s interval:

```
GET    /api/v1/incidents/{id}            → current status + enrichment + proposal
GET    /api/v1/incidents/{id}/timeline   → the per-stage progress events
                                           (<step>_running / <step>_done / <step>_skipped)
```

The pipeline advances asynchronously in the ARQ worker; the client re-fetches
these two GETs until the incident reaches a terminal or gate state
(`awaiting_signoff`, auto-closed, etc.). Integrators should poll the same way.

## Manual ingest (paste)

```
POST   /api/v1/alerts/paste            { raw_text, customer?, source_hint?, severity? }
                                       → { incident_id, case_number, status }
```

Returns one `IngestResponse`. The server creates the incident and kicks off the
ARQ pipeline asynchronously; poll `GET /incidents/{id}` (see "Live updates") for
progress.

## File ingest

```
POST   /api/v1/alerts/upload           multipart/form-data: file (json | ndjson),
                                                          customer?,
                                                          source_hint?
                                       → [ { incident_id, case_number, status }, … ]
```

Returns a **list** of `IngestResponse` — one per record parsed from the file
(a JSON array or ndjson yields many; a single JSON object yields one). Each row
is enqueued to the pipeline independently.

> **Bulk / historical import** is a separate surface under `/api/v1/ingest`
> (the `batch_import` router): `POST /api/v1/ingest/batch/upload`,
> `POST /api/v1/ingest/batch/path`, and `GET /api/v1/ingest/batch/jobs[/{id}]`
> for large backfills tracked as `import_jobs`. It is distinct from the
> interactive `/alerts/upload` above.

## Webhook ingest (machine-to-machine)

```
POST   /v1/ingest/{source_id}
Headers:
  X-EKSIR-Signature: <HMAC-SHA256 of "timestamp.body", hex>
  X-EKSIR-Timestamp: <unix seconds>     (rejected outside the skew window, ~5min)
Body: any JSON (vendor-shaped) OR ndjson for batches
                                       → [ { incident_id, case_number, status }, … ]
```

Returns a **list** of `IngestResponse` (one per record). Signature recipe:

```
sig = hmac_sha256(secret, timestamp + "." + body_bytes).hex()
```

`{source_id}` is the id of a webhook source registered under
`/api/v1/admin/webhook-sources` (its HMAC secret is shown once at creation).

## Forensics

Static-only. Dynamic/behavioral detonation was removed by design (shared-container
detonation is unsafe for hostile samples).

```
POST   /api/v1/forensics/triage         { ioc, type? }                 → { job_id, … }
POST   /api/v1/forensics/static         multipart: file                → { job_id, … }
POST   /api/v1/forensics/dynamic                                       → 410 GONE  (tombstone)
GET    /api/v1/forensics/jobs/{job_id}                                 → status + result
GET    /api/v1/forensics/jobs?kind&status&incident_id                  → list
GET    /api/v1/forensics/jobs/{job_id}/report.md                       → analyst report (markdown)
```

> `POST /forensics/dynamic` is retained only as a **410 Gone tombstone** so legacy
> clients fail loudly instead of queuing against a path that no longer runs. For
> dynamic analysis, integrate an **external VM-isolated sandbox** (Hybrid Analysis,
> any.run, Triage, Joe Sandbox) via its own API. Historical `dynamic` job rows
> stay queryable through `GET /forensics/jobs`.

## Admin

```
GET    /api/v1/admin/users
POST   /api/v1/admin/users              { email, role, password }
PATCH  /api/v1/admin/users/{id}
DELETE /api/v1/admin/users/{id}

GET    /api/v1/admin/webhook-sources
POST   /api/v1/admin/webhook-sources    { name, customer_default?, ip_allowlist? }
                                        → { id, secret_shown_once }
DELETE /api/v1/admin/webhook-sources/{id}

GET    /api/v1/admin/auto-close-rules
POST   /api/v1/admin/auto-close-rules   { rule_id, customer?, match, verdict, reason }
PATCH  /api/v1/admin/auto-close-rules/{id}
DELETE /api/v1/admin/auto-close-rules/{id}
POST   /api/v1/admin/auto-close-rules/export-yaml   → writes auto_close_rules.yaml

GET    /api/v1/admin/llm-backends                       → list virtual model mappings
GET    /api/v1/admin/llm-usage?from&to                  → token + cost report
GET    /api/v1/audit?actor&action&from&to               → audit trail
```

## Dashboard

```
GET    /api/v1/dashboard/stats          ?window=24h|7d|30d|90d
                                        → totals, status breakdown, severity breakdown,
                                          monthly cases/incidents series, FP/TP series
GET    /api/v1/dashboard/unique-iocs    ?window
                                        → count distinct IOCs in window
```

## Other shipped router areas (see `/docs` for full detail)

The service mounts these additional routers under `/api/v1` (plus the
webhook ingest at `/v1/ingest`). They are omitted above only to keep this
reference focused — each is documented in the live OpenAPI spec:

`connectors`, `entities`, `hunt`, `easm`, `exclusions`, `threat-intel`,
`knowledge-base`, `mitre`, `attack-graph`, `customer-cases`, `reports`,
`notifications`, `shifts`, `sla`, `queue`, `analytics`, `copilot`, `autonomy`,
`rbac`, `mssp`, `costs`, `admin/byok`, `dashboard-layout`, and the provider
operations/actions surfaces `v1ops` / `v1actions` (Vision One) and
`defenderops` / `defenderactions` (Microsoft Defender), plus the batch/historical
`ingest` router noted above.
