# ISOC / EKSIR — build plan (selected roadmap features)

> Companion to `docs/ROADMAP.md`. Ten features selected by the product owner, each
> grounded against the current code (mapped 2026-07-12). For each: what changes,
> exact files, schema, tests, UI, size, and risks.
>
> **Invariant preserved throughout:** the analyst Approve gate is the only commit point.
> Every feature here is read-only, proposal/recommendation-only, or an explicit
> analyst-gated action. Nothing adds autonomy.

> **Status (2026-07-20): historical planning record.** This is the pre-build plan.
> Eight of the ten features, plus both shared building blocks, have since shipped;
> only the two LLM-ops items (#9 persona registry, #10 model discovery) remain
> pending. Each section below carries a **Status:** line. `CHANGELOG.md` and
> `docs/ROADMAP.md` hold the authoritative shipped list.

| # | Feature | Status |
|---|---------|--------|
| 1 | Batch / historical import | Shipped (#98) |
| 2 | SLA 24/7 redesign + notifications (B1) | Shipped (#100, #101) |
| 3 | Product-security hardening (staged) | Shipped (3a #102, MFA + revocation #103) |
| 4 | STIX / CSV export of confirmed IOCs | Shipped (#104) |
| 5 | STIX/TAXII inbound feed | Shipped (#105) |
| 6 | SOC dashboard trends | Shipped (#106) |
| 7 | Branded automated reports + branding (B2) | Shipped (#107) |
| 8 | Case collaboration | Shipped (#109) |
| 9 | Data-driven persona registry | Pending |
| 10 | Provider model discovery + typed budgets | Pending |

---

## Grounding that applies to every feature

- **Schema on deploy:** `Base.metadata.create_all` in `db/session.py::init_db` is the
  real path (Alembic is vestigial: 0 real migrations, `0001` is a stub). So:
  - **New table** → just add the SQLAlchemy model. It is created on boot, serialized
    by the existing `pg_advisory_xact_lock(823641927)` so the `--workers 2` boot race is
    already handled.
  - **New column on an existing table** → `create_all` will NOT alter it. Add a
    `db/<name>_backfill.py` with `ADD COLUMN IF NOT EXISTS` and wire it into `init_db`
    (mirror `sla_backfill.py` / `add_queue_columns`).
- **Tests:** `backend/tests/`, pure unit style (no Postgres/Redis/LLM). Unit-test the
  pure `build_*` / helper functions, not DB integration. `asyncio_mode=auto`.
- **Frontend:** Next.js client pages + typed helpers in `frontend/lib/api.ts` (Bearer
  token from localStorage + `X-Tenant-Scope`). Charts already use **recharts 2.15.0**.
- **After any backend change:** `cd deploy && docker compose build backend worker && up -d`
  (source is baked into the image, not host-mounted).

## Two shared building blocks (build once, reused)

These are not on the roadmap by name but fall out of the analysis. Building each once
removes duplicate work from several features.

- **B1 — Notifications substrate.** _Shipped with #100 / #109._ There is no in-app notification system today; the
  only outbound path is `mailer.py::send_html_email` for customer case emails. A minimal
  `notifications` table (recipient user, kind, title, link, read_at) + a tiny
  `routes/notifications.py` (list / mark-read) + a bell in the top bar. Reused by **SLA
  breach alerting** and **case @mentions/watchers**. Build it inside whichever ships
  first (SLA), then the other reuses it.
- **B2 — Tenant branding/asset store.** _Shipped with #107._ A per-tenant logo (PNG) + accent color, stored
  as a `tenant_branding` row (or columns on `Tenant`). Reused by **branded reports** and,
  later, the customer-case notification template (which today has a `⬡` glyph, no logo).

---

## Suggested build order

Ordered by value ÷ effort, dependency, and "needed before you expose the product." Size
is relative complexity (S/M/L), not a time estimate.

| # | Feature | Phase | Size | Why here |
|---|---------|-------|------|----------|
| 1 | **Batch / historical import** | A · momentum | M | Biggest ingestion gap; testable now with zero external API; extends the existing `alerts.upload`. High value, self-contained. |
| 2 | **SLA 24/7 redesign** (+ B1 notifications) | A · momentum | S–M | High MSSP value, small effort now that we know it's already wall-clock. Carries the shared notifications substrate. |
| 3 | **Security hardening** (staged) | B · before exposure | S→L | Default JWT secret is `change-me-dev-only`; do the S tier (secret + headers) before any customer sees it. MFA/revocation follow. |
| 4 | **STIX / CSV export of confirmed IOCs** | C · intel | S | Trivial quick win; turns ISOC into a producer. Independent. |
| 5 | **STIX/TAXII inbound feed** | C · intel | M | New feed `format` branch, reuses the existing upsert + read path. Needs a new dep. |
| 6 | **SOC dashboard trends** | C · reporting | M | Build the per-source / per-tenant time-series first so reports can embed the same aggregations. |
| 7 | **Branded automated reports** (+ B2 branding) | C · reporting | L | Heaviest: PDF engine + template model + logo + scheduler. Reuses #6's aggregations and B2 branding. |
| 8 | **Case collaboration** (reuses B1) | D · collaboration | M | Comments/watchers mirror `TimelineEvent`; @mention notifications reuse B1. |
| 9 | **Data-driven persona registry** | D · LLM ops | M–L | Valuable (tune prompts without a rebuild) but touches TWO consumption sites — do carefully. |
| 10 | **Model discovery + typed budgets** | D · LLM ops | S | Small polish on the same admin-LLM surface as #9; ship together. |

Rationale for the phase split: **A** gives fast, self-contained wins that need no live
vendor tenant. **B** is the "safe to expose" gate — invisible but a prerequisite if the
product goes in front of customers. **C** is the customer-facing deliverable stack (intel
+ dashboards + reports), ordered so each reuses the last. **D** is internal polish.

---

## Feature plans

### 1. Batch / historical import

**Status: Shipped (#98).** `POST /api/v1/ingest/batch` + the Sources **Import** tab.

**Goal.** Upload or point at a file (JSONL / CSV / Parquet / S3 folder); stream each
record through the same parser + field-map + normalizer the pull spine uses, landing each
as a `RECEIVED` incident.

**Key insight from grounding.** Not greenfield. `routes/alerts.py::upload` (L60–124)
already does NDJSON/JSON batch under `IngestSource.FILE`. Parsing/field-map/normalize all
happen at *pipeline* time (`_step_parse`), so batch only has to land correct `RECEIVED`
rows. A `preview` endpoint (`routes/connectors.py:334`) already runs the dry-run parse.

**Backend.**
- Extract a shared `create_received_incident(payload, ingest_source)` helper from the
  duplicated `worker._create_pull_incident` (L434) / `alerts.upload` loop — one place that
  builds `Incident(status=RECEIVED, raw_payload={text, source_hint, original, field_map, pull})`
  and enqueues `pipeline_run`.
- Add `IngestSource.BATCH` enum value.
- New readers keyed by file type: JSONL (exists), CSV (`stdlib csv`), Parquet (**new dep
  `pyarrow`**), S3 folder (**new dep `boto3`**, list + stream objects). Each yields raw
  records into the shared helper. Stream, don't load whole files.
- Reuse the existing per-source field-map (`field_map.apply_field_map`) and Redis `SET NX`
  dedup so re-import is idempotent.
- New route `POST /api/v1/ingest/batch` (multipart upload or `{source_id, path/s3_uri}`)
  → enqueue an ARQ job `batch_import` that streams + creates rows, updating a progress row.

**Schema.** `import_jobs` table (id, tenant_id, source_id, filename/uri, total, processed,
failed, status, created_at). New table → auto-created on boot.

**Frontend.** New **Import** tab on `frontend/app/admin/sources/page.tsx`: drag-a-file /
paste-a-path → dry-run preview of the first N parsed records (reuse the `preview` endpoint)
→ Start → a progress bar polling the `import_jobs` row. Add `api.connectors.sources.import*`.

**Tests.** Pure: CSV/Parquet record → `PulledAlert` mapping; dedup key stability;
field-map application. Mirror `test_ingest_pull.py` / `test_field_map.py`.

**Size / risk.** M. Risk: Parquet/S3 deps add image weight; keep readers lazy-imported so
a missing dep can't break module import (the EASM `recon_adapter` pattern).

---

### 2. SLA 24/7 redesign (+ notifications substrate B1)

**Status: Shipped (#100, #101).** Response + resolution targets per severity, a breach
scan, the in-app notifications substrate (B1), and assignee / "Assign to me". Per-tenant
business-hours windows remain the one deferred sub-item.

**Goal.** 24/7 wall-clock SLA with **response** and **resolution** targets per severity,
**per-tenant** overrides, and **breach alerting**. Business-hours becomes an optional,
off-by-default per-tenant mode.

**Key insight from grounding.** The clock is *already* 24/7 wall-clock UTC per severity
(`pipeline/sla.py`: `DEFAULT_TARGET_MINUTES` crit 60 / high 240 / med 1440 / low 4320,
elapsed = `closed_at − created_at`). There is **no business-hours logic to undo**. Gaps:
only resolution is targeted (no response target/metric), targets are **global** (`SLATarget`
PK = severity alone), and breaches are reported but never alerted.

**Backend.**
- `SLATarget`: add `tenant_id` (nullable = global default) → composite key
  `(severity, tenant_id)`; add `response_target_minutes` alongside `target_minutes`
  (rename the latter conceptually to "resolution"). Column adds → `sla_backfill.py` +
  a partial unique index for the NULL-tenant global row (mirror the RBAC/global pattern).
- **Response metric:** anchor on the `acknowledged` SLA event (already emitted at queue
  claim, `queue.py:190`); response_time = `first(acknowledged|resolved) − created_at`.
  Extend `pipeline/sla.py` pure helpers (`resolution_seconds` → add `response_seconds`,
  `is_breached` → take both targets) and `build_sla_dashboard` to report both dimensions.
- **Breach alerting:** new ARQ periodic job `sla_breach_scan` (every ~5 min) that finds
  open incidents past — or within 25% of — their response/resolution target and emits a
  **notification** (B1) to the assignee + tenant watchers. Idempotent (don't re-alert;
  store `alerted_at` on the incident or a dedup key in Redis).
- **Optional business-hours mode:** per-tenant `business_hours` JSONB (tz, windows,
  holidays) + `enabled` flag, default OFF. When on, `resolution/response_seconds`
  subtract out-of-window time. Ships last, behind the flag, so 24/7 stays the default.

**Schema.** `SLATarget` +2 columns + tenant scoping; `notifications` table (B1).

**Frontend.** `frontend/app/sla/page.tsx`: per-tenant target editor with **two** columns
(response + resolution), a breach-report view, and timers showing response vs resolution
state. Add a top-bar notification bell (B1). `api.sla.*` gains per-tenant target save.

**Tests.** Pure: `response_seconds` / dual-target `is_breached` at boundaries; breach-scan
selection logic; business-hours subtraction (fixed `NOW`). Mirror `test_sla_dashboard.py`.

**Size / risk.** S–M. Risk: defining the response anchor when an incident is worked
without a queue claim — fall back to first analyst action or verdict time.

---

### 3. Product-security hardening (staged)

**Status: Shipped (#102, #103).** Stage 3a (weak-secret boot guard, security headers,
CORS lockdown) in #102; stage 3b MFA (TOTP) and stage 3c fail-closed token revocation in
#103. Session-fingerprinted JWT is the remaining follow-up.

**Goal.** Move from "works locally" to "safe to expose." Staged so value lands early.

**Key insight from grounding.** JWT is PyJWT HS256, claims `sub/role/iat/exp/iss`, TTL 60m,
**secret defaults to `change-me-dev-only`**, no refresh, fully **stateless** (logout is a
no-op; a live token cannot be revoked). Tokens live in `localStorage` + Bearer header (not
cookies), so **CSRF is not a current exposure** — do not add cookie auth casually or you
*introduce* it. No security headers anywhere; Caddy is a bare `reverse_proxy`.

**Stage 3a (S) — do first, before exposure.**
- Fail-closed on a weak secret: refuse to boot in non-dev if `jwt_secret ==
  change-me-dev-only` (or is short). One check in `settings.py` / app startup.
- Security headers: add HSTS, CSP, X-Frame-Options=DENY, X-Content-Type-Options=nosniff,
  Referrer-Policy in the Caddyfile (`config/Caddyfile`) and/or a FastAPI middleware.
- Verify the client-controlled `X-Tenant-Scope` header is validated server-side against
  membership (it appears to be, via `require_in_scope`) — if any route trusts it blindly
  that is a horizontal-access bug. Audit and lock down.
- Tighten CORS `allow_origin` for the deployed origin (today localhost-only regex).

**Stage 3b (M) — MFA (TOTP).**
- `User` +`totp_secret` (Fernet-encrypted) +`mfa_enabled`. New dep **`pyotp`**.
- `routes/auth.py`: `/mfa/enroll` (returns provisioning URI → QR on the client),
  `/mfa/verify`, and a second factor step in `login` when `mfa_enabled`.
- Frontend: MFA enrollment in user settings; a code step on the login page.

**Stage 3c (M) — fail-closed revocation.**
- Add a `jti` claim + a `token_version` int on `User` (or a small denylist table). Reject
  when `jti` is revoked or `token_version` mismatches. `/logout` and "revoke sessions"
  bump the version. Keeps the stateless model but makes revocation real.

**Schema.** `User` +3 columns (backfill); optional `revoked_tokens` table.

**Tests.** Pure: weak-secret guard; TOTP verify window; token-version reject. Extend
`test_rbac.py` style.

**Size / risk.** S → L across stages. Risk: don't switch to cookie auth (introduces CSRF);
keep Bearer + add revocation instead.

---

### 4. STIX / CSV export of confirmed IOCs

**Status: Shipped (#104).** `GET /api/v1/threat-intel/export?format=stix|csv`.

**Goal.** Read-only export of analyst-confirmed indicators → ISOC becomes an intel producer.

**Key insight from grounding.** "Confirmed" is not a field on the feed store. It is
`IOCRecord` (per-incident) joined to `Incident WHERE verdict='TP' AND excluded=false`.
That join is the export source.

**Backend.**
- New route `GET /api/v1/threat-intel/export?format=stix|csv&window=…&tenant=…`.
- CSV: `stdlib csv` (no dep). STIX 2.1 bundle: **new dep `stix2`** — map each IOC to an
  `Indicator` SDO with a STIX pattern (`[ipv4-addr:value = '…']`, `file:hashes`, etc.).
- Tenant-scoped through the incident join; respects exclusions.

**Schema.** None.

**Frontend.** An **Export** button on the `threat-iocs` page (dropdown: STIX / CSV, window).

**Tests.** Pure: IOC row → STIX pattern string per type; CSV row shape; TP+excluded filter.

**Size / risk.** S. Deprioritized by you in 2026-07, but it is cheap and pairs with #5.

---

### 5. STIX/TAXII inbound feed ingestion

**Status: Shipped (#105).** A `format: "taxii"` feed branch in `threat_intel/sync.py`
(`_fetch_taxii` + `stix_parse.indicators_to_iocs`) reusing the existing upsert path.

**Goal.** Pull commercial/ISAC intel automatically into the local feed store enrichment
already reads — a new *producer*, no pipeline change.

**Key insight from grounding.** Feeds are already table-driven (`threat_feeds`), and
`sync.py::_sync_one` dispatches on `ThreatFeed.parser_config` JSONB (`format: csv|lines`).
Adding a `format: "taxii"` branch that maps STIX indicators → `(ioc_type, value)` and reuses
the **same `_UPSERT_SQL`** leaves `threat_iocs` and the whole read/scoring path unchanged.

**Backend.**
- New dep **`taxii2client`** (+ `stix2` from #4 for parsing).
- `_sync_one`: add the `taxii`/`stix` branch — fetch a collection, page through, parse
  STIX `Indicator` patterns into IOCs, run through `_UPSERT_SQL` (append-source-if-missing).
- Config (server URL, collection id, auth) lives in `parser_config` → **no model change**.
- Extend the `kind_hint` validation in `routes/threat_intel.py` (L163/197) if new IOC kinds
  appear.

**Schema.** None (config in existing JSONB).

**Frontend.** `FeedsPanel` on the `threat-iocs` page gains a "TAXII" feed type with
server/collection/auth fields. Matched IOCs then surface in enrichment exactly as today.

**Tests.** Pure: STIX pattern → `(ioc_type, value)` extraction; parser_config dispatch.

**Size / risk.** M. Risk: TAXII auth/paging variance across providers; start with one
(e.g. an OTX or MISP TAXII endpoint) and generalize.

---

### 6. SOC dashboard trends

**Status: Shipped (#106).** MTTR p50/p90 percentiles + per-source / per-verdict
time-series.

**Goal.** MTTR, alert volume, verdict mix, and **per-source / per-tenant** trends over time
for a manager-at-a-glance view.

**Key insight from grounding.** A lot already exists: `dashboard.py::stats` already buckets
with `date_trunc` (`verdict_series`, `sla_trend`, `fp_rate_trend`, etc.). Gaps: **MTTR is a
plain AVG, not percentiles**; **per-source trends do not exist** (`top_rules`/`source_product`
are counts, never time-bucketed); `mssp`/`analytics` are point-in-time.

**Backend.**
- Extend the pure aggregation in `dashboard.py` (and/or a new `analytics/trends.py`) with:
  MTTR p50/p90 (percentile, not AVG), per-source volume-over-time, per-tenant verdict mix
  over time. All `date_trunc` GROUP BYs, tenant-scoped.
- Keep them pure `build_*` functions for unit testing.

**Schema.** None.

**Frontend.** New recharts panels on `app/dashboard` (and a per-tenant breakdown on
`app/mssp`): stacked verdict-mix area, per-source line chart, MTTR percentile bands. Chart
colors already tokenized.

**Tests.** Pure: percentile math; per-source bucketing; empty-window fallback. Mirror
`test_cost_dashboard.py`.

**Size / risk.** M. Low risk (read-only aggregation). Do before #7 so reports embed these.

---

### 7. Branded automated per-customer reports (+ branding B2)

**Status: Shipped (#107).** HTML + PDF (WeasyPrint), tenant branding (B2), built-in
templates, cron generates to DRAFT only, analyst-gated send.

**Goal.** Scheduled/on-demand tenant reports with **reusable templates**, the **customer's
logo/PNG**, and **our SOC brand/theme** baked in.

**Key insight from grounding.** Heaviest feature. Today `routes/reports.py` returns **JSON +
CSV only** — no HTML, no PDF, no report model, nothing scheduled. But **Jinja2 already
exists** (`templates/__init__.py`, used for case emails) and `customer_cases.py::_render_case_html`
is the branded-HTML precedent. No PDF library anywhere. No logo dir in `frontend/public/`.

**Backend.**
- **Branding (B2):** `tenant_branding` (tenant_id, logo bytes/path, accent color) + upload
  endpoint. Logo embedded as a data-URI or served asset.
- **Report templates:** `report_templates` table (name, tenant_id nullable, sections config,
  Jinja body). Start with 2–3 built-in templates in code (exec summary / monthly ops / IOC
  digest), editable per tenant later.
- **Render engine:** assemble report data (reuse #6 aggregations + monthly_summary) → Jinja
  HTML (SOC theme + customer logo header) → **PDF via new dep `weasyprint`** (HTML/CSS →
  PDF, matches the existing HTML approach; alt `playwright` if CSS fidelity needs it).
- **Scheduler:** ARQ cron `report_generate` per tenant schedule → renders to a
  `generated_reports` row (status draft). **Respect the gate philosophy:** the scheduler
  *generates to review*, it does not auto-email customers. Delivery is an explicit
  analyst-gated Send (reuse the case `send` path), unless a tenant sets an "auto-send" flag.

**Schema.** `tenant_branding`, `report_templates`, `report_schedules`, `generated_reports`
(all new tables → auto-created).

**Frontend.** `app/reports/page.tsx`: template picker + logo upload + a **Schedule** control
+ a delivery/history list with Preview (HTML) and Download (PDF) and a gated Send.

**Tests.** Pure: report-data assembly; template section selection; schedule-due calc.
(PDF render itself is integration — smoke-test HTML output shape.)

**Size / risk.** L. Risks: `weasyprint` has native deps (add to the backend Dockerfile,
like `nmap` for EASM); auto-send to customers must stay opt-in/gated to honor the invariant.

---

### 8. Case collaboration (reuses notifications B1)

**Status: Shipped (#109).** Case comments, @mentions (in-app + email), and watchers.

**Goal.** Threaded comments, @mentions, and watchers on customer cases so the case is the
record of record.

**Key insight from grounding.** Comments should mirror `TimelineEvent` (append-only child,
CASCADE, JSONB payload); watchers mirror the `CustomerCaseIncident` join-table shape. The
current user is resolved via `require_analyst`; `User` has `full_name` (no `name`) for
authors/mentions. **No notification system** — @mentions need B1.

**Backend.**
- `case_comments` (case_id FK CASCADE, author_id FK SET NULL, body Text, mentions JSONB,
  created_at) — mirror `TimelineEvent`.
- `case_watchers` join (case_id, user_id, UNIQUE) — mirror `CustomerCaseIncident`.
- `routes/customer_cases.py`: `POST /{id}/comments` (parse `@name` → mention user ids →
  emit B1 notifications + auto-add mentioned users as watchers), `GET /{id}/comments`,
  watcher add/remove. Auto-watch on comment. Reuse `audit.log` as the routes already do.

**Schema.** Two new tables (auto-created).

**Frontend.** A comment-thread panel on `app/cases/[id]/page.tsx` beside `<AttachedIncidents>`
with mention autocomplete (over the tenant's users) and a watcher list. `api.cases.comments.*`.

**Tests.** Pure: `@mention` parse → user-id resolution; watcher auto-add dedup.

**Size / risk.** M. Risk: mention email (vs in-app only) — start in-app via B1, reuse
`mailer.py` for email as a follow-up.

---

### 9. Data-driven persona registry

**Status: Pending.** Not built; persona prompts still live as constants in
`llm/prompts.py`.

**Goal.** Move persona prompt *content* out of `llm/prompts.py` into editable data, with
per-tenant overrides. Keep the fixed L1→L2→hunt→forensics→manager topology in code.

**Key insight from grounding.** The prompts (`L2_SYSTEM`, `HUNT_SYSTEM`, `FORENSIC_SYSTEM`,
`MANAGER_CHAT_SYSTEM`, `FAST_CLASSIFIER_SYSTEM`) are consumed at **two mirrored sites** —
`pipeline/synthesis_steps.py` (langgraph path) and `pipeline/orchestrator.py` (legacy inline
`_step_synthesis`) — plus `manager_chat.py`. Both sites must be swapped or they drift.
`config_store.py` (DB singleton + 60s cache + `invalidate_cache`) and the BYOK per-tenant
pattern (`byok_store.py`, `TenantLLMCredential` PK=tenant_id) are the exact shapes to mirror.

**Backend.**
- `persona_prompts` table (persona key, tenant_id nullable = global default, system_text,
  updated_by, version) — content is non-secret, so skip Fernet; reuse the cache+TTL shape.
- `llm/persona_store.py`: `get_persona(key, tenant_id)` → tenant override → global → the
  in-code constant as the ultimate fallback (never break the pipeline). Cache + invalidate.
- **Swap both consumption sites** to call `get_persona(...)` instead of importing the
  constant. Seed the table from the current constants so behaviour is identical on day one.
- Keep `contracts.py` output parsing unchanged (editing content can't change topology).

**Schema.** `persona_prompts` (new table).

**Frontend.** A prompt editor in `app/admin/settings` (persona tabs, per-tenant selector,
textarea) with a **diff-from-default** view and a "reset to default" button.

**Tests.** Pure: resolver precedence (tenant → global → code fallback); seed idempotency.

**Size / risk.** M–L. Risk (the big one): the **dual consumption sites**. Missing one means
edits silently apply on only one code path. Add a test asserting both call `get_persona`.

---

### 10. Provider model discovery + typed budgets

**Status: Pending.** Not built; the admin model field is still free-text.

**Goal.** Replace the free-text model field with a live provider model list (behind the SSRF
guard) and add per-model budget caps.

**Key insight from grounding.** `model_name` is a plain `<input>` at
`app/admin/settings/page.tsx:217`. Per-call resolution is `_resolve_call` (tenant BYOK →
admin DB → env). Budgets live in `pipeline/budget.py` (`cap_reason`, daily/incident caps).

**Backend.**
- `routes/admin.py`: `GET /llm/models` → call the provider's `/models` endpoint through
  `url_safety.assert_endpoint_url` (SSRF guard already used on the config endpoint), cache
  the list in `config_store` (short TTL).
- Per-model typed budget: extend `budget.py` with a per-model cap keyed on the resolved
  `effective_model`, checked after model selection in `_resolve_call` / `complete`.

**Schema.** Optional `model_budgets` (model, daily_cap, incident_cap) or a JSONB on the
LLM config row.

**Frontend.** Swap the free-text model input for a populated dropdown (fetched from
`/llm/models`) + a per-model budget input. Same admin settings page as #9 — ship together.

**Tests.** Pure: budget-cap selection per model; graceful fallback when discovery fails
(keep manual entry as a fallback so a provider without `/models` still works).

**Size / risk.** S. Low risk; degrade to the current free-text field if discovery fails.

---

## Cross-cutting risks & notes

- **Dual-write in the pipeline (feature 9).** The persona registry is the only feature that
  touches the hot synthesis path twice; everything else is additive/read-only. Treat it as
  the highest-care item and test both code paths.
- **New native deps** land in the backend Dockerfile runtime stage (precedent: `nmap` for
  EASM): `weasyprint` (reports), and pure-Python `pyarrow`/`boto3`/`pyotp`/`stix2`/
  `taxii2client` in `pyproject.toml`. Lazy-import optional ones so a missing dep can't break
  module import.
- **Outbound actions stay gated.** Report auto-send and SLA/mention notifications are the
  only features that send anything. Reports send is analyst-gated (reuse case `send`);
  notifications are internal-to-SOC (in-app first, email opt-in). No feature auto-touches a
  customer or a customer's console without an analyst check.
- **No Alembic.** Every schema change is a model add (table) or a `*_backfill.py` (column).
  Do not author migrations expecting them to run.
