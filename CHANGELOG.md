# Changelog

All notable changes to EKSIR are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## How to use this file

- **Every user-visible change gets a line.** UI features, breaking API changes,
  schema migrations, deploy procedure changes, security fixes.
- **No line for**: refactors that don't change behavior, internal comments,
  dependency bumps unless the bump fixes a CVE (Dependabot PRs are tracked
  on GitHub separately).
- Active work goes under `## [Unreleased]` at the top.
- When cutting a release: rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`,
  create a new empty `[Unreleased]` block, tag the commit, push the tag,
  optionally `gh release create vX.Y.Z` for a GitHub release page.

### Version policy

| Change | Bump |
|---|---|
| Breaking API change, breaking DB migration (manual step required) | **MAJOR** (1.x.x) |
| New feature, additive endpoint, new dashboard panel | **MINOR** (x.1.x) |
| Bug fix, internal hardening, dependency update | **PATCH** (x.x.1) |

Pre-1.0 (current): we allow breaking changes in minor versions and note them
explicitly. Once we tag 1.0, the table above is binding.

---

## [Unreleased]

_Nothing yet; add lines here as work lands._

---

## [0.2.0] - 2026-07-20

Second release, and the first public, open-source cut under Apache-2.0.
Everything below shipped since 0.1.0. The headline is the agent-persona
synthesis pipeline (L1 → L2 → hunt? → forensics? → manager) that parks every
uncertain alert at a human sign-off gate, wrapped in pull-based ingestion, a
durable connector framework, and deep Vision One + Microsoft Defender
integrations. Invariant held throughout: the analyst Approve gate is the only
point that writes a verdict or fires a response action.

### Added

#### Agent-persona synthesis and the human gate (#63)
- Persona synthesis pipeline: a fast L1 classifier, deep L2 synthesis (markdown
  report plus a fenced `AnalysisVerdict` block, may call read-only tools),
  conditional hunt and forensic reasoning personas, and a deterministic manager
  stage that parks at `AWAITING_SIGNOFF`. Verdict stays PENDING until sign-off.
- Conversational manager chat at the gate: revises the proposed verdict and
  actions and re-tasks the hunt/forensic personas with an analyst directive.
  Proposes only, never commits.
- Read-only deep-tier tool calling (`ISOC_ENABLE_LLM_TOOLS`, default off), for
  example `lookup_ioc_history`.

#### Multi-tenant EDR/XDR integrations (ADR-0003, #63)
- Per-customer API-key store (Integration store) with admin management;
  credentials resolve by (provider, incident customer).
- Customer-case promotion plus branded email notifications with a structured
  threat-intel table.
- External attack surface (EASM) recon, MITRE ATT&CK coverage and attack-graph
  views, MSSP tenant rollup, and an analyst shift board.

#### Confidence / threat scoring (#80, #87, #115)
- Fused 0-100 `confidence` and effective-`threat` scores (`pipeline/scoring.py`
  → `enrichment['scores']`): effective threat is inherent × P(malicious), so a
  confident false positive sinks. The LLM band is a prior capped at 0.75; hard
  corroboration adds on top with contradiction penalties. Surfaced as chips on
  the incident list and tiles on the detail Sidecar.
- The vendor's own risk score (Vision One) feeds inherent threat (#115).

#### Pull-based ingestion and the Sources page (#90-#96)
- Pull spine: `ingest_sources` plus a `pull_ingest` cron plus an adapter
  registry, with a **Sources** admin page.
- Pull adapters and parsers for Vision One, SentinelOne, CrowdStrike, and
  Microsoft Defender.
- OAuth client-credential support in the Integration store (#93).
- Config-driven field mapping (#95) and per-source observability, health, and
  stale detection (#96).
- SSRF / URL-safety guard and fail-safe LLM cost caps (#91).

#### Batch / historical import (#98)
- `POST /api/v1/ingest/batch` plus an **Import** tab on the Sources page: stream
  JSONL / CSV / Parquet / S3 records through the same parser + field-map +
  normalizer into `RECEIVED` incidents. Idempotent via Redis dedup; progress
  tracked in an `import_jobs` row.

#### 24/7 SLA and the notifications substrate (#100, #101)
- Response and resolution targets per severity (24/7 wall-clock), an
  `sla_breach_scan` job, and an in-app notifications table plus a top-bar bell.
- Assignee column and "Assign to me" bulk action; assignment stamps the SLA
  response anchor.

#### Security hardening and MFA (#102, #103)
- Stage 3a: fail-closed weak-secret boot guard, security headers (HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy), and CORS lockdown.
- MFA (TOTP) enrollment and verification, plus fail-closed token revocation
  (`jti` claim + per-user `token_version`).

#### Threat-intel producer and inbound (#104, #105)
- STIX 2.1 / CSV export of analyst-confirmed IOCs
  (`GET /api/v1/threat-intel/export`), tenant-scoped and respecting exclusions.
- STIX/TAXII inbound feed ingestion: a new `taxii` feed format that upserts
  STIX indicators into the existing local feed store.

#### SOC trend analytics and branded reports (#106, #107)
- Dashboard trend analytics: MTTR p50/p90 percentiles and per-source /
  per-verdict time-series.
- Branded scheduled per-customer reports rendered to HTML plus PDF (WeasyPrint):
  slide-per-page layout, tenant logo/accent branding, and built-in templates
  (monthly ops / exec summary / IOC digest). The cron generates to DRAFT only;
  the sole outbound action is the analyst-gated
  `POST /reports/generated/{id}/send`.

#### Case collaboration (#109)
- Threaded case comments, @mentions (in-app plus email to mentioned users), and
  watchers, reusing the notifications substrate.

#### Durable connector framework (ADR-0006, #111-#113)
- Typed `Connector` contract targeting OCSF, with a registry flip off the legacy
  pull adapters (`pipeline/ocsf.py`).
- Schema-drift sentinel on pull sources, OCSF `severity_id` plus a Detection
  Finding event envelope driving incident severity, and a self-describing admin
  connector wizard (#112).
- Live CrowdStrike plus Microsoft Defender connectors normalizing to OCSF (#113).

#### Vision One workbench / OAT enrichment and write-back (ADR-0005, #114-#116)
- Read-only auto-enrichment from the V1 Workbench alert and OAT detections
  (behind `v1_autofetch_enabled` / `v1_oat_enabled`, default off).
- Full Workbench alert extraction (#114).
- Verdict write-back: mirror the analyst verdict to Vision One at sign-off
  (#116), gated and off by default.

#### Microsoft Defender integration (ADR-0003, #118-#130)
- Read-only Defender tools for the deep tier (#118) and a native OCSF-first
  parser for Graph `alerts_v2` (#119).
- Live Defender advanced-hunting in the manager-chat hunt re-task (#120).
- Analyst-gated response actions: isolate / unisolate / AV scan (#121),
  Ti.ReadWrite blocklist plus scan proposals (#125), and `disable_user`
  identity containment (#127).
- Alert write-back plus verdict-mirror-on-approve plus an action UI (#122);
  manager proposes Defender isolate at the gate (#123); provider-aware
  manager-chat action revision (#126).
- Strict per-customer credential isolation, fail-closed for unmapped tenants
  (`STRICT_TENANT_CREDS`, #124).
- Tenant-aware Vision One plus Defender ops on the Actions page (#130).
- Flags: `DEFENDER_TOOLS_ENABLED`, `DEFENDER_STATUS_WRITEBACK_ENABLED`.

#### Threat-intel classifier and schema
- `hash` IOC type (MD5 / SHA1 / SHA256) in the classifier; a CSV feed parser
  (per-feed `parser_config`); and an abuse.ch Auth-Key header on matching feed
  syncs.
- `customer_cases.attribution` and `customer_cases.prior_cases_note` columns and
  a `_build_threat_intel_ctx()` helper feeding the structured TI table.

#### DevSecOps
- Backend unit-test suite: ~60 test files, 681 pure unit tests that import
  `isoc_api.*` directly (no Postgres/Redis/Qdrant/LLM needed), run locally with
  `pytest -q`.
- Container image pipeline: `release.yml` builds and pushes `eksir-backend` and
  `eksir-frontend` to GHCR on `main` and `v*` tags.
- Production compose file (`deploy/docker-compose.prod.yml`) pulling GHCR images,
  pinned by `EKSIR_VERSION`.
- `pg_trgm` trigram indexes on `incidents.title` / `rule_name` / `case_number`
  for indexed free-text search.
- Rate limiting via slowapi (login 10/min per IP; paste 60/min per user).
- Security scanning workflow (`security.yml`): Trivy plus npm audit plus
  pip-audit on PRs, pushes, and Mondays.

### Changed
- **Relicensed to Apache-2.0** for the public open-source launch (0.1.0 shipped
  proprietary).
- **Customer notification redesign.** Threat Intelligence renders a structured
  key/value table sourced from `incident.enrichment` (so the LLM can no longer
  paraphrase or hallucinate the factual rows); Critical Impact copy is leaner
  (~40 words); Recommended Actions is hard-capped at 5; section headings use
  monochrome unicode glyphs instead of emojis; and the severity chip moved into
  the top facts strip. Old cases fall back to the legacy paragraph.
- **Threat-intel feeds: SOCRadar → public OSINT.** The SOCRadar seeds are
  deleted on every boot and replaced with 6 public feeds (Emerging Threats, Tor
  exit nodes, URLhaus, MalwareBazaar, ThreatFox, SSLBL). First production sync
  seeded ~91k IOCs.
- **Next.js 14.2.18 → 15.5.18** in /frontend and /landing, closing the Next.js
  middleware authorization-bypass CVE and ~20 high Next.js CVEs.
- 21 backend Python dependency bumps plus 5 JS minor/patch bumps and GitHub
  Actions v4/v5 → v6.
- Backend Dockerfile installs `packaging` into the build prefix before the
  project install so slowapi's transitive `limits` dep resolves at runtime.

### Security
- Weak-JWT-secret boot guard, security headers, CORS lockdown, MFA (TOTP), and
  fail-closed token revocation (see Added, #102 / #103).
- Strict per-customer EDR credential isolation, fail-closed for unmapped tenants
  (`STRICT_TENANT_CREDS`, #124).
- Vulnerability triage: 63 open Dependabot alerts reduced to 2 medium (0
  critical, 0 high).

---

## [0.1.0] - 2026-05-26

Initial private release. EKSIR shipped as a self-contained, deployable
SOC operations platform with CI/CD scaffolding in place.

### Added

#### Core platform
- Multi-tenant incident pipeline: ingest → enrich → classify → synthesize
- Three ingest paths:
  - `POST /api/v1/alerts/paste` — interactive paste from UI
  - `POST /api/v1/alerts/upload` — file upload (single JSON, JSON array, NDJSON)
  - `POST /v1/ingest/{source_id}` — HMAC-SHA256 signed webhook for SIEM/EDR/XDR
- Customer-case promotion + Jinja2 email notification flow with preview
- LLM-driven verdict + analyst report (two-tier: fast pre-classifier → deep
  on uncertainty); short-circuit gates for high-confidence FP/benign
- Threat-intel feeds (8 SOCRadar sources, daily sync) + per-tenant exclusions
- Static malware forensics via REMnux container (peframe, capa, YARA-Forge
  5K core + 11K full, oledump, pdfid, manalyze, signsrch, portex, floss…)
- Vector similarity search via Qdrant + alert-memory-mcp embeddings
  (bge-m3 dense + sparse, hybrid retrieval)
- Auto-close rule engine (YAML + DB-backed admin rules, merged at runtime)
- LLM transcript persistence with opt-out via `ISOC_LOG_LLM_TRANSCRIPTS`
- Audit log for every analyst action

#### UI
- Customizable drag-drop dashboard (react-grid-layout) with:
  - 6 KPI cards (incidents, TP, FP, FP-rate, avg SLA, LLM cost)
  - SLA trend (overall) + SLA trend by priority (per-severity lines)
  - SLA distribution (bucketed close times)
  - True/False positive area chart, status / severity / verdict donuts
  - Top 10 IOCs, top 10 rules, monthly volume, daily incidents
  - 6-month FP-rate trend, LLM token usage panel
- Per-user / tenant-default layout persistence; admin can save as tenant default
- Per-panel hide/show toggle in edit mode + "Add panel" menu
- `/incidents` page: pagination (10/25/50/100), filters, bulk selection,
  bulk actions (close / verdict / reassign / archive), CSV export
- Admin-only soft delete (archive → restore → purge) with FK protection
- Forensics page with past-runs list, triage tab, static analysis report
- LLM Calls tab on incident detail (full transcripts when enabled)

#### Backend
- `/health` (liveness) + `/health/deep` (DB + Redis + Qdrant readiness probe)
- ARQ worker with `max_jobs=8`, fully async pipeline
- Idempotent DB backfills (no Alembic yet; pyproject ships alembic for later)
- 9-container compose stack: backend, frontend, worker, postgres, redis,
  qdrant, litellm, caddy, remnux

#### DevSecOps
- Private GitHub repo: https://github.com/tallcyberguy/eksir
- GitHub Actions CI: backend (ruff + mypy) + frontend (lint + type + build)
- Dependabot: weekly batched updates for pip, npm, docker, github-actions
- Pre-commit hooks: detect-secrets, ruff, file hygiene
- Docker base images pinned by sha256 digest (python:3.12-slim, node:22-alpine)
- alert-memory-mcp vendored into the backend image (self-contained, no
  host-folder runtime dependency)
- `.env.example` template + production .env checklist documented
- LICENSE: Apache-2.0 (0.1.0 shipped proprietary; relicensed at the 0.2.0
  public launch)

### Known limitations
- No staging environment — first prod deploy will be direct from local.
- No GHCR image push yet — Phase 2 (next).
- No backups configured — Phase 4 (before first paid customer).
- Branch protection on `main` requires GitHub Pro ($4/mo) — solo-dev
  discipline for now; `ci-ok` aggregator job is ready to gate when upgraded.
- mypy runs with `|| true` (warnings non-blocking) — tighten once warning
  count is manageable.
