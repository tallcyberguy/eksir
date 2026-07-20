# ISOC / EKSIR — roadmap

> Living roadmap for the pull-ingestion → adjudication → response arc.
> Seeded from the Vigil-SOC comparison (`docs/INGEST-PULL-PLAN.md` + the verified
> contribution analysis). Grouped by theme; not strictly ordered.

## Shipped

| Area | What | PR |
|------|------|----|
| Ingestion | Pull spine (`ingest_sources` + `pull_ingest` cron + adapter registry) + Vision One source + **Sources** admin page | #90 |
| Safety | SSRF/url-safety guard + LLM cost caps (fail-safe to the gate) | #91 |
| Consoles | SentinelOne pull adapter + parser | #92 |
| Credentials | OAuth client-credential support in the Integration store + generic admin form | #93 |
| Consoles | CrowdStrike + Microsoft Defender pull adapters + parsers | #94 |
| Ingestion | Config-driven field mapping + **fix**: pull-path JSON parsing (V1/S1 were parsing as `unknown`) | #95 |
| Observability | Per-source metrics (poll ms / count / total) + stale detection + health summary | #96 |
| Ingestion | Batch / historical import (JSONL / CSV / Parquet / S3) via the Sources **Import** tab | #98 |
| MSSP SLA | 24/7 response + resolution SLA per severity + breach scan + in-app notifications | #100 |
| Security | Stage 3a hardening (weak-secret boot guard, security headers, CORS lockdown) | #102 |
| Security | MFA (TOTP) + fail-closed token revocation (`jti` + per-user `token_version`) | #103 |
| Threat intel | STIX 2.1 / CSV export of analyst-confirmed IOCs (intel producer) | #104 |
| Threat intel | STIX/TAXII inbound feed ingestion (new `taxii` feed format) | #105 |
| Reporting | SOC trend analytics (MTTR p50/p90 + per-source / per-verdict time-series) | #106 |
| Reporting | Branded automated per-customer reports (HTML + PDF, scheduled to DRAFT, analyst-gated send) | #107 |
| Collaboration | Case comments + @mentions + watchers (reuse the notifications substrate) | #109 |
| Connectors | Durable typed connector framework + registry flip (OCSF target, ADR-0006) | #111-#113 |
| Enrichment | Vision One Workbench / OAT read-only auto-enrichment (ADR-0005) | #114-#115 |
| Scoring | Fused confidence + effective-threat case scores (vendor risk score feeds inherent threat) | #80, #87, #115 |
| Write-back | **Write-back to source at sign-off** (gated, off by default): Vision One verdict mirror + Microsoft Defender classification/status | #116, #122-#123 |
| Consoles | Full Microsoft Defender integration: OCSF parser, live hunt, gated response (isolate / scan / blocklist / disable_user) + strict per-customer credential isolation | #118-#130 |

Live pull consoles: **Vision One, SentinelOne, CrowdStrike, Microsoft Defender**.
Invariants held throughout: alert-native, deterministic-first, **human sign-off gate
is the only commit point**, local-first. Every write-back and response action is
gate-fired, analyst-checked, and off by default.

## Deferred (needs live-console field testing)

- **Write-back to source for the remaining consoles.** Vision One (verdict mirror)
  and Microsoft Defender (classification / status) shipped, gated and off by default
  (see Shipped). SentinelOne (`analystVerdict` / `incidentStatus`) and CrowdStrike
  (alert `status`) write-back stay deferred: those vendor write APIs are still
  unverified against a live tenant. They ride the same gate-fired, analyst-checked
  `proposed_actions` path when built. Incident already carries the origin id
  (`raw_payload.pull.external_id`).

## Candidate next features

### Ingestion (completion)
- **Kafka streaming ingest** (optional): a consumer that emits normalized alerts
  into the same pipeline path, for customers who publish to a bus.

### MSSP case management
- **Evidence chain-of-custody**: first-class, hashed evidence records for
  defensible cases.
- **Per-tenant business-hours SLA windows**: an optional, off-by-default mode that
  subtracts out-of-window time from the 24/7 response / resolution clocks that
  shipped in #100.

### Threat intel
- **Multi-sandbox hash enrichment**: read-only lookup-by-hash across sandboxes.

### LLM ops
- **Data-driven persona registry**: persona prompts / params as editable data (keep
  the fixed L1 → L2 → hunt → forensics → manager topology in code); per-tenant
  overrides. See ADR-0004 for the related (proposed) procedures library.
- **Provider model discovery + typed budgets**: a live model list for the admin LLM
  config (behind the SSRF guard) + per-model caps.

### Platform / security hardening
- **Optional Helm/K8s chart**: scale-out deploy path (one-box compose stays the
  default). Session-fingerprinted JWT is the remaining product-security item after
  the #102 / #103 hardening.

## Explicitly not adopting (from the Vigil analysis)

Autonomous auto-response / auto-close · LLM self-sequencing · the FederationAdapter
framework (duplicates our seam) · a bitemporal triple store · a second BM25 rerank
pass (we already have the sparse leg) · mempalace · `DEV_MODE` auth bypass.
