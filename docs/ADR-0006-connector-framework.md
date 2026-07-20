# ADR 0006 — Durable connector framework (typed contract + OCSF normalization)

**Date:** 2026-07-13
**Status:** Accepted, P0 landed (2026-07-13). New files under
`backend/isoc_api/adapters/connectors/` (`fields.py`, `capabilities.py`, `base.py`, `severity.py`,
`drift.py`, `routing.py`, `providers/` — all 12 connectors ported), the P0 routing change in
`adapters/parser_adapter.py`, and unit tests in `backend/tests/test_connector_framework.py`.
**P0.1 (deterministic routing) and P0.2 (registry flip) are DONE:** `registry.CONNECTORS` is now
built from the typed `Connector` classes, proven catalogue-faithful by a golden snapshot test
(the legacy `tests/test_connectors.py` + the new suite pass; 605 tests total, ruff + mypy clean).
The change is additive and backward-compatible (legacy `ConnectorSpec`/`catalog()` shape unchanged,
now a superset). **P1 update (2026-07): OCSF normalization has started.** The Microsoft Defender
connector is now `adapter_status="live"` (pull-ingest + gated response actions — ADR-0007, PRs
#118–#127), and the first **native OCSF-first parser** (`adapters/ocsf_defender.py`) supersedes the
vendored one via a native-parser seam in `parser_adapter` (see P0 routing below). P2 not started.
Needs a backend image rebuild to take effect in the running stack.
**Relates to:** ADR-0007 (multi-tenant EDR/XDR credential store — this generalizes its catalogue
layer), ADR-0005 (Vision One enrichment — the first live connector), `docs/PIPELINE.md`,
`adapters/connectors/registry.py`, `adapters/ingest/`, `pipeline/ocsf.py`, `pipeline/ingest_sources.py`.
**Method:** synthesized from a multi-agent research + adversarial-review workflow (AiSOC repo
architecture read, full 78-connector catalogue, a 2026 standards-landscape pass over OCSF / ECS /
STIX / Sigma and how Panther / Cribl / Chronicle / Sentinel structure their connector layers, and
an adversarial critique that stress-tested the "ISOC is more durable" claim).

## Context

We advertise two connectors today (Trend Micro Vision One, SentinelOne) and want to grow the
portfolio to dozens. Before adding many connectors we need the connector architecture to be
durable at that count. A review compared ISOC's model against AiSOC's (an MIT-licensed
open-source SOC with ~78 connectors) and against 2026 industry practice.

**Verdict: durable engine, brittle chassis.** ISOC's runtime and data layer is genuinely ahead
of AiSOC and much of the field. Its authoring and catalogue layer is where cost compounds as the
count grows.

What is already good and stays (the engine):

- **Opaque per-source cursor** (`ingest_sources.cursor` JSONB) for exact resumption. AiSOC uses a
  recomputed `since_seconds` time window, which drops events on long outages and duplicates on
  overlap. That is an ingestion-correctness bug Kafka does not fix; ISOC does not have it.
- **Idempotency**: Redis `ingest:seen:{provider}:{external_id}` (`SET NX`) plus a DB backstop that
  survives a Redis flush.
- **Operational resilience**: health states (disabled / error / stale / ok / pending) with
  stale-detection, capped exponential backoff, per-source metrics, never auto-disables.
- **One pipeline**: pulled alerts ride the same path as webhooks to the same human sign-off gate.
- **No-code onboarding**: `field_map.py` dotted-path JSONB + the `/sources/preview` dry-run. This
  is best-in-class and mirrors Vector VRL / Matano / Cribl.
- **Standards trajectory**: STIX/TAXII inbound shipped; the hunt layer emits Sigma / KQL / S1QL;
  an OCSF entity model is underway (`pipeline/ocsf.py`, PR #82).

What will hurt as the catalogue grows (the chassis), ranked by pain:

1. **Parser routing by payload-sniffing (HIGH).** `parsers.detect_source` picks the parser from an
   ordered `if`-chain of raw-key checks. The pull adapter already declares its identity
   (`PulledAlert.source_hint`), but routing ignores it and re-guesses. The vendored code already
   shows the strain ("Vision One requires >=2 distinctive markers so it can't shadow the others").
   As Cortex / Defender / Elastic / Sumo arrive, vendors will share discriminating keys (`id`,
   `severity`, `alerts`), so a new connector can silently re-route an existing vendor's payloads to
   the wrong parser.
2. **Concern-drift across the four authoring sites (HIGH).** A connector's truth is spread across
   `registry.py` (spec), `adapters/ingest/<x>.py` (fetch), `health.py` (test), and a vendored
   parser, with nothing type-binding them. A spec can declare a field the fetch never reads; a
   `respond` capability can exist with no respond adapter.
3. **No schema-drift detection (HIGH).** `field_map` dotted-path lookups resolve to `null` silently
   when a vendor renames `source.ip` to `src.ip`. Across dozens of independently-versioned APIs
   that rot is continuous and invisible until an analyst notices missing IOCs.
4. **Bare string-tuple credential fields (MEDIUM).** `ConnectorSpec.fields = ("api_key","region")`
   carries no type, masking, validation, help, or docs, so it cannot drive a real onboarding
   wizard for heterogeneous auth.
5. **Three-verb capability model (MEDIUM).** `enrich` / `respond` / `hunt` collapses isolate-host,
   disable-user, and push-case into one `respond` bucket, so no per-action RBAC / audit / policy.
6. **Only two auth shapes modeled (MEDIUM).** Token and OAuth client-credentials only. AWS keys,
   GCP service-account JSON, and mTLS are not representable; the GuardDuty stub already
   misrepresents AWS as `api_key + region`.
7. **Wazuh 1-15 as canonical severity (MEDIUM).** A vendor convention that maps to nothing outside
   Wazuh and has no clean mapping to OCSF `severity_id` 0-6, and it fights our own OCSF trajectory.

Industry practice in 2026 is consistent: **one canonical open schema plus many thin, config-driven,
versioned mappers.** Panther maps to OCSF; Cribl emits OCSF; Google SecOps normalizes to UDM;
Sentinel uses ASIM. For a platform that federates across many third-party vendors (our exact case),
the open convergence point is **OCSF** (`class_uid`, `metadata.product`, `severity_id` 0-6). STIX is
the TI target (shipped) and Sigma is the downstream detection layer (shipped). CEF / LEEF / syslog
are input formats you parse into OCSF, never a storage target.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Keep the runtime engine | **No Kafka, no ingest microservice.** Keep ARQ + opaque cursor + Redis/DB dedup + backoff | Our cursor + dedup already give at-least-once-with-resume at single-box scale, which is what Kafka would buy. Local-first stays. |
| 2 | Unify the four pieces | **One typed `Connector` contract** (metadata + typed fields + capabilities + fetch + test + declared parser source), loader-enforced, projecting to the legacy `ConnectorSpec` | Kills concern-drift: one file per connector, one source of truth. Borrows AiSOC's cohesion without its runtime. |
| 3 | Kill payload-sniffing routing | **Route by the connector's declared source**; `detect_source` becomes the fallback for the unknown-source paste/webhook path only | The pull path already carries `source_hint`. Deterministic routing, no key-collision as sources grow. This is P0. |
| 4 | Normalization target | **Adopt OCSF as the canonical event target.** Back `NormalizedAlert` with OCSF field names + a Detection/Security-Finding envelope; extend `pipeline/ocsf.py` from entities to events | Every mapper aims at a documented, versioned, industry-shared schema instead of a private shape. Contains vendor drift. |
| 5 | Severity | **OCSF `severity_id` 0-6 is canonical.** Wazuh 1-15 kept only as a legacy display/compat map | Keep the 0-100 fused confidence/threat scores (`pipeline/scoring.py`) as the separate analytic dimension they already are. |
| 6 | Credential schema | **Typed `Field` descriptors + `OAuthHints`** replace the string tuple; drives the admin wizard and validation | Superset of the current shape, so the old `fields` name list still renders. Biggest lever on cheap-40th-connector. |
| 7 | Auth shapes | **Model auth as typed variants**: token, OAuth client-creds (both exist), then AWS SigV4 (+ IAM-role fallback), GCP SA-JSON (RS256 JWT), mTLS | Unblocks the whole cloud category. Fix the GuardDuty stub honestly. |
| 8 | Capabilities | **Fine-grained verb taxonomy** (`pull_alerts`, `enrich_ioc`, `hunt_query`, `isolate_host`, `disable_user`, `block_hash`, `push_case`, ...) with a projection to the legacy coarse `enrich`/`respond`/`hunt` | Per-action RBAC/audit later; the coarse projection keeps today's UI badges + gating working unchanged. |
| 9 | Schema-drift sentinel | **Fingerprint the union of top-level field names per source**, alarm on change | Borrowed from AiSOC's `fingerprint.py`. Catches silent field rot before it nulls the mapping. |
| 10 | Migration style | **Additive and backward-compatible.** New contract lands beside the legacy registry; a test proves `Connector.to_spec()` equals the current catalogue entries; flip the registry to build from `Connector` classes in one commit | No big-bang. Existing live connectors (V1, S1) keep working throughout. |

## Design

### The typed `Connector` contract (`adapters/connectors/base.py`)

One class per connector, replacing the four scattered pieces. Metadata is declarative
(classmethods, no instantiation needed); `fetch` / `test_connection` are the runtime surface.
`to_spec()` projects to the exact dict the current catalogue/UI consume, as a superset (adds
`field_specs`, `capability_verbs`, `auth_shape`, `oauth_hints`, `parser_source`).

```python
class Connector(ABC):
    key: str                     # matches Integration.provider + ingest_sources.provider
    label: str
    category: str                # edr|ti|recon|siem|identity|email|cloud|network|itsm|appsec
    identifier_label: str
    adapter_status: str          # "live" | "planned"
    auth_shape: AuthShape        # token | oauth_client_creds | aws_keys | gcp_sa_json | mtls
    parser_source: str | None = None   # declared vendored-parser source; None => field_map/generic
    docs_url: str | None = None

    @classmethod
    def fields(cls) -> tuple[Field, ...]: ...          # typed, drives the wizard
    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]: ...  # fine verbs
    @classmethod
    def oauth_hints(cls) -> OAuthHints | None: return None
    @classmethod
    def region_options(cls) -> tuple[str, ...]: return ()

    async def fetch(self, *, creds, cursor, max_items) -> FetchResult: ...   # planned => NotImplemented
    async def test_connection(self, creds) -> dict: ...                      # planned => no_adapter

    @classmethod
    def to_spec(cls) -> dict: ...   # legacy-compatible superset for routes/admin + routes/connectors
```

`Field` (`fields.py`) is `{key, label, type (text|secret|textarea|select|number|boolean), required,
help, placeholder, options, docs_url}`; `OAuthHints` is `{authorize_url, token_url, scopes,
supported_in_hosted}` with `{domain}` placeholder substitution. `validate_config(fields, config)`
returns a list of human-readable errors, pure and unit-tested.

`Capability` (`capabilities.py`) is the fine verb enum; `coarse_for(caps)` projects to the legacy
`("enrich","respond","hunt")` so `registry.capabilities_for` and the UI badges are unchanged.

### P0 routing fix (`adapters/parser_adapter.py` + `connectors/routing.py`)

`resolve_parser_source(source_hint, known_sources, detect)` is a pure decision: if the connector
declared a source we have a parser for, dispatch straight to that parser module
(`getattr(parsers, source).parse(raw, customer)`); otherwise fall back to `parsers.parse` (which
runs `detect_source`). `known_sources = {qradar, wazuh, fortigate, syslog, visionone, sentinelone,
crowdstrike, microsoft_defender}`. This is entirely ISOC-owned (no vendored change); today's behavior
is unchanged (the live pull sources already detect correctly) but routing becomes deterministic as
new sources land.

**Native-parser seam (2026-07):** `parser_adapter._native_parse_fn(source)` lets an isoc_api-side
parser SUPERSEDE the vendored one per source — the migration path off the retiring vendored parsers
toward native OCSF-first parsing (Decision #4). `microsoft_defender` routes to `adapters/ocsf_defender.py`,
which recovers the Defender-for-Office-365 email evidence (`analyzedMessageEvidence`/`mailboxEvidence`)
the vendored parser dropped, so `pipeline/ocsf.py` then emits the sender/recipient user entities. The
vendored path stays as the fallback for sources without a native parser.

### OCSF severity (`connectors/severity.py`)

`to_ocsf_severity(value) -> int` maps vendor words and numbers (5-tier ladders, 0-100 bands, Wazuh
1-15) onto OCSF `severity_id` 0-6 (Unknown / Informational / Low / Medium / High / Critical /
Fatal). `ocsf_to_wazuh` / `wazuh_to_ocsf` keep the legacy 1-15 display alive during migration.

### Schema-drift sentinel (`connectors/drift.py`)

`field_fingerprint(records)` is a SHA-256 over the sorted union of top-level field names;
`detect_drift(previous_fingerprint, records)` returns `{changed, added, removed, fingerprint}`. The
cron persists the fingerprint per source (next to the cursor) and raises the existing
`enrich_subtask_failed`-style timeline signal on change. Pure and unit-tested; wiring into the cron
is P1.

## Build order

**P0 — do before adding connectors (DONE 2026-07-13):**

1. **Kill payload-sniffing routing.** `resolve_parser_source` + the `parser_adapter` wiring. Small,
   backward-compatible, high-leverage. *(Done.)*
2. **Land the typed `Connector` contract** (`fields.py`, `capabilities.py`, `base.py`) plus the
   `providers/` ports (all 12 connectors), and flip `registry.CONNECTORS` to build from the
   `Connector` classes. Proven catalogue-faithful by the golden snapshot test. *(Done — the
   catalogue is now sourced from the connector classes; adding a connector is a new `providers/`
   module + one line in `providers.ALL`.)*

**P1 — next:**

3. **Adopt OCSF as the normalization target.** Extend `pipeline/ocsf.py` from entities to the event
   envelope; back `NormalizedAlert` with OCSF field names; make `severity_id` 0-6 canonical and
   demote Wazuh 1-15 to display. *(Severity helper drafted. **STARTED:** `adapters/ocsf_defender.py`
   is the first native OCSF-first parser, routed via the native-parser seam; the vendored parsers are
   being retired source-by-source as native ones land.)*
4. **Self-describing credential UI.** Frontend admin wizard renders from `field_specs` + `oauth_hints`.
5. **Schema-drift sentinel** wired into the cron with a per-source fingerprint column. *(Helper drafted.)*

**P2 — unlocks categories:**

6. **Broaden auth shapes** (AWS SigV4 + IAM fallback, GCP SA-JSON, mTLS); fix the GuardDuty stub.
7. **Fine-grained capability gating** (per-verb RBAC + audit) as response actions multiply.

## Consequences

- Adding a connector becomes one file implementing one typed contract, loader-enforced, instead of
  four coordinated edits across three subsystems. The cost of the 40th connector stays flat.
- Routing is deterministic; a new connector cannot silently steal an existing vendor's payloads.
- Mappers target OCSF, an industry-shared versioned schema, so cross-vendor semantics are grounded
  and vendor drift is contained (and caught by the sentinel).
- The admin "Add connector" wizard renders and validates itself from typed fields, including odd
  auth shapes.
- No new runtime failure domain: the engine, the human gate, and the local-first deployment are
  untouched. The invariant (only the analyst's Approve commits a verdict or fires an action) is
  unchanged.
- Backward-compatible throughout: legacy `ConnectorSpec`, `catalog()`, `connector_keys()`, and the
  two live connectors keep working until the registry flip, which is proven equivalent by test.

## Alternatives considered

- **Adopt AiSOC's Kafka / Go ingest microservice.** Rejected: disproportionate ops weight and a
  second failure domain for a local-first single-box product, and it does not fix AiSOC's own
  cursor/dedup correctness gap. Our engine already provides the guarantee. If reduction/routing
  volume ever demands it, add a Vector/OTel-style processor stage between fetch and normalize rather
  than re-platforming transport.
- **Adopt ECS instead of OCSF.** Rejected as the forward target: ECS is being frozen and folded into
  OpenTelemetry Semantic Conventions. OCSF is where cross-vendor security-finding investment flows
  in 2026 (AWS Security Lake, Panther, Cribl, SentinelOne, Palo Alto).
- **Lift AiSOC connector code directly.** Rejected: MIT-licensed so legally clean, but
  architecturally incompatible (one class feeding a Go/Kafka pipeline vs our four-way split riding
  the in-process gated pipeline). We lift the per-vendor API recipes (endpoints, pagination, auth
  flow, severity/field maps), not the files.

## Revisit when

- A single ARQ worker head-of-line-blocks on chatty sources → shard the cron by source or add a
  processor stage; still no Kafka required.
- A connector needs per-tenant or hot-shippable parse logic → move parsers out of the baked image
  behind a versioned mapper store (the OCSF mapper layer is the natural home).
- Per-action RBAC/policy is requested → promote the fine capability verbs into the authz layer.
