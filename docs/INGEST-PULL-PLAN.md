# Pull-native alert ingestion (implementation plan)

> **Status:** proposed / not built. This is an engineering spec, not an ADR yet.
> Written as a follow-on to the Vigil-SOC comparison. It reuses ISOC's existing
> seams (`mailbox_poll`, `integration_store`, the connectors catalog, the
> `RECEIVED -> pipeline_run` path) rather than importing Vigil's daemon framework.
> New, untracked file: move it under an ADR number (`ADR-0006`) or keep it here as
> you prefer.

## 1. Goal and non-goals

**Goal.** Let ISOC pull alerts directly from EDR/XDR and SIEM consoles (Trend Micro
Vision One first, then SentinelOne, CrowdStrike, Microsoft Defender, and more) on a
schedule, so analysts stop forwarding alerts by email and stop copy-pasting from
consoles. Email ingestion (`mailbox_poll`) stays as a fallback source, not the
strategy.

**Why this is the right shape.** A direct API pull is a real, robust integration.
Email forwarding depends on a mailbox being up, on subject-line company
attribution, and on the console's email format not changing. Pulling the Vision One
Workbench alert over the v3.0 API also returns *richer* data than the email ever
did (full `impactScope.entities`, `matchedRules` with MITRE technique ids,
`indicators` with command lines and hashes), so the pull path is strictly better,
not just more convenient.

**Non-goals (deliberate, to protect ISOC's invariants).**
- No autonomous triage or response. Pulled alerts are proposals like any webhook
  alert. The analyst sign-off gate stays the only commit point.
- No new always-on daemon process. The pull loop is an ARQ cron on the existing
  worker (see section 4).
- No new parallel framework. We do not port Vigil's `daemon/federation/*`
  package; we generalize the `mailbox_poll` seam ISOC already has.

**Invariants preserved.** Alert-native normalization stays deterministic (vendored
parsers + normalizer). Per-customer credentials stay in the encrypted `Integration`
store. Every pulled alert enters as `Incident(status=RECEIVED)` and rides the same
deterministic pipeline to the human gate.

## 2. Architecture at a glance

```
                       ┌────────────────────────────────────────────┐
   Vision One ──┐      │  pull_ingest  (ARQ cron, every 60s)         │
   SentinelOne ─┤      │  for each enabled & due ingest_sources row: │
   CrowdStrike ─┼─API─▶│    creds  = integration_store.get_creds*    │
   Defender ────┤      │    result = adapter.fetch(cursor, max_items)│
   (many more)  ┘      │    for each alert: dedup(Redis) →           │
                       │      Incident(RECEIVED, ingest_source=PULL) →│
                       │      enqueue pipeline_run                    │
                       │    record_success(cursor) / record_failure  │
                       └───────────────────┬────────────────────────┘
                                           ▼
   (unchanged) parser_adapter → normalizer → enrich → synthesis → HUMAN GATE
                                           ▲
   webhook  ──────────────────────────────┤  (same entry contract)
   mailbox_poll (fallback) ───────────────┘
```

Everything left of the gate is new; everything from `parser_adapter` right is
untouched.

## 3. Data model

### 3.1 New enum value (`db/enums.py`)

`IngestSource` is a `StrEnum`, so this is additive and needs no data migration of
existing rows:

```python
class IngestSource(StrEnum):
    WEBHOOK = "webhook"
    EMAIL = "email"
    PULL = "pull"      # NEW — API-pulled from a console
    # BATCH = "batch"  # later: historical file/S3 import
```

### 3.2 New table `ingest_sources` (`db/models.py`)

One row per (provider, console-identifier). Columns are ported from Vigil's
`federation_sources` and named for ISOC.

```python
class IngestSourceConfig(Base, UUIDMixin, TimestampMixin):
    """A pull source: which console to poll, how often, and its cursor.

    (provider, identifier) is unique. `identifier` matches the Integration row
    the credentials live in (integration_store); `customer` is the tenant the
    created incidents are attributed to.
    """

    __tablename__ = "ingest_sources"

    provider: Mapped[str] = mapped_column(String(32), nullable=False)   # connectors catalog key
    identifier: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    customer: Mapped[str | None] = mapped_column(String(128), index=True)

    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    min_severity: Mapped[str | None] = mapped_column(String(16))
    max_items: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # Phase 2: config-driven field mapping for sources with no bespoke parser.
    field_map: Mapped[dict | None] = mapped_column(JSONB)

    cursor: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    consecutive_errors: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("provider", "identifier", name="uq_ingest_source_provider_identifier"),
    )
```

### 3.3 Migration

Add an Alembic migration in `backend/migrations/versions/` creating `ingest_sources`
(plus the idempotent `CREATE TABLE IF NOT EXISTS` mirror in the startup schema pass,
matching how the project applies additive schema). The `IngestSource.PULL` enum value
needs no DDL because `ingest_source` is stored as a string column.

## 4. The `pull_ingest` cron (`worker.py`)

This is the whole "daemon". It is `mailbox_poll` generalized over a table. One cron
fires every minute; each row is polled only when it is due, so a single job serves
many per-console cadences.

```python
from datetime import datetime, timezone
from sqlalchemy import select

from .adapters import integration_store
from .adapters.ingest import get_adapter          # registry, section 5
from .pipeline.ingest_sources import due, record_success, record_failure, dedup_key

async def pull_ingest(ctx) -> dict:
    """Poll every enabled+due pull source; create RECEIVED incidents.

    Idempotent: dedups on (provider, external_id) via Redis with a DB backstop.
    A no-op when no sources are enabled, so it is safe to leave the cron on.
    """
    redis = ctx["redis"]
    now = datetime.now(timezone.utc)
    ingested, polled = 0, 0

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(IngestSourceConfig).where(IngestSourceConfig.enabled.is_(True))
        )).scalars().all()

    for row in rows:
        if not await due(redis, row, now):        # interval + last_poll_at, or poll-now flag
            continue
        adapter = get_adapter(row.provider)
        if adapter is None:
            continue
        creds = await _resolve_creds(row.provider, row.identifier)   # section 6
        if creds is None:
            continue

        polled += 1
        try:
            result = await adapter.fetch(creds=creds, cursor=row.cursor or {}, max_items=row.max_items)
        except Exception as e:
            await record_failure(row.id, str(e))    # increments consecutive_errors, backoff
            continue

        for alert in result.alerts:
            if not _severity_passes(alert.get("severity"), row.min_severity):
                continue
            ext = alert.get("external_id")
            if not ext:
                continue
            key = dedup_key(row.provider, ext)
            # SET NX EX — atomic claim; skip if already seen this window.
            if not await redis.set(key, "1", nx=True, ex=7 * 24 * 3600):
                continue
            incident_id = await _create_pull_incident(row, alert)   # DB backstop dedup inside
            if incident_id:
                await redis.enqueue_job("pipeline_run", incident_id)
                ingested += 1

        await record_success(row.id, cursor=result.cursor or {})

    return {"polled": polled, "ingested": ingested}
```

Incident creation mirrors `mailbox_poll` exactly, only the `ingest_source` and the
`raw_payload` origin change:

```python
async def _create_pull_incident(row, alert) -> str | None:
    async with AsyncSessionLocal() as session:
        if await _pull_already_ingested(session, row.provider, alert["external_id"]):
            return None                                  # DB backstop for the Redis dedup
        inc = Incident(
            title="(unparsed)",
            status=CaseStatus.RECEIVED,
            ingest_source=IngestSource.PULL,
            customer=row.customer,
            raw_payload={
                "text": alert.get("raw_text", ""),
                "source_hint": alert.get("source_hint"),   # routes detect_source
                "original": alert.get("original"),          # the raw console object (dict)
                "pull": {"provider": row.provider, "external_id": alert["external_id"]},
            },
        )
        session.add(inc)
        await session.flush()
        incident_id = str(inc.id)
        await session.commit()
        return incident_id
```

Wire it in `WorkerSettings` next to `mailbox_poll`:

```python
functions = [ ..., mailbox_poll, pull_ingest ]
cron_jobs = [
    ...,
    cron(mailbox_poll, minute=set(range(60)), run_at_startup=True),
    cron(pull_ingest,  minute=set(range(60)), run_at_startup=True),   # per-row interval gates actual polls
]
```

`due()`, `record_success()`, `record_failure()`, and `dedup_key()` live in a small
`pipeline/ingest_sources.py` helper (the ISOC analogue of Vigil's `federation/store.py`):
cold-start returns "due now"; `record_failure` increments `consecutive_errors` and
applies capped exponential backoff (`min(2**errors, 8) * interval`); nothing ever
auto-disables a source.

## 5. Adapter contract and registry (`adapters/ingest/`)

Thin, source-agnostic contract. Output is *raw* text/dict for the existing parser,
not a pre-normalized finding (this is the key difference from Vigil: normalization
stays deterministic and centralized).

```python
# adapters/ingest/base.py
from dataclasses import dataclass, field
from typing import Any, Protocol, TypedDict

class PulledAlert(TypedDict, total=False):
    external_id: str          # stable per-source id -> dedup key (required)
    raw_text: str             # text form for parsers that read text
    original: Any             # the raw console object (dict) for JSON parsers
    source_hint: str          # e.g. "visionone" — routes detect_source
    severity: str | None      # raw severity, for the min_severity floor
    occurred_at: str | None

@dataclass(slots=True)
class FetchResult:
    alerts: list[PulledAlert] = field(default_factory=list)
    cursor: dict[str, Any] = field(default_factory=dict)

class IngestAdapter(Protocol):
    provider: str
    async def fetch(self, *, creds: Any, cursor: dict, max_items: int) -> FetchResult: ...
```

`adapters/ingest/__init__.py` holds a `get_adapter(provider)` registry keyed by the
connectors-catalog key, so `pull_ingest` and the connectors API share it.

## 6. Vision One adapter (first source)

### 6.1 Add a list endpoint to `v1_adapter.py`

Clone the `nextLink` pagination already used by `get_endpoint_activity`
(`v1_adapter.py:299-344`). **Verify the exact query-param names and path against your
tenant's API version** before shipping (the OAT function already flags one unverified
filter, so treat V1 query syntax as needing confirmation):

```python
async def list_workbench_alerts(
    *, start: str, end: str | None = None,
    region: str | None = None, api_key: Any = None,
    top: int = 100, max_records: int = 100,
) -> list[dict]:
    """List Workbench alerts created since `start` (RFC3339 Z), newest-safe paging."""
    params: dict[str, Any] = {
        "startDateTime": start,
        "dateTimeTarget": "createdDateTime",
        "orderBy": "createdDateTime asc",
        "top": top,
    }
    if end:
        params["endDateTime"] = end
    items: list[dict] = []
    async with _client(region=region, api_key=api_key) as c:
        resp = await c.get("v3.0/workbench/alerts", params=params)
        data = await _raise_for(resp)
        items.extend(data.get("items", []) if isinstance(data, dict) else [])
        next_link = data.get("nextLink") if isinstance(data, dict) else None
        while next_link and len(items) < max_records:
            resp = await c.get(next_link)
            data = await _raise_for(resp)
            items.extend(data.get("items", []) if isinstance(data, dict) else [])
            next_link = data.get("nextLink") if isinstance(data, dict) else None
    return items[:max_records]
```

### 6.2 The ingest adapter

```python
# adapters/ingest/vision_one.py
import json
from datetime import datetime, timedelta, timezone
from .. import v1_adapter
from .base import FetchResult, PulledAlert

def _iso(dt): return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class VisionOneIngestAdapter:
    provider = "vision_one"

    async def fetch(self, *, creds, cursor, max_items) -> FetchResult:
        # Cold start = ~now (no backfill), matching mailbox_poll's "only new".
        start = cursor.get("last_poll_at") or _iso(datetime.now(timezone.utc) - timedelta(minutes=1))
        raw = await v1_adapter.list_workbench_alerts(
            start=start, region=creds.region, api_key=creds.api_key, max_records=max_items,
        )
        alerts: list[PulledAlert] = []
        for a in raw:
            ext = str(a.get("id") or a.get("workbenchId") or a.get("alertId") or "")
            if not ext:
                continue
            alerts.append(PulledAlert(
                external_id=ext,
                raw_text=json.dumps(a, ensure_ascii=False, default=str),
                original=a,
                source_hint="visionone",
                severity=(a.get("severity") or None),
                occurred_at=a.get("createdDateTime"),
            ))
        return FetchResult(alerts=alerts, cursor={"last_poll_at": _iso(datetime.now(timezone.utc))})
```

Credentials: V1 has its own resolver that folds in the region, so `_resolve_creds`
routes V1 to `integration_store.get_creds_v1(customer)` (returns `V1Creds(api_key,
region)`) and everything else to the generic `integration_store.get_creds(provider,
identifier)` (`Creds(api_key, base_url, region)`).

### 6.3 The one real V1 work item: a Workbench-JSON parser branch

The current `parsers/visionone.py` parses the **email notification text**, not the
API JSON. The API object is richer. Because `parsers.detect_source` and
`parsers.parse` already accept `str | dict`, the clean fix is to teach them the JSON
shape (vendored code, extend it in place per project convention):

- `detect_source(dict)`: recognize a Workbench alert dict (e.g. an `id` matching
  `WB-...` plus `impactScope` / `matchedRules` keys) and return `"visionone"`.
- `visionone.parse(dict)`: map the Workbench JSON to `NormalizedAlert`
  (`model`/`severity`/`score`, `impactScope.entities` to hosts/users/IPs,
  `matchedRules[].mitreTechniqueIds` to techniques, `indicators[]` to command lines
  and hashes).

This yields better normalization than the email path. It is the only genuinely new
parsing work for V1; the client and the pipeline are reused.

## 7. Safety bundle (ships in the same phase, not later)

Adding outward network calls without these turns admin config into an attack surface.

1. **SSRF / url-safety guard.** Port Vigil's `services/url_safety.py`: resolve the
   host, block loopback/private/link-local/metadata IPs (`169.254.169.254`,
   `fd00:ec2::254`), reject userinfo/fragment, strip the query. Wire it into every
   admin-supplied URL: the SentinelOne/CrowdStrike/Cortex `base_url`, the LLM admin
   `base_url`, and BYOK endpoints. ISOC has no SSRF guard today; this is the one
   prerequisite the whole plan depends on.
2. **Shared dedup.** The Redis `SET NX EX` in section 4 plus the DB backstop.
3. **Cost governance.** Persist `cost_usd` on every LLM call (2-line change in
   `orchestrator.py::_llm_call_row` using `llm/pricing.py`), then add per-run and
   daily budget caps that fail *safe*: on breach, reuse the existing blocked-result
   path so the incident parks at `AWAITING_SIGNOFF`, never auto-closes. Local models
   price at $0, so caps never fire on an Ollama/vLLM deployment. This matters the
   moment a misconfigured poller fans a burst of alerts into deep-tier synthesis.

## 8. Control plane (API + UI)

Extend `routes/connectors.py` (admin-only, already the home of the catalog + test):

- `POST /connectors/{provider}/sources` — register a pull source (identifier,
  customer, interval_seconds, min_severity, max_items).
- `PATCH /sources/{id}` — enable/disable, retune interval/severity.
- `POST /sources/{id}/poll-now` — set a Redis flag `pull:trigger:{id}` the cron
  consumes with `GETDEL` on the next tick.
- `GET /sources` — list with health (`last_success_at`, `consecutive_errors`,
  `last_error`).
- `POST /connectors/{provider}/preview` — **read-only** sample-preview: take one
  pasted raw record, run it through `detect_source` + `parse` + field-map, return the
  `NormalizedAlert`, create no Incident. This is the "verify before you go live"
  step that de-risks every new source.

Frontend: a "Sources" admin page (list + health tiles + add/enable form), reusing
the existing connectors UI. Turn `vision_one`'s catalog entry into a pull-capable
source; flip `sentinelone`/`crowdstrike` `adapter_status` from `planned` to `live`
only once each has an adapter + parser.

## 9. Config-driven mapping (Phase 2 seam)

To onboard a source without writing a parser, add a `field_map` JSONB per source row
(already in the schema in 3.2): a declarative map from raw keys to
`title/severity/src_ip/user/rule_name/timestamp`, plus Vigil's `normalize_severity`
(maps `critical/5/emergency`, `high/4/error`, ... to the canonical band). A source
with a bespoke parser ignores `field_map`; a source without one uses it in front of
the normalizer. This is what stops "every new source needs Python + an image
rebuild" and is the real MSSP self-serve unlock.

## 10. Rollout

1. Ship dark: table + cron land with every source `enabled=False`, so the cron is a
   no-op (like `mailbox_poll` before email was configured).
2. Enable Vision One for one tenant. Confirm pulled Workbench alerts create RECEIVED
   incidents and reach the gate with richer data than the email path.
3. Keep `mailbox_poll` running as fallback. Once V1 pull is proven per tenant, turn
   that tenant's email forward off.
4. Add SentinelOne, then CrowdStrike (each: adapter + parser + flip `adapter_status`).

## 11. Testing

Pure unit tests (no stack needed, matching the project's test style):
- Adapter mapping: a fixture of a raw Workbench alert JSON to expected `PulledAlert`.
- `due()`: interval + `last_poll_at` + poll-now flag logic, and backoff on
  `consecutive_errors`.
- `dedup_key()` stability and the DB-backstop path.
- The new `visionone.parse(dict)` branch: JSON fixture to `NormalizedAlert`.

## 12. Commercial hardening checklist ("not a localhost app")

- **Multi-tenant isolation:** every pulled alert is attributed to `row.customer`;
  never default an unknown customer (mirror `mailbox_poll`'s strict attribution).
- **Secrets:** credentials stay in the Fernet-encrypted `Integration` store; no
  secrets in `.env` or source rows.
- **SSRF guard** on every admin-supplied URL (section 7) — non-negotiable before
  any `base_url` adapter ships.
- **Cost governance:** budget caps + `cost_usd` persistence so pull volume cannot
  run away with deep-tier spend.
- **Rate/backoff:** per-source interval + capped backoff; never hammer a failing
  console; never auto-disable silently (surface via health).
- **Observability:** per-source health (last success, consecutive errors) and
  per-adapter call spans (latency/success/errors).
- **Audit:** log source create/enable/disable and credential changes.
- **Never inherit** Vigil's `DEV_MODE` default-on auth bypass.
- **Human gate intact:** pulled alerts are proposals; only analyst Approve writes a
  verdict or fires a response (including any upstream write-back added in Phase 3).

## 13. Open decisions (pick before build)

1. Vision One Workbench **list endpoint path + query params** — confirm against your
   tenant's v3.0 API version (section 6.1 is the expected shape, unverified).
2. Whether the pull cron runs on the **shared worker** or a **dedicated ingest
   worker** (recommend shared first; split only if pull volume competes with
   synthesis jobs for `max_jobs`).
3. Dedup **retention window** (Redis TTL) vs relying on the DB backstop for older
   replays (default: 7 days Redis + permanent DB check on `external_id`).
4. Whether to add a lightweight **`provider` / `external_id` column** on `Incident`
   (indexed) instead of keeping them only in `raw_payload.pull`, for faster
   dedup/reporting. Recommended if pull becomes the primary source.
