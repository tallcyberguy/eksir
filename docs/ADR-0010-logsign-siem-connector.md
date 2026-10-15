# ADR 0010: Logsign SIEM connector (alert ingest, Lucene hunt, feed-list response action)

**Date:** 2026-08-19
**Status:** **Withdrawn** (2026-09-28). Design agreed 2026-08-19, never built; no code was
ever written and nothing in the repo references Logsign. Recorded here because the decision
not to build is itself part of the log. Superseded by nothing: the connector was simply
dropped from scope. One risk was never resolved, and would need resolving first if this is
ever revived: the response schemas below were derived from vendor documentation and were
never verified against a live Logsign instance.

First SIEM-category connector on the ADR-0006 framework. Logsign Unified SecOps exposes a
pull-only REST API (no webhooks) authenticated by an `api_key` **query parameter** against
`https://<LOGSIGN_HOST>`. Three capabilities land here: alert ingestion via `/get_incidents`,
SIEM queries via `/get_events` (analyst UI **and** gated LLM tool), and an IP-block response
action via `POST /feed_list`, plus flag-gated verdict write-back via `/set_incident_status`.

**Relates to:** ADR-0006 (connector framework: `Connector` + ingest registries), ADR-0007
(per-tenant creds, gate-only live tools, provider-routed actions), ADR-0009 (live hunt UI;
the injectable query panel built there is reused).

## Context

The connector framework is fully wired: adding a `providers/` module lights up the admin
credential UI, catalogue, and test-connection; a registered `ingest/` adapter joins the
`pull_ingest` ARQ cron (every minute, per-source interval + backoff) with two-layer dedup.
Microsoft Defender is the reference implementation end to end. Logsign differs in three ways:

1. **Pull-only, key-in-URL auth.** No OAuth, no webhook. The api_key must never appear in
   logs or error messages (URL scrubbing is an invariant of the adapter).
2. **Lucene query language** over a vendor-normalized `MainColumn.SubColumn` schema, not KQL.
   The hunt persona needs a Logsign-specific syntax guide and output contract.
3. **Tight per-endpoint rate limits** (30/min on the hot endpoints, 10/min on some, 1/min on
   `/get_alert_configs`). Polling cadence and tool row-caps must respect them.

## API surface (vendor docs, 2026-08)

| Endpoint | Method | Rate | Used for |
|---|---|---|---|
| `/test_api` | GET | 10/min | `test_connection` |
| `/get_incidents?last_run=<ISO8601>&query=&source=` | GET | 30/min | **alert ingest** (default returns alert data, `DataType:Alert`; `source=incident` needs Logsign >= 6.4.112) |
| `/get_events?query=&time_frame=&page=&size=` | GET | 30/min | **SIEM search** (hunt tool + analyst panel) |
| `/get_count`, `/get_columns` | GET | 30/min | aggregations (optional read tools) |
| `/feed_list?list_name=` + body `{value, expire_time}` | POST | 30/min | **IP block action** |
| `/feed_list?list_name=` | GET | 10/min | read-back / verify |
| `/set_incident_status?incident_id=` + body `{reason_id, comment}` | POST | 30/min | verdict write-back (1=FP, 2=TP, 3=No Action, 4=Resolved, 5=Other) |
| `/incident_comment` body `{incident_id, message}` | POST | 30/min | verdict comment |
| `/get_system_events`, `/data_collection_list`, `/get_alert_configs`, `/get_version` | GET | mixed | out of scope for v1 |

`time_frame` accepts `<number> <unit>` (`10 min`, `1 hour`, `1 day`; min<=1440, hour<=168,
day<=7) and `last_1_hour`-style aliases. Errors: 403 bad key/param, 400 bad JSON, 429 rate limit.

### Query language (for the hunt persona guide)

Lucene over `MainColumn.SubColumn` columns. Operators: `AND` (space = implicit AND), `OR`,
`NOT`, `( )` grouping, `[a TO b]` inclusive range (numbers, dates, IPs/subnets), `{a TO b}`
exclusive, `*` wildcard, `"quoted phrase"`, bare-value full-text search, `_exists_:(Col)`,
`.raw` subfield for exact keyword match. Vendor-verified examples:

```
Source.IP:([192.168.250.0 TO 192.168.250.255] OR [10.10.100.0 TO 10.10.100.255])
  Destination.Port:443 NOT Protocol.Name:TCP
  NOT Time.Generated:["2023-04-24 00:00:00" TO "2023-04-24 08:59:59"]

_exists_:(Source.MAC AND Source.UserName) NOT Source.UserName.raw:(Administrator OR *$)
```

Known columns: `Source.IP/Port/UserName/HostName/MAC/NatIP`, `Destination.IP/Port/NatIP`,
`Protocol.Name`, `Service.Name`, `Application.Name`, `Event.Info`, `Event.Category`,
`EventMap.Context/Type/SubType`, `EventSource.IP/Vendor`, `Time.Generated`, `DataType`,
`Alert.AlertUID/Category/Info`, `Severity.Name`.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Provider identity | key **`logsign_siem`**, category `siem`, label "Logsign SIEM" | `category="siem"` already legal in the `Connector` contract; no schema change. |
| 2 | Credentials | `AuthShape.TOKEN`: per-tenant `base_url` + `api_key` in the existing `integrations` table | `identifier` = customer. `STRICT_TENANT_CREDS` applies unchanged. api_key is scrubbed from every logged URL/error. |
| 3 | Ingestion | `pull_ingest` cron + `IngestAdapter` polling `/get_incidents` for **alert data** (default, no `source=` param) | Per-alert granularity matches the pipeline (decision: alert data, works on any Logsign version). Cursor `{"last_run": iso}`; `external_id` = alert UID; framework dedup (Redis NX 7d + DB backstop); no history backfill. |
| 4 | Normalization | Native OCSF-first parser `adapters/ocsf_logsign.py`, `parser_source="logsign_siem"` | `Severity.Name` -> OCSF `severity_id`; `Alert.Info` -> rule name; `Source.*`/`Destination.*` -> endpoints; `Time.Generated` -> timestamp. |
| 5 | Hunt output contract | Persona emits **`{query, time_frame}`** (Lucene), not KQL, when `source_product == "logsign_siem"` | Syntax guide above is injected into the hunt persona + `hunt/translate.py` gains a Logsign target. |
| 6 | Live query execution | **Both** analyst UI (Actions page + incident detail, reusing the ADR-0009 injectable panel) and a gate/deep-tier LLM tool `logsign_get_events` | Behind new flag `LOGSIGN_TOOLS_ENABLED` (default off), mirroring `DEFENDER_TOOLS_ENABLED`. Row caps: `size<=100`, bounded pages, per ADR-0007 decision 2 (gate-only loop). |
| 7 | Response action | `blocklist_ioc` (provider `logsign_siem`) -> `POST /feed_list` with `{value, expire_time}` | Proposed only for malicious IP IOCs on a TP verdict; executed solely by the analyst's Approve (or the direct action panel). `expire_time` default 0 (no expiry). |
| 8 | Feed list name | **Per-tenant setting**, default `blocked_ips` | Stored in a new nullable `integrations.config` JSON column (idempotent ALTER + Alembic migration), surfaced as an optional field on the admin connector form. First connector-specific setting; the column is generic for future connectors. |
| 9 | Verdict write-back | On Approve only: `set_incident_status` (false_positive->1, true_positive->2, benign->3 No Action) + `incident_comment` with the analyst summary | Behind `LOGSIGN_STATUS_WRITEBACK_ENABLED` (default off), mirroring the Defender write-back. Best-effort: failure never blocks the gate commit. |

**Invariant unchanged:** personas and the conversational manager only propose; the analyst's
Approve in `routes/cases.py` is the only path that writes a verdict, posts to Logsign, or
adds a feed-list entry.

## Build plan (PR per slice)

**PR 1: foundation + ingest.**
`adapters/logsign_adapter.py` (client: `LogsignError`, `ping`, `get_incidents`, `get_events`,
`get_count`, `feed_list_get/add`, `set_incident_status`, `incident_comment`; api_key scrubbing);
`adapters/connectors/providers/logsign.py` + entry in `providers.ALL`;
`adapters/ingest/logsign.py` + registration in `ingest/__init__._ensure_loaded`;
`adapters/ocsf_logsign.py` + `parser_adapter._native_parse_fn` branch + `KNOWN_PARSER_SOURCES`.
Tests: client (mocked httpx), ingest adapter, parser goldens; update the golden catalogue
snapshot in `test_connectors.py` (expected to fail until updated).

**PR 2: hunt.**
Lucene guide constant + hunt-persona wiring (`source_product` switch), `hunt/translate.py`
Logsign target, `logsign_get_events`/`logsign_get_count` tools + per-tenant handler factory
(mirrors `make_defender_handlers`), `LOGSIGN_TOOLS_ENABLED` in `settings.py` +
`deploy/docker-compose.yml`, manager-chat live-hunt state for Logsign incidents.
Tests: prompt contract, tool handler caps, translate parsing.

**PR 3: actions + UI.**
`_propose_logsign_actions` branch in `agent_routing.propose_response_actions`;
`provider == "logsign_siem"` branch in `cases.py:_run_proposed_actions`;
`integrations.config` column + admin form field for `feed_list_name`;
`routes/logsignactions.py` (incident-scoped: block, events query, history) +
Actions-page tab (block panel + query panel via the shared injectable panel);
`ACTION_LABEL` entry in `ProgressRail.tsx`; RBAC reuses the existing blocklist permission.
Tests: proposal builder, action dispatch, permission gating.

**PR 4: write-back.**
`verdict_to_logsign_reason` map + `mirror_verdict_to_logsign` called from `_commit_verdict`,
`LOGSIGN_STATUS_WRITEBACK_ENABLED` flag + compose wiring. Tests: mapping + best-effort failure.

## Open items

- **Response schemas are only partially documented.** `/get_incidents` and `/get_events`
  payload shapes (and whether `get_incidents` paginates) must be verified against a real
  instance before the parser goldens are trusted. XSOAR guidance: keep fetches under ~200.
- Exact alert UID field for dedup (`Alert.AlertUID` vs `DocID`) to confirm on live data.
- Column catalogue for the hunt guide is seeded from vendor docs; extend from live
  `/get_columns` output later if needed.
