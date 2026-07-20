# ADR 0004 — Analyst-direct IOC exclusion & full pipeline visibility

**Date:** 2026-06-10
**Status:** **Accepted & Implemented.** Shipped in code: `POST /incidents/{id}/iocs/exclude`
(`routes/cases.py`, `require_analyst`), the `ExcludeButton`, and the full-visibility timeline
(`timeline_events.level` / `step` / `duration_ms`, migration `0003_timeline_steps`). All decisions below are live.
**Builds on:** ADR-0003 (exclusions + per-customer scope; the deobfuscation/auto-tuning ADR), the timeline/`_emit` design

## Context

Two analyst-facing gaps:

1. The Technical-tab IOC table only offered **Block** (push to Trend Micro Vision
   One — a containment action). Analysts had no way to mark an IOC *known-good*
   and add it to our exclusion list without going to the admin Exclusions page.
2. The incident **Timeline** only rendered events the pipeline chose to emit,
   and most stages were silent unless they hit something. RAG-retrieve with no
   priors, YARA with 0 matches, and — critically — **failed enrichment subtasks
   (triage/IP-info/KB) were logged but never timelined**. An analyst couldn't
   tell "stage didn't run" from "ran silently" from "failed." (NightBeacon's
   live per-stage log was the reference UX.)

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Exclude action | New `ExcludeButton` beside Block in the IOC table | Opposite intent: suppress, not contain |
| 2 | Who can exclude | **Analysts directly** (not just admins) | New `POST /incidents/{id}/iocs/exclude` (`require_analyst`); the admin global-CRUD route stays admin-only |
| 3 | Default scope | **This customer** (with a global toggle) | Uses the ADR-0003 `exclusions.customer` column |
| 4 | URL/email handling | Collapse to host/domain | The exclusion filter matches url/email against domain rules; modal warns it broadens to the domain |
| 5 | Idempotency | Existing rule → `200 already_excluded`, not 409 | Also flags the matching `IOCRecord.excluded=True` |
| 6 | Timeline depth | **Full**: schema + stage checklist | `TimelineEvent` gains `level`, `step`, `duration_ms` |
| 7 | Instrumentation point | The `_safe_step` wrapper | Emits `running` on entry + `ok`/`error` with duration on exit for EVERY stage — including silent ones — without touching the ~20 in-step emits |
| 8 | Detail grouping | UI walks the ordered stream | A `*_running` opens a stage; later events nest under it until `*_done`/`*_failed`. No per-emit `step` tagging needed |
| 9 | Failure surfacing | Enrich subtask failures → `warn` timeline events | Was `logger.warning` only — the core "so I can see what failed" fix |
| 10 | Terminal event | `pipeline_done` (ok) / `pipeline_failed` (error) | Final checklist row |

## Why instrument the wrapper, not each step

`run_pipeline` already routes every stage through `_safe_step(...)`. Emitting
`running`/`ok`/`error` + duration there gives *guaranteed* start/done/failed
coverage for all six stages at one site, and the existing fine-grained emits
(deobfuscation, YARA, TI match, …) automatically become detail lines under the
currently-open stage in the UI. Minimal blast radius, maximal coverage.

## Schema / ops notes

- `timeline_events.level/step/duration_ms` added by idempotent boot backfill +
  migration `0003` (column-adds only — tables come from `create_all`, per the
  repo convention).
- The Timeline UI (`PipelineTimeline.tsx`) falls back to the old flat list for
  legacy events lacking `step`/`level`, so historical incidents still render.
- Polling stays at 3.5 s, so the checklist animates live as stages complete.
  True streaming (SSE) is a deferred enhancement.
- `cases.py` needed a `from pydantic import BaseModel` import for the new request
  model — `py_compile` won't catch a missing-name (only syntax); importing the
  module against real deps does. Worth a runtime import smoke-test before deploy.
