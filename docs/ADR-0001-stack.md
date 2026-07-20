# ADR 0001 — Initial Stack Decisions

**Date:** 2026-05-23
**Status:** Accepted — **#1 (LLM router) and #8 (context shape) revised by ADR-0002.**
Decision #8's "two-stage cheap+expensive" alternative was, in fact, adopted in
production (two-tier fast classifier → deep synthesis); the default LLM is now
local Seneca (Ollama), not Claude-first. See ADR-0002.

## Context
Bootstrapping ISOC, an analyst workbench that replaces the LLM-driven `/analyze-alert`
SKILL loop with a deterministic backend pipeline that calls the LLM only at synthesis.

## Decisions

| # | Decision | Choice | Alternative considered |
|---|---|---|---|
| 1 | LLM router | **LiteLLM proxy** | Native multi-client, Anthropic-only |
| 2 | Case DB | **PostgreSQL 16** | SQLite, Qdrant-as-everything |
| 3 | Vector DB | **Share existing `alerts_v2` + `knowledge_base_v2`** with `source='isoc'` payload tag for traceability | Read-only on existing + new ISOC collections, fully separate |
| 4 | Frontend | **Next.js App Router + Tailwind + shadcn/ui** (bootstrapped on 14; **upgraded to 15.x**, pinned in `frontend/package.json`) | Vite+React SPA, SvelteKit |
| 5 | Auth | **Multi-user RBAC day 1** (admin / analyst / viewer) | Single-user session cookie, no-auth+Tailscale |
| 6 | Task queue | **ARQ (asyncio + Redis)** | Celery, FastAPI BackgroundTasks |
| 7 | Ingestion | **All four:** manual paste, HMAC webhook, file upload, email-to-investigation | Subsets |
| 8 | LLM context shape | **Markdown pre-rendered briefing** (~5-10K tokens) | Compact JSON, two-stage cheap+expensive |

## Consequences

- ISOC writes to existing Qdrant collections, tagged `source='isoc'` for safe rollback if a bug pollutes the store.
- ARQ + Redis adds one container but gives durable retries for slow REMnux jobs.
- Markdown context costs more tokens than compact JSON but produces analyst-grade narrative on the first try — fewer regen cycles.
- Multi-user RBAC day 1 means more schema upfront (Users, Roles, AuditLog) but no painful migration later.
- Email ingestion adds IMAP polling — flagged as "Phase 2" inside Pass 2 to keep MVP scope tight.

## Revisit when
- vLLM local hits >50 % of traffic → may add per-route routing rules in LiteLLM.
- Cases/month crosses 10K → revisit Postgres partitioning + audit log retention.
- More than 3 concurrent analysts → revisit single-server vs. multi-instance ARQ workers.
