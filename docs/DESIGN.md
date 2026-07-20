# ISOC — Intelligent SOC

> Frontend SOC analyst workbench. Automates the deterministic parts of the `/analyze-alert`
> workflow locally, only asks the LLM at decision points. **Local-first & self-hostable**
> on a single machine. The shipped default routes the LLM to the **Claude API** via
> LiteLLM; a local model (Seneca 8B via Ollama) or a GPU-backed vLLM backend are optional
> swap-ins behind the same LiteLLM routing.

> **⚠️ This document is the 2026-05 design/planning record: kept for the "why",
> not the "what".** For the current implemented state, **`docs/PIPELINE.md` is
> canonical**; see also **ADR-0002** (local-LLM & ops), **ADR-0003** (EDR
> integrations + gate tools), **ADR-0006** (connector framework), and the diagrams
> `docs/architecture-components.png` + `docs/rag-pipeline-sequence.png`.
>
> **What changed since this was written (trust this list over the body below):**
> - **LLM default:** the shipped config routes **both tiers to Claude** via LiteLLM
>   (`isoc-deep` → `anthropic/claude-sonnet-4-5`, `isoc-fast` → `anthropic/claude-haiku-4-5`
>   in `config/litellm.config.yaml`). Local **Seneca** (8B via Ollama) and **vLLM**
>   are optional swap-ins, not the default.
> - **The LLM step is not "two-tier".** Step 6 is the **agent-persona pipeline**
>   (L1 → L2 → hunt? → forensics? → manager) in `pipeline/orchestrator.py`
>   `_step_synthesis`, up to 3-4 LLM calls on a true positive. The **manager stage
>   is deterministic (no LLM)** and there is **no "report polish" call**. See
>   PIPELINE.md → "Agent personas & human gate".
> - **A human sign-off gate** (`awaiting_signoff`) replaces the old "analyst review"
>   step: personas + the conversational manager only *propose*; the analyst's Approve
>   is the only thing that commits a verdict or fires a response action.
> - **Multi-tenancy + RBAC shipped.** Tenants, roles (admin/analyst/viewer), and
>   per-tenant credential isolation (`STRICT_TENANT_CREDS`, fail-closed for unmapped
>   customers) are implemented; section 8's "single-user, single-org" line is obsolete.
> - **Ingestion is moving to a connector-based, OCSF-first model** (`pipeline/ocsf.py`
>   + `adapters/connectors/`; see ADR-0006). The legacy vendored parsers
>   (`vendor/alert-memory-mcp/parsers/`) are being **retired**; new connector alerts
>   normalize to OCSF, not the legacy `NormalizedAlert`.
> - Context is a **markdown briefing** (`briefing.py`), not compact JSON;
>   **dynamic sandboxing was removed** (static-only forensics); each case carries
>   fused **confidence/threat scores** (`pipeline/scoring.py`; see PIPELINE.md →
>   "Case scores").

---

## 1. Why a new app (and not extend the prior console / MCP)

| Current state | Limitation |
|---|---|
| `analyze-alert` skill drives the whole workflow inside the model | Every alert consumes ~10-30K tokens. Most steps are deterministic. |
| MCP (`alert-memory-mcp`) is a tool surface, not a UI | No case management, no timeline, no analyst-facing visualizations |
| Triage scripts run from CLI | No persistence of investigation state, no asynchronous enrichment |
| `auto_close.py` only runs when the skill remembers to call it | No structured handoff, no audit trail |

**ISOC inverts the control flow.** The *app* drives the workflow deterministically;
the LLM is called **only** when synthesis or judgment is needed. Token usage drops by
~70-90 % per investigation.

---

## 2. High-level architecture

> Current rendered topology: `docs/architecture-components.png`. ASCII below is
> the original sketch (the LLM layer defaults to the Claude API via LiteLLM;
> local Ollama/Seneca and vLLM are optional swap-ins).

```
                       ┌───────────────────────────────────────┐
                       │   Next.js Frontend (SOC-console UI)   │
                       │   Dashboard / Cases / Incidents /     │
                       │   Forensics / Actions / Reports       │
                       └──────────────┬────────────────────────┘
                                      │  HTTPS / WebSocket
                       ┌──────────────▼────────────────────────┐
                       │   FastAPI Backend (orchestrator)      │
                       │   - Investigation state machine       │
                       │   - Reuses alert-memory-mcp modules   │
                       │   - Calls triage.py, REMnux MCP, KB   │
                       └──┬───────────────┬───────────┬────────┘
                          │               │           │
                          │               │           │
              ┌───────────▼──┐   ┌────────▼────┐  ┌──▼──────────────┐
              │ PostgreSQL    │   │  Qdrant     │  │ LiteLLM proxy   │
              │ (cases, audit,│   │  (vectors — │  │ Claude API ──┐  │
              │  webhooks)    │   │   reuse v2) │  │ vLLM local ──┤  │
              └───────────────┘   └─────────────┘  │ OpenAI compat┘  │
                                                   └──────┬──────────┘
                                                          │
                                  ┌───────────────────────▼─────┐
                                  │  REMnux container (forensics)│
                                  │  - triage (fast lookup)      │
                                  │  - static (capa/floss/yara)  │
                                  │  - (dynamic REMOVED; static- │
                                  │    only) — needs >=8GiB RAM  │
                                  └──────────────────────────────┘
```

---

## 3. Investigation pipeline (the optimised RAG)

The current `analyze-alert` SKILL.md is **8 sequential LLM-driven steps**. ISOC turns
this into a **state machine** the backend executes. The deterministic front half now
runs **seven code steps** (parse, auto-close pre-check, dedup/RAG, enrich, entity
resolution, correlate, decision) with **no LLM**; only an inconclusive decision gate
reaches the LLM.

> **This box diagram is the original 2026-05 sketch** (kept for intent). The real
> step 6 is the **agent-persona pipeline** (L1 → L2 → hunt? → forensics? → manager),
> up to **3-4 LLM calls** on a true positive, with a **deterministic manager stage**
> and **no "report polish" call**. `docs/PIPELINE.md` is the canonical current-state
> description.

```
[1] INGEST          → parser detects source, normalizes fields            [no LLM]
[2] AUTO-CLOSE      → autoclose_adapter YAML check                        [no LLM]
[3] DEDUP / EXACT   → store_adapter.find_exact_match()                    [no LLM]
[4] ENRICHMENT      → parallel: triage + ipinfo + vector top-k + KB       [no LLM]
    ENTITY + CORREL → OCSF entity resolution + optional correlation       [no LLM]
[5] DECISION GATE   ┐
                    │ if EXACT_MATCH score≥0.9 AND human_verified → auto-suggest verdict
                    │ if N_WAY_AGREEMENT ≥4/5 → auto-suggest verdict      [no LLM]
                    │ if AUTO_CLOSE fires + clean TI → auto-suggest verdict
                    │ else ↓
[6] AGENT PERSONAS  → L1 → L2 → hunt? → forensics? → manager (manager is
                      deterministic). See PIPELINE.md                    [3-4 LLM calls]
[7] HUMAN GATE      → parks at awaiting_signoff; analyst Approve is the only
                      commit point (personas only propose)                [no LLM]
[8] INDEX           → store.index_alert() at analyst approval             [no LLM]
```

**Token budget per investigation:** briefing in / ~50 out for fast-classifier
only; ~3-8K in / ~1-2K out when deep synthesis runs (vs. 15-30K in the old
SKILL loop). The LLM sees a **pre-rendered markdown briefing** (`briefing.py`),
not raw tool output. See PIPELINE.md "Token budget per investigation" and ADR-0002.

---

## 4. UI structure

```
THREAT OPS              RESPONSE              SETTINGS
├ Dashboard             ├ Actions             ├ Administration
├ Cases                 │   └ Playbooks           ├ LLM Backends
├ Incidents             └ Reports                 ├ Webhook Sources
│  ├ Incidents                                    ├ Auto-close Rules
│  ├ Indicators of Compromise                     ├ KB Editor
│  └ Personal Identity Info                       └ Users
└ Forensics
   ├ Triage (fast IOC lookup — IP/hash/domain/URL)
   └ Static Analysis (PE / Office / PDF / scripts via REMnux; file-type-aware
      tool waves + YARA-Forge; dynamic detonation removed for safety)
```

**Incident detail view** uses these tabs: `Summary | Details | Technical Analysis |
Remediations | Related Events | Timeline | Actions`.

---

## 5. Decisions to lock in

The questions in the next message cover the high-leverage choices.

| # | Decision | Why it matters |
|---|---|---|
| 1 | LLM router (LiteLLM vs custom) | Affects how Claude/vLLM/OpenAI swap works |
| 2 | DB for case state (PostgreSQL vs SQLite) | Affects deploy complexity vs scale headroom |
| 3 | Vector DB sharing (reuse existing vs new collections) | Affects whether ISOC inherits 3 months of analyst-verified verdicts |
| 4 | Frontend stack (Next.js vs Vite+React vs SvelteKit) | Affects build complexity and your familiarity |
| 5 | Auth model (single-user vs multi-tenant from day 1) | Affects schema design |
| 6 | Task queue (FastAPI BG vs ARQ vs Celery) | Affects how long-running enrichment behaves |
| 7 | Webhook auth (HMAC vs API key vs IP allowlist) | Affects ingestion security |

---

## 6. Deployment shape (Hetzner GPU)

Single `docker-compose.yml` on the Hetzner host:

```
services:
  caddy           # auto-HTTPS reverse proxy
  isoc-frontend   # Next.js static export or SSR
  isoc-backend    # FastAPI + uvicorn
  postgres        # cases, audit log
  qdrant          # vector DB (mounted volume from existing alert-memory-mcp)
  litellm         # LLM router (Anthropic + vLLM + OpenAI compat)
  vllm            # optional — GPU-backed local model (Qwen2.5-72B / Llama-3.3-70B)
  redis           # task queue + cache
  remnux          # malware analysis sandbox (network-isolated)
```

GPU plan recommendation for vLLM:
- **Min**: 1× RTX 4000 SFF Ada (20GB VRAM) → Qwen2.5-32B-Instruct AWQ-4bit @ 8K ctx
- **Comfort**: 1× RTX 6000 Ada (48GB VRAM) → Qwen2.5-72B-Instruct AWQ-4bit @ 32K ctx
- **Future**: 2× RTX 6000 Ada → Llama-3.3-70B FP8 @ full ctx

---

## 7. Folder layout

```
isoc/
├── docs/                  # this file, ADRs, runbooks
├── backend/
│   ├── isoc_api/
│   │   ├── main.py        # FastAPI app
│   │   ├── routes/        # /alerts, /cases, /forensics, /admin
│   │   ├── pipeline/      # state machine: parse → autoclose → dedup → enrich →
│   │   │                  #   entities → correlate → decision → _step_synthesis
│   │   ├── llm/           # LiteLLM client + prompt templates + read-only tools
│   │   ├── adapters/      # alert-memory-mcp wrappers, EDR connectors, and the
│   │   │                  #   forensics adapters (remnux_adapter.py, triage_adapter.py;
│   │   │                  #   there is NO backend/isoc_api/forensics/ package:
│   │   │                  #   the static-file subsystem is routes/forensics.py + these)
│   │   └── db/            # SQLAlchemy models, migrations
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
├── frontend/
│   ├── app/               # Next.js App Router pages
│   ├── components/        # hex cards, status pills
│   ├── lib/api.ts         # backend client
│   ├── styles/            # the dark cyber theme
│   └── Dockerfile
├── scripts/               # symlinks/wrappers to existing triage.py etc.
├── config/                # LiteLLM config, Caddyfile, .env.example
├── deploy/
│   ├── docker-compose.yml
│   └── README.md
└── README.md
```

---

## 8. What we will NOT do (initially)

- Re-implement parsers/normalizer/auto_close — **adapter-wrap the existing ones**
- Re-implement Qdrant client — **import `alert-memory-mcp/store.py`**
- Build a new triage engine — **call `triage.py` via subprocess + parse JSON**
- Train a custom model — **route to Claude API + optional local vLLM**
- ~~Multi-tenant SaaS plumbing — single-user, single-org~~ **(SUPERSEDED: full
  multi-tenancy + RBAC (admin/analyst/viewer) + per-tenant credential isolation via
  `STRICT_TENANT_CREDS` shipped; see the banner at the top of this file.)**

This keeps the blast radius small. The existing `/analyze-alert` SKILL keeps working
unchanged; ISOC is a separate consumer of the same building blocks.
