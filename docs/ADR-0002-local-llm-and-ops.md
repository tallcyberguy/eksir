# ADR 0002 — Local LLM migration & operational hardening

**Date:** 2026-06-03
**Status:** Accepted
**Supersedes:** parts of ADR-0001 (#1, #8) and the "Hetzner GPU / Claude-first" framing in DESIGN.md

## Context

ADR-0001 assumed a Claude-API-first deployment with optional local vLLM on a
Hetzner GPU box. The project has since moved to **local-first, self-hosted on a
single machine**, with the hosted Claude path kept only as an optional fallback.
This ADR records the decisions and operational findings from that migration.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Default LLM | **Local Seneca** (`seneca-cyber`, Llama-3.1-8B cyber fine-tune, Q4_K_M) via **Ollama** | Air-gap capable, zero per-alert API cost |
| 2 | Context window | **`num_ctx = 16384`** baked into the Ollama Modelfile (was 8192) | See "Why 16k" below |
| 3 | Embeddings (RAG) | **bge-m3** via Ollama (`OLLAMA_URL`), unchanged | Fully decoupled from the synthesis LLM — see ADR note |
| 4 | LLM tiering | **Two-tier confirmed in prod:** fast classifier (Tier-1) → deep synthesis (Tier-2) | Reverses ADR-0001 #8's "not chosen" note — it *was* implemented |
| 5 | Model routing | Two supported paths: **(a) Admin-UI direct** (bypasses LiteLLM, one model for both tiers) and **(b) LiteLLM routing** (per-tier models, e.g. `isoc-fast`→Seneca, `isoc-deep`→Claude) | `client.py` honours the admin `llm_config` row first |
| 6 | REMnux host memory | **≥ 8 GiB** required for the forensics tool wave | Was 2.85 GiB → caused OOM kills |

## Why 16k context

The forensics and noisy-multi-IOC alert briefings can exceed an 8k window. The
OpenAI-compatible endpoint EKSIR uses **cannot override `num_ctx` per request**,
so Ollama silently truncates oversized prompts **from the front** — dropping the
system prompt (the analyst contract, report template, JSON-only instruction)
first. Verified empirically: at 8192 a ~7.5k-token briefing lost the system
prompt; at 16384 it is retained. `num_ctx=16384` covers the large majority of
real alerts; `briefing.py` section caps bound the rest.

## Operational finding — REMnux OOM (FLOSS failures)

FLOSS was failing with empty stderr + nonzero exit (the SIGKILL/OOM signature)
while succeeding when run alone. Root cause: the static tool wave runs **all
tools concurrently** (`asyncio.gather`) and the Docker VM had only ~2.85 GiB.
FLOSS (vivisect) + capa + yara-full together exhausted RAM. **Fix: raise Docker
Desktop memory to ≥ 8 GiB.** Optional follow-ups (not yet applied): bound wave
concurrency with a semaphore; serialise the two vivisect tools (floss + capa).

## Known limitation — 8B synthesis quality

On the deep-synthesis tier the 8B model under-incorporates rich sections (e.g.
capa capabilities) and can produce a header verdict inconsistent with its own
reasoning. This is a model-capability ceiling, **not** a context-truncation
issue. Recommended (not yet applied):
- Deterministically merge `capa.attack_techniques` into `synthesis.mitre_techniques`
  in `routes/forensics.py` (change the `or` fallback to a union).
- Harden `STATIC_SYSTEM_PROMPT` to force enumeration of capa capabilities.
- For highest fidelity, route the deep tier to Claude or a larger local model
  (Qwen2.5-72B) while keeping Seneca on the fast/classifier tier.

## RAG is independent of the LLM config

Changing the Admin-UI LLM endpoint/model does **not** affect RAG. Embeddings go
through `bge_embedder.py` (its own `OLLAMA_URL`, hardcoded `bge-m3`); retrieval
hits Qdrant via `QDRANT_URL`. The `llm_config` table is read only by
`llm/client.py`. RAG quality is unchanged whether synthesis runs on Seneca or Claude.

## Consequences

- Fully local, air-gap-capable deployment; no telemetry leaves the host.
- Per-alert LLM cost ≈ 0 on the local path.
- Forensics now requires a host with ≥ 8 GiB allocated to Docker.
- Deep-synthesis quality on 8B is the main tradeoff vs Claude — mitigations above.

## Revisit when
- Deep-synthesis accuracy on 8B proves insufficient → adopt the LiteLLM hybrid
  (Seneca fast tier + Claude/Qwen-72B deep tier).
- Briefings routinely exceed 16k tokens → raise `num_ctx` to 32k or add a
  token-budget guard in `client.py`.

## Reference diagrams
- `docs/architecture-components.png` — full component/service topology
- `docs/rag-pipeline-sequence.png` — alert RAG pipeline sequence
