# ADR 0008 — Procedures (SOP) library injected into persona prompts

**Date:** 2026-06-21
**Status:** Proposed (design only — not implemented)
**Relates to:** `docs/PIPELINE.md` (agent-persona synthesis), `pipeline/briefing.py`,
`pipeline/agent_routing.py`, `adapters/autoclose_adapter.py`

## Context

The persona pipeline (L1 → L2 → hunt? → forensics? → manager) reasons from a
pre-rendered markdown briefing (`pipeline/briefing.py`) plus a static per-persona
system prompt (`llm/prompts.py`). What it *cannot* do today is apply
**house-specific standard operating procedures** — "when you see a Kerberoasting
pattern, check these three things and prefer this disposition", "for phishing with
a credential-harvest landing page, follow this containment checklist". Analysts
carry that playbook knowledge in their heads; the LLM reasons generically.

We want a **procedures library**: deterministically-selected SOP snippets,
matched to an alert's characteristics, injected into the relevant persona's
prompt so the model follows the house playbook instead of improvising.

This is distinct from three things already in the system (see "Distinctions"
below) and must not duplicate them.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Source of truth | **Repo markdown files** with YAML frontmatter; DB-stored procedures merged at selection time as a later extension | Mirrors the `auto_close_rules.yaml` + `AutoCloseRule` table hybrid in `autoclose_adapter`. Start file-only; no UI needed to ship. |
| 2 | Selection | **Pure function over the normalized alert + enrichment** (`pipeline/procedures/registry.py`) | Same testable shape as `agent_routing.py` — LLMs reason, code decides what's injected. |
| 3 | Injection | **One new section in `briefing.render(...)`** (`## Applicable procedures`); briefing is already shared by every persona | No persona-prompt surgery, no contract change. |
| 4 | MITRE-matched procedures | Injected only into **post-L2 stages** (hunt / forensics / manager) | MITRE techniques aren't known until L2 emits `AnalysisVerdict.mitre_techniques` — an ordering constraint, see below. |
| 5 | Token control | Per-section count cap + per-body truncation + a `priority` field for tie-breaking | Matches `briefing.py`'s `_MAX_KB_HITS` / `_MAX_TRIAGE_BLOCKS` discipline. |
| 6 | Transparency | Emit a `procedures_selected` timeline event; stash selected ids in `enrichment["procedures"]` | Same pattern as `deobfuscation` / `sensitive_rule`; surfaces in the UI rail. |

## Procedure format

```
pipeline/procedures/
  registry.py
  kerberoasting.md
  phishing_credential_harvest.md
  ransomware_canary.md
```

Each file: YAML frontmatter (matcher + metadata) then a markdown body.

```markdown
---
id: kerberoasting
title: Kerberoasting / TGS-REP roasting
priority: 70                       # higher wins when the section is capped
applies_to: [l2, hunt]             # which personas see it; omit = all post-match stages
match:                             # ANY group matching selects the procedure
  source_product: [wazuh, sentinelone]
  mitre: [T1558.003]               # post-L2 only (see ordering constraint)
  rule_name_contains: ["kerberos", "TGS", "4769"]
  event_keywords: ["ticket", "RC4", "0x17"]
---
When TGS requests show RC4 (0x17) encryption for many SPNs from one account:
- Confirm the requesting account is not a known service-scanning tool.
- Check for a preceding LDAP SPN enumeration from the same host.
- Disposition guidance: a single 4769 with RC4 is weak; a burst across SPNs from
  a non-service account is a strong TP signal — prefer escalation over auto-close.
```

`registry.py` loads + validates these at startup (fail-soft: a malformed file is
logged and skipped, never crashes the pipeline), exposing:

```python
def select(normalized, enrichment, *, stage: str, mitre: list[str] | None = None) -> list[Procedure]:
    """Pure, deterministic. Returns procedures whose match group fits this alert
    and whose `applies_to` includes `stage`, ordered by priority desc, capped."""
```

## Selection & the MITRE ordering constraint

Matchers are evaluated against fields ISOC already has at the relevant point:

- **Pre-L2 (L1, L2 input):** `source_product`, `rule_name_contains`,
  `event_keywords` (over `event_name` / `event_description` / raw), IOC types
  present, the sensitive-rule flag. No MITRE yet.
- **Post-L2 (hunt, forensics, manager):** all of the above **plus** `mitre`,
  matched against `AnalysisVerdict.mitre_techniques` from the L2 stage.

This is a real constraint, not a nicety: a procedure keyed only on MITRE cannot
inform L2 itself (L2 is what produces the technique list). Such procedures simply
won't select for L2 and will select for the downstream stages. The `applies_to`
field makes the intended scope explicit.

## Injection

`briefing.render(...)` gains an optional `procedures: list[Procedure] | None`
argument and renders a section (capped like the others):

```python
# briefing.render(...) — new section, same idiom as KB hits
if procedures:
    lines.append("## Applicable procedures")
    lines.append("_House SOPs selected for this alert's characteristics. "
                 "Follow them unless the evidence clearly contradicts._")
    for p in procedures[:_MAX_PROCEDURES]:
        lines.append(f"### {p.title}")
        lines.append(p.body[:_MAX_PROCEDURE_CHARS])
    lines.append("")
```

Both render call sites pass procedures:

- `orchestrator._step_synthesis._render(...)` — select on alert surface for the
  L1/L2 briefing; after L2, a second `select(..., stage="hunt", mitre=...)` pass
  feeds the hunt/forensic prompts (which already take the rendered briefing).
- `manager_chat.render_case_briefing(...)` — select with the now-known MITRE so the
  gate conversation carries the same playbook.

A `procedures_selected` event records which ids fired, for the UI and audit.

## Distinctions — what this is NOT

- **Not the KB (Qdrant `knowledge_base_v2`).** KB hits are *semantically
  retrieved* reference material (bge-m3 + Qdrant), ranked by similarity, already
  in the briefing as "Knowledge Base hits". Procedures are *deterministically
  selected* by explicit matchers and read as instructions, not references.
  Different mechanism, different intent — keep them separate sections.
- **Not auto-close rules.** Auto-close YAML/DB rules *decide a verdict and short-
  circuit the LLM*. Procedures never decide anything — they shape how the LLM
  reasons. A procedure can say "prefer escalation"; it cannot close a case.
- **Not Claude Code skills.** The backend (FastAPI/ARQ) cannot invoke `.claude`
  skills like `analyze-alert` at incident time — those run in the Claude Code
  harness. Procedures are backend-owned markdown. Existing skills are useful
  *source material* to author procedures from, nothing more.

## Token control

- `_MAX_PROCEDURES` per section + `_MAX_PROCEDURE_CHARS` per body, both bounded so
  a broad-matching alert can't balloon the prompt past the context window
  (the same failure mode `briefing.py` already guards: an 8k-window model drops
  the *front* — the system prompt — on overflow).
- `priority` desc decides which procedures survive the cap. Selection is logged so
  a dropped procedure is visible, never silent.

## Consequences

- House playbooks become enforceable in synthesis without retraining or per-alert
  prompt edits — author a markdown file, it applies to every matching alert.
- Fully deterministic and unit-testable (the `select()` function), like
  `agent_routing`; no new external I/O, no new failure mode beyond a skipped bad file.
- Stays inside the invariant: procedures only *shape reasoning*; they never commit
  a verdict or fire an action.
- One ordering subtlety to document for authors: MITRE matchers only apply post-L2.

## Build order (when picked up)

1. `pipeline/procedures/registry.py` + the markdown format + 2–3 seed procedures.
   *Pure, unit-testable in isolation — no pipeline wiring yet.*
2. Add the `procedures` arg + section to `briefing.render(...)`; wire the alert-
   surface selection into `_step_synthesis._render(...)`. Emit `procedures_selected`.
3. Post-L2 MITRE-aware pass into hunt/forensic prompts + `manager_chat`.
4. (Optional, later) DB-stored procedures + admin UI, merged in `select()` exactly
   as `autoclose_adapter` merges DB rules with YAML.

Phase 1 ships and is testable with zero pipeline impact. Phase 2 is the smallest
change that delivers value (surface-matched SOPs in L2). Phases 3–4 are additive.

## Revisit when
- Procedure bodies routinely exceed the per-section cap → add semantic ranking
  (embed procedures, rank by alert similarity) instead of static priority.
- Analysts want to edit procedures without a deploy → promote Phase 4 (DB + UI).
- A procedure needs to *gate* flow (not just advise) → that belongs in
  `agent_routing.py` / auto-close, not here. Keep procedures advisory.
