# ADR 0003 — Payload deobfuscation, YARA-on-content & exclusion auto-tuning

**Date:** 2026-06-10
**Status:** **Accepted & Implemented.** Shipped in code: `pipeline/deobfuscate.py`,
`pipeline/yara_scan.py`, the `exclusion_suggestions` table + `exclusions.customer` column
(migration `0002_exclusion_autotune`), and the verdict-hook auto-tuning. All decisions below are live.
**Builds on:** ADR-0002 (pipeline + REMnux operational findings)

## Context

The alert pipeline extracted IOCs only via regex over raw text, so anything
hidden inside an **encoded payload** (base64 PowerShell `-EncodedCommand`, gzip
chains, hex, percent/escape encodings, char-code arrays) was invisible — the C2
inside never reached triage. YARA-Forge existed but only ran on **manually
uploaded forensics files**, never on alert content. Separately, false-positive
suppression was entirely manual.

Inspiration: Binary Defense **NightBeacon** (pre-analyst deobfuscation +
classification, per-environment FP auto-tuning, human-in-the-loop containment).
**Revoke-Obfuscation was evaluated and rejected as a "deobfuscator"** — it is an
obfuscation *detector/scorer* (AST + GBM model), not a decoder, and would
require baking PowerShell into the REMnux image for only a score. We implement
an equivalent transparent heuristic scorer in Python instead.

## Decisions

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Decoding | New pure-Python `pipeline/deobfuscate.py` — recursive layered decode (base64/UTF-16LE/gzip/hex/percent/`\x`/`\u`/char-array) | No LLM, no container; runs on every alert |
| 2 | Decoded IOCs | Re-run `ioc_extract` on each decoded layer; **merge into the IOC set inside `_step_enrich` before triage/exclusions** | Hidden C2s get full TI enrichment |
| 3 | Obfuscation score | Heuristic blend (Shannon entropy + symbol density + marker hits), labelled "not an ML verdict"; headline = max(original, decoded) | Revoke-Obfuscation **not** used |
| 4 | YARA-on-content | `pipeline/yara_scan.py` scans script/command fields **and** decoded payloads via REMnux `yara_forge` (core ruleset only) | Per user choice: scan any non-empty script/command field |
| 5 | YARA safety | In-process SHA256 LRU cache + concurrency semaphore + total-time budget + fail-soft | YARA is a bonus signal, never a pipeline gate |
| 6 | AI surfacing | New briefing section + Tier-1/Tier-2 prompt contract; decoded IOCs added to the hallucination allow-set | Report explains the payload; UI `DeobfuscationPanel` renders it |
| 7 | Exclusion auto-tuning (F8) | `ExclusionSuggestion` table; verdict hook learns from repeated FP/Benign verdicts; **suggest-only, human-approved** | Mirrors NightBeacon's no-autonomous-action ethos |
| 8 | Per-customer scope | New nullable `exclusions.customer` column; scoped rules only match same-customer incidents; suggestions key on `(value, ioc_type, customer)` | One tenant's noise never silences another |

## Why max(original, decoded) for the score

A base64 `-EncodedCommand` blob is mostly alphanumeric, so it scores *low* on
the outer text; once decoded to `IEX (...).DownloadString(...)` it scores
*high*. Reporting only the "before" score would understate the threat, and a
naive before/after "delta" reads as negative ("decoding made it worse") which
confuses analysts. The headline is therefore the **most obfuscated thing seen,
before or after decoding**, plus a separate `encoded_layers` count for the
hiding signal.

## Guardrails (F8)

A suggestion is created only for exclusion-eligible types (ip/domain/hash) and
**never** for an IOC that (a) ever appeared in a TP incident, or (b) was flagged
malicious by threat intel on the contributing incident. Promotion to the review
queue requires corroboration: `fp_count ≥ 3` across `≥ 2` distinct rules. A
dismissed suggestion is never resurrected. Nothing is ever auto-applied.

## Operational notes

- **YARA load.** Scanning every alert with a script/command field puts REMnux in
  the hot path more often; the SHA256 cache absorbs the (highly repetitive) SOC
  stream. Watch scan latency; REMnux still needs ≥ 8 GiB (ADR-0002 #6).
- **Schema.** `exclusion_suggestions` is created by `create_all`; the
  `exclusions.customer` column is added by an idempotent boot backfill and by
  migration `0002_exclusion_autotune` (alembic-only path).
- **Files.** Decoded blobs are written under `<workspace>/deob` (shared REMnux
  mount, same as forensics) and always cleaned up.
