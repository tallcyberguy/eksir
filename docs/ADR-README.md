# Architecture Decision Records (ADRs)

This directory records the significant architecture decisions behind ISOC / EKSIR. Each ADR captures
the context, the decision, and its consequences at a point in time. An ADR is a historical record:
where the design later changed, the newer ADR carries a `Supersedes` / `Relates to` line rather than
editing the old one. Status reflects what actually shipped in code, not just what was agreed.

> **Numbering note:** ADRs 0007 and 0008 were originally filed as duplicate `0003` and `0004`. They
> have been renumbered so every number is unique. `ADR-0003` now refers solely to the
> deobfuscation / auto-tuning record, and `ADR-0004` solely to the analyst-exclude record;
> cross-references elsewhere in `docs/` were updated to match.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](ADR-0001-stack.md) | Initial stack decisions | Accepted (#1 LLM router + #8 context shape later revised by ADR-0002) |
| [0002](ADR-0002-local-llm-and-ops.md) | Local LLM migration & operational hardening | Accepted (supersedes parts of ADR-0001) |
| [0003](ADR-0003-deobfuscation-and-autotuning.md) | Payload deobfuscation, YARA-on-content & exclusion auto-tuning | Accepted & Implemented |
| [0004](ADR-0004-analyst-exclude-and-pipeline-visibility.md) | Analyst-direct IOC exclusion & full pipeline visibility | Accepted & Implemented |
| [0005](ADR-0005-vision-one-workbench-enrichment.md) | Vision One workbench / OAT auto-enrichment (read-only) | Implemented (read-only path, behind default-off flags; write-back deferred) |
| [0006](ADR-0006-connector-framework.md) | Durable connector framework (typed contract + OCSF normalization) | Accepted; P0 + registry flip landed, P1 (OCSF) started, P2 not started |
| [0007](ADR-0007-edr-integrations-and-gate-tools.md) | Multi-tenant EDR/XDR integrations & gate-only live tools | Implemented for Microsoft Defender (the SentinelOne design in the body was not built as written) |
| [0008](ADR-0008-procedures-library.md) | Procedures (SOP) library injected into persona prompts | Proposed (design only, not implemented) |
| [0009](ADR-0009-live-hunt-and-manager-routing.md) | Pre-gate live hunt, expanded read tools & manager-owned hunt routing | Proposed (design only, not implemented; amends ADR-0007 #2) |

## Status vocabulary

- **Proposed**: design captured, not yet built.
- **Accepted**: decision agreed; may or may not be fully built yet (see the record's own banner).
- **Accepted & Implemented**: agreed and fully shipped in code.
- **Implemented**: realized in code (a record may note a scope caveat, e.g. ADR-0007 shipped against
  Microsoft Defender rather than the SentinelOne example the design was written around).
- **Supersedes / Relates to**: see the header of each record for how the decisions connect.
