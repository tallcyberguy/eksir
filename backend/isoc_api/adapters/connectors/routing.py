"""Deterministic parser routing (ADR-0006 decision #3 — the P0 fix).

`parsers.detect_source` picks a parser by sniffing the raw payload's top-level keys in an ordered
if-chain. That is fine with a handful of sources but becomes a silent-mis-routing minefield as the
catalogue grows and vendors share discriminating keys (`id`, `severity`, `alerts`). The pull path
already *declares* its source (`PulledAlert.source_hint`, set by the ingest adapter), so we should
route on that declaration and only sniff when the source is genuinely unknown (a pasted/webhook
alert).

`resolve_parser_source` is the pure decision; `parser_adapter` does the actual dispatch. Keeping
the decision pure (a `detect` callable is injected) makes it unit-testable without importing the
vendored parser package.
"""

from __future__ import annotations

from collections.abc import Callable

# The vendored `parsers` package (vendor/alert-memory-mcp/parsers/) that we can dispatch to by
# name. Each is an importable submodule exposing `parse(raw, customer=None)`.
KNOWN_PARSER_SOURCES: frozenset[str] = frozenset(
    {
        "qradar",
        "wazuh",
        "fortigate",
        "syslog",
        "visionone",
        "sentinelone",
        "crowdstrike",
        "microsoft_defender",
    }
)


def resolve_parser_source(
    source_hint: str | None,
    known_sources: frozenset[str],
    detect: Callable[[], str],
) -> tuple[str, str]:
    """Decide which parser source to use.

    Returns `(source, reason)` where `reason` is `"declared"` when the connector's declared
    `source_hint` matches a parser we have, or `"detected"` when we fell back to key-sniffing.
    A declared source we do NOT have a parser for is ignored (we sniff), so a new connector
    without a parser yet degrades gracefully to the generic/field_map path.
    """
    if source_hint and source_hint in known_sources:
        return source_hint, "declared"
    return detect(), "detected"
