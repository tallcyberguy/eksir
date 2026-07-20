"""Fine-grained connector capability verbs + projection to the legacy coarse taxonomy (ADR-0006).

The legacy catalogue models three coarse capabilities (`enrich`/`respond`/`hunt`, from
`registry.py`). That cannot distinguish host-isolation from user-disable from case-push — all of
which collapse to `respond` — so it cannot support per-action RBAC/audit/policy as response
actions multiply. This module introduces the fine verb enum and a projection back to the coarse
words, so the fine taxonomy is the source of truth while today's UI badges and gating keep working
unchanged.

Pure — no I/O.
"""

from __future__ import annotations

from enum import StrEnum

# Coarse words the legacy registry + UI already use.
ENRICH = "enrich"
RESPOND = "respond"
HUNT = "hunt"


class Capability(StrEnum):
    # read-only enrichment (auto-runnable, coarse=enrich)
    PULL_ALERTS = "pull_alerts"
    ENRICH_IOC = "enrich_ioc"
    GET_ALERT_DETAIL = "get_alert_detail"
    # telemetry query (coarse=hunt)
    HUNT_QUERY = "hunt_query"
    # containment / effect actions (analyst-gated, coarse=respond)
    ISOLATE_HOST = "isolate_host"
    RELEASE_HOST = "release_host"
    SCAN_ENDPOINT = "scan_endpoint"
    KILL_PROCESS = "kill_process"
    DISABLE_USER = "disable_user"
    BLOCK_HASH = "block_hash"
    BLOCK_IOC = "block_ioc"
    # bidirectional workflow (coarse=respond)
    PUSH_CASE = "push_case"
    PUSH_STATUS = "push_status"


# fine verb -> coarse word
_COARSE: dict[Capability, str] = {
    Capability.PULL_ALERTS: ENRICH,
    Capability.ENRICH_IOC: ENRICH,
    Capability.GET_ALERT_DETAIL: ENRICH,
    Capability.HUNT_QUERY: HUNT,
    Capability.ISOLATE_HOST: RESPOND,
    Capability.RELEASE_HOST: RESPOND,
    Capability.SCAN_ENDPOINT: RESPOND,
    Capability.KILL_PROCESS: RESPOND,
    Capability.DISABLE_USER: RESPOND,
    Capability.BLOCK_HASH: RESPOND,
    Capability.BLOCK_IOC: RESPOND,
    Capability.PUSH_CASE: RESPOND,
    Capability.PUSH_STATUS: RESPOND,
}

# Stable display order for the coarse projection.
_COARSE_ORDER = (ENRICH, HUNT, RESPOND)


def coarse_for(caps: tuple[Capability, ...]) -> tuple[str, ...]:
    """Project fine verbs onto the legacy `(enrich, respond, hunt)` set, de-duplicated and in a
    stable order, so `registry.capabilities_for` and the UI badges are unchanged."""
    present = {_COARSE[c] for c in caps if c in _COARSE}
    return tuple(w for w in _COARSE_ORDER if w in present)


def is_response(cap: Capability) -> bool:
    """True for a containment/effect verb (always analyst-gated at the human sign-off gate)."""
    return _COARSE.get(cap) == RESPOND
