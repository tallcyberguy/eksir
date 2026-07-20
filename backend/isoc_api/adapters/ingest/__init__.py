"""Pull-ingestion adapter registry.

Adding a new source is a new module here plus one `register()` call — the
`pull_ingest` cron and the connectors control plane both resolve adapters
through `get_adapter(provider)`. Adapters register lazily (imported for their
side effect) so importing this package doesn't pull in every console client.
"""

from __future__ import annotations

from .base import FetchResult, IngestAdapter, PulledAlert

__all__ = ["FetchResult", "IngestAdapter", "PulledAlert", "get_adapter", "register", "providers"]

_ADAPTERS: dict[str, IngestAdapter] = {}


def register(adapter: IngestAdapter) -> None:
    """Register an adapter instance under its `.provider` key."""
    _ADAPTERS[adapter.provider] = adapter


def providers() -> tuple[str, ...]:
    _ensure_loaded()
    return tuple(_ADAPTERS.keys())


def get_adapter(provider: str) -> IngestAdapter | None:
    _ensure_loaded()
    return _ADAPTERS.get(provider)


_LOADED = False


def _ensure_loaded() -> None:
    """Import builtin adapter modules so they self-register."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from . import (  # noqa: F401  (register on import)
        crowdstrike,
        microsoft_defender,
        sentinelone,
        vision_one,
    )
