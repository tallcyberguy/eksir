"""Pull-ingestion adapter contract.

Each adapter wraps one console (Vision One, SentinelOne, ...) behind a uniform
`fetch()` so the `pull_ingest` cron can iterate a registry instead of hardcoding
per-source loops. Adapters are intentionally thin: they call the existing
`adapters/*` API clients and return **raw** alerts (text + the original dict) for
the deterministic parser/normalizer to handle. They do NOT normalize, score, or
create incidents — that stays centralized so pulled alerts ride the exact same
path a webhook alert does and park at the human gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, TypedDict, runtime_checkable


class PulledAlert(TypedDict, total=False):
    """One alert pulled from a console.

    `external_id` is the stable per-source id used for idempotent dedup and is
    required. `source_hint` routes `parsers.detect_source`. `original` carries
    the raw console object so a JSON parser can consume it; `raw_text` is a text
    fallback. `severity` (raw word) feeds the per-source `min_severity` floor.
    """

    external_id: str
    source_hint: str
    raw_text: str
    original: Any
    severity: str | None
    occurred_at: str | None


@dataclass(slots=True)
class FetchResult:
    """An adapter fetch's output: the new alerts plus the cursor to persist."""

    alerts: list[PulledAlert] = field(default_factory=list)
    cursor: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class IngestAdapter(Protocol):
    """Contract every pull-ingestion adapter implements."""

    #: connectors-catalog key (also the `ingest_sources.provider` value).
    provider: str

    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        """Pull new alerts since `cursor`.

        `cursor` is the per-source state previously returned by this adapter
        (empty dict on first run — adapters MUST treat empty as "from now" and
        NOT backfill history). Implementations honor `max_items` to bound the
        first-run blast radius.
        """
        ...
