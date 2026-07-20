"""Scheduling, dedup, and bookkeeping for the `pull_ingest` cron.

Pure helpers (due-check, backoff, dedup key, severity floor) are unit-tested and
have no I/O. `record_success` / `record_failure` do the best-effort watermark
update on the `ingest_sources` row. This is the ISOC analogue of Vigil's
`federation/store.py`, but the cron itself lives in `worker.py` (ARQ) rather than
a bespoke daemon.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..adapters.connectors import drift as _drift

# Canonical severity bands -> rank. Accepts the words adapters emit plus the
# NormalizedAlert "med" spelling, so a min_severity floor is comparable.
_SEVERITY_RANK = {
    "info": -1,
    "informational": -1,
    "low": 0,
    "medium": 1,
    "med": 1,
    "high": 2,
    "critical": 3,
    "crit": 3,
}

_MAX_BACKOFF_MULT = 8
_MIN_INTERVAL_SECONDS = 5


def dedup_key(provider: str, external_id: str) -> str:
    """Redis key claiming one (provider, external_id) as already ingested."""
    return f"ingest:seen:{provider}:{external_id}"


def pollnow_key(source_id: Any) -> str:
    """Redis flag the control plane sets to force one immediate poll of a source."""
    return f"ingest:pollnow:{source_id}"


def severity_passes(alert_severity: str | None, floor: str | None) -> bool:
    """True if `alert_severity` meets the `min_severity` floor (None floor = all)."""
    if not floor:
        return True
    rank_alert = _SEVERITY_RANK.get((alert_severity or "").lower(), -1)
    rank_floor = _SEVERITY_RANK.get(floor.lower(), 0)
    return rank_alert >= rank_floor


def drift_check(previous_fingerprint: str | None, alerts: list[dict]) -> _drift.DriftReport | None:
    """Schema-drift sentinel for a batch of pulled alerts (ADR-0006 P1a).

    Fingerprints the RAW vendor payloads (each `PulledAlert['original']`'s top-level field names),
    not the uniform PulledAlert wrapper, and compares against the source's stored fingerprint.
    Returns a `DriftReport` (`.changed`, `.fingerprint`), or `None` when the batch has no dict
    payloads to fingerprint — a no-op poll must not raise a false alarm or clobber the fingerprint.
    Pure: the cron logs on `.changed` and persists `.fingerprint`.
    """
    originals = [
        a.get("original")
        for a in alerts
        if isinstance(a, dict) and isinstance(a.get("original"), dict)
    ]
    if not originals:
        return None
    return _drift.detect_drift(previous_fingerprint, originals)


def effective_interval(interval_seconds: int, consecutive_errors: int) -> int:
    """Poll interval with capped exponential backoff after failures."""
    mult = min(2**consecutive_errors, _MAX_BACKOFF_MULT) if consecutive_errors else 1
    return max(int(interval_seconds) * mult, _MIN_INTERVAL_SECONDS)


def is_due(
    *,
    interval_seconds: int,
    consecutive_errors: int,
    last_poll_at: datetime | None,
    now: datetime,
) -> bool:
    """True if a source is due to poll (never polled → due; else interval elapsed)."""
    if last_poll_at is None:
        return True
    lp = last_poll_at if last_poll_at.tzinfo else last_poll_at.replace(tzinfo=timezone.utc)
    elapsed = (now - lp).total_seconds()
    return elapsed >= effective_interval(interval_seconds, consecutive_errors)


_STALE_INTERVAL_MULT = 3
_STALE_MIN_SECONDS = 600  # never flag a source stale before ~10 min


def is_stale(
    *,
    enabled: bool,
    interval_seconds: int,
    last_success_at: datetime | None,
    now: datetime,
) -> bool:
    """True for a source that used to succeed but hasn't in > max(3×interval, 10m)
    — i.e. the cron silently stopped polling it. A source that has never
    succeeded is 'pending'/'error', not stale."""
    if not enabled or last_success_at is None:
        return False
    ls = last_success_at if last_success_at.tzinfo else last_success_at.replace(tzinfo=timezone.utc)
    threshold = max(int(interval_seconds) * _STALE_INTERVAL_MULT, _STALE_MIN_SECONDS)
    return (now - ls).total_seconds() > threshold


def source_health(
    *,
    enabled: bool,
    interval_seconds: int,
    consecutive_errors: int,
    last_success_at: datetime | None,
    now: datetime,
) -> str:
    """One-word health: disabled | error | stale | ok | pending."""
    if not enabled:
        return "disabled"
    if consecutive_errors and consecutive_errors > 0:
        return "error"
    if is_stale(
        enabled=enabled,
        interval_seconds=interval_seconds,
        last_success_at=last_success_at,
        now=now,
    ):
        return "stale"
    return "ok" if last_success_at is not None else "pending"


async def record_success(
    source_id: Any,
    *,
    cursor: dict[str, Any],
    poll_ms: int | None = None,
    count: int = 0,
    field_fingerprint: str | None = None,
) -> None:
    """Persist a successful poll: advance cursor, clear errors, record metrics.
    Never raises. `field_fingerprint` (when not None) updates the schema-drift baseline; a
    no-op poll passes None so the stored fingerprint is preserved, not wiped."""
    from ..db.models import IngestSourceConfig
    from ..db.session import AsyncSessionLocal

    now = datetime.now(timezone.utc)
    try:
        async with AsyncSessionLocal() as session:
            row = await session.get(IngestSourceConfig, source_id)
            if row is None:
                return
            row.last_poll_at = now
            row.last_success_at = now
            row.last_error = None
            row.consecutive_errors = 0
            row.cursor = cursor or {}
            row.last_poll_ms = poll_ms
            row.last_poll_count = count
            row.total_ingested = (row.total_ingested or 0) + count
            if field_fingerprint is not None:
                row.field_fingerprint = field_fingerprint
            await session.commit()
    except Exception:  # noqa: BLE001 — bookkeeping must not break the cron
        pass


async def record_failure(source_id: Any, error: str) -> None:
    """Persist a failed poll: bump consecutive_errors (drives backoff). Never
    auto-disables the source. Never raises."""
    from ..db.models import IngestSourceConfig
    from ..db.session import AsyncSessionLocal

    now = datetime.now(timezone.utc)
    try:
        async with AsyncSessionLocal() as session:
            row = await session.get(IngestSourceConfig, source_id)
            if row is None:
                return
            row.last_poll_at = now
            row.last_error = (error or "")[:2000]
            row.consecutive_errors = (row.consecutive_errors or 0) + 1
            await session.commit()
    except Exception:  # noqa: BLE001
        pass
