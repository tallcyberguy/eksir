"""Schema-drift sentinel (ADR-0006 decision #9).

`field_map`'s dotted-path lookups resolve to `null` silently when a vendor renames or drops a
field (e.g. `source.ip` -> `src.ip`). Across dozens of independently-versioned vendor APIs that
rot is continuous and invisible until an analyst notices missing IOCs. Borrowing AiSOC's
`fingerprint.py` idea: hash the set of top-level field names a source emits, persist it next to
the cursor, and raise a signal when it changes so a human can re-check the mapping before it
rots.

Pure — no I/O. Wiring the fingerprint into the `pull_ingest` cron is ADR-0006 P1.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


def _top_level_keys(records: list[Any]) -> set[str]:
    keys: set[str] = set()
    for r in records:
        if isinstance(r, dict):
            keys.update(str(k) for k in r.keys())
    return keys


def field_fingerprint(records: list[Any]) -> str:
    """Stable SHA-256 over the sorted union of top-level field names across a batch.

    Order-independent and value-independent: only the *shape* (which keys appear) matters, so a
    normal batch-to-batch value change does not trip it, but a renamed/dropped/added field does.
    """
    joined = "\n".join(sorted(_top_level_keys(records)))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class DriftReport:
    changed: bool
    added: tuple[str, ...]
    removed: tuple[str, ...]
    fingerprint: str


def detect_drift(previous_fingerprint: str | None, records: list[Any]) -> DriftReport:
    """Compare this batch's shape against the previously stored fingerprint.

    First run (`previous_fingerprint is None`) is never flagged as drift — there is no baseline —
    but the returned fingerprint should be persisted so the next batch can be compared. When only
    the hash is stored (not the key set), `added`/`removed` are unknown and left empty; `changed`
    still fires. Pass a prior key set via `detect_drift_keyset` if you want the diff.
    """
    fp = field_fingerprint(records)
    if previous_fingerprint is None:
        return DriftReport(changed=False, added=(), removed=(), fingerprint=fp)
    return DriftReport(changed=(fp != previous_fingerprint), added=(), removed=(), fingerprint=fp)


def detect_drift_keyset(previous_keys: set[str] | None, records: list[Any]) -> DriftReport:
    """Richer variant when the prior key set (not just its hash) was persisted: reports the exact
    added/removed field names."""
    now = _top_level_keys(records)
    fp = field_fingerprint(records)
    if previous_keys is None:
        return DriftReport(changed=False, added=(), removed=(), fingerprint=fp)
    added = tuple(sorted(now - previous_keys))
    removed = tuple(sorted(previous_keys - now))
    return DriftReport(changed=bool(added or removed), added=added, removed=removed, fingerprint=fp)
