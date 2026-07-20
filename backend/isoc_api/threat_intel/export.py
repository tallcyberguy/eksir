"""Feature 4 — export analyst-confirmed IOCs as STIX 2.1 or CSV.

ISOC becomes an intel *producer*: the export source is per-incident `IOCRecord`
rows whose incident verdict == TP and which are not excluded (the tenant-scoped
query lives in routes/threat_intel.py). Everything here is pure and unit-tested
— dedupe, the CSV writer, and the STIX pattern/bundle builders — so it needs no
DB or stack.

`stix2` is imported lazily inside `to_stix_bundle` so a missing dependency can
never break module import or the CSV path (mirrors the EASM lazy-import pattern).
"""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

# Fixed namespace → STIX Indicator ids are a deterministic uuid5 of the pattern,
# so re-exporting the same indicator yields the same id and downstream consumers
# (TAXII servers, MISP) dedupe cleanly instead of accumulating copies.
_STIX_NS = uuid.UUID("0f7e2c1a-5b9d-4e3f-8a6c-1d2e3f4a5b6c")


@dataclass
class ExportRow:
    """One unique indicator, with the confirming incidents as provenance."""

    ioc_type: str
    value: str
    first_seen: datetime | None = None
    incidents: list[str] = field(default_factory=list)  # case numbers, e.g. INC-000123
    tenant: str | None = None


def _escape_stix_value(value: str) -> str:
    """Escape a value for a STIX single-quoted string literal (backslash first)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc_type: str, value: str) -> str | None:
    """Map an IOCType value to a STIX 2.1 pattern, or None for an unknown type."""
    v = _escape_stix_value(value)
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']",
    }.get(ioc_type)


def dedupe(rows: Iterable[tuple]) -> list[ExportRow]:
    """Collapse raw `(ioc_type, value, first_seen, case_number, tenant)` tuples by
    (ioc_type, value): earliest first_seen, sorted-unique confirming incidents,
    first non-null tenant. Deterministically ordered."""
    by_key: dict[tuple[str, str], ExportRow] = {}
    for ioc_type, value, first_seen, case_number, tenant in rows:
        key = (ioc_type, value)
        row = by_key.get(key)
        if row is None:
            row = ExportRow(ioc_type=ioc_type, value=value, first_seen=first_seen, tenant=tenant)
            by_key[key] = row
        if first_seen and (row.first_seen is None or first_seen < row.first_seen):
            row.first_seen = first_seen
        if row.tenant is None and tenant:
            row.tenant = tenant
        if case_number and case_number not in row.incidents:
            row.incidents.append(case_number)
    out = list(by_key.values())
    for row in out:
        row.incidents.sort()
    out.sort(key=lambda r: (r.ioc_type, r.value))
    return out


def to_csv(rows: list[ExportRow]) -> str:
    """CSV with a header row. stdlib csv handles quoting/escaping."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ioc_type", "value", "first_seen", "incident_count", "incidents", "tenant"])
    for r in rows:
        writer.writerow(
            [
                r.ioc_type,
                r.value,
                r.first_seen.isoformat() if r.first_seen else "",
                len(r.incidents),
                " ".join(r.incidents),
                r.tenant or "",
            ]
        )
    return buf.getvalue()


def to_stix_bundle(rows: list[ExportRow], now: datetime) -> str:
    """Serialize a STIX 2.1 bundle of Indicator SDOs (one per unique indicator).

    Rows whose type has no STIX mapping are skipped. Timestamps are taken from
    the indicator's first_seen (falling back to `now`) so the output is stable.
    """
    import stix2

    indicators = []
    for r in rows:
        pattern = stix_pattern(r.ioc_type, r.value)
        if not pattern:
            continue
        ts = r.first_seen or now
        indicators.append(
            stix2.Indicator(
                id=f"indicator--{uuid.uuid5(_STIX_NS, pattern)}",
                created=ts,
                modified=ts,
                valid_from=ts,
                pattern=pattern,
                pattern_type="stix",
                indicator_types=["malicious-activity"],
                name=f"{r.ioc_type}: {r.value}",
                description=(
                    "Analyst-confirmed (TP) in " + ", ".join(r.incidents)
                    if r.incidents
                    else "Analyst-confirmed (TP)"
                ),
                allow_custom=False,
            )
        )

    if not indicators:
        # stix2.Bundle omits an empty `objects` key, which its own parser then
        # rejects — emit an explicit empty-objects bundle so an empty export is
        # still well-formed JSON for any consumer.
        import json

        return json.dumps(
            {"type": "bundle", "id": f"bundle--{uuid.uuid5(_STIX_NS, 'empty')}", "objects": []},
            indent=4,
        )
    return stix2.Bundle(objects=indicators, allow_custom=False).serialize(pretty=True)
