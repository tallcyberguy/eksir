"""Match extracted alert IOCs against the local threat-intel DB.

Called from the enrichment pipeline. Two match modes:
  1. Exact: alert value == DB value (works for IP, hash, URL, domain)
  2. Parent-domain: alert domain is a sub of a DB domain
     (e.g. alert `admin.compromised.example.com` matches feed `compromised.example.com`).
     The inverse (alert has parent of a feed entry) is intentionally NOT done —
     would false-positive too often (e.g. `google.com` parent of one bad sub).

One DB round-trip regardless of how many IOCs the alert has.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession


async def match_iocs(
    session: AsyncSession,
    iocs: list[tuple[str, str]],
) -> list[dict]:
    """Return one dict per IOC that matched the local threat DB.

    Input:  [(extractor_ioc_type, value), ...]  — extractor uses "ipv4"/"ipv6"/
            "domain"/"url"/... (see db.enums.IOCType).
    Output: [{value, alert_value, ioc_type, match_kind, first_seen_at,
              last_seen_at, sources}, ...]
              match_kind ∈ {"exact", "parent_domain"}.
              `value` is the DB row; `alert_value` is the IOC from the alert.
              For exact matches, the two are equal.
    """
    if not iocs:
        return []

    # Normalise input: trim, drop blanks, lowercase domains for case-insensitive
    # matching (feeds store lowercase via the classifier).
    norm_values: list[str] = []
    alert_domains: list[str] = []
    for _t, v in iocs:
        if not (isinstance(v, str) and v.strip()):
            continue
        val = v.strip()
        norm_values.append(val)
        # Anything that could be a domain (no scheme, has a dot, no slash) is a
        # candidate for parent-domain match. Cheaper than re-validating each one.
        if "/" not in val and " " not in val and "." in val and ":" not in val:
            alert_domains.append(val.lower())

    if not norm_values:
        return []

    # Single SQL — UNION ALL of (exact match) + (parent-of-alert match).
    # The parent-match leg only fires on domain rows.
    stmt = sql_text("""
        SELECT value, ioc_type, first_seen_at, last_seen_at, sources,
               alert_value, match_kind
        FROM (
            SELECT t.value, t.ioc_type, t.first_seen_at, t.last_seen_at, t.sources,
                   t.value AS alert_value, 'exact' AS match_kind
            FROM threat_iocs t
            WHERE t.value = ANY(:values)

            UNION ALL

            SELECT t.value, t.ioc_type, t.first_seen_at, t.last_seen_at, t.sources,
                   d AS alert_value, 'parent_domain' AS match_kind
            FROM threat_iocs t,
                 unnest(cast(:domains AS text[])) AS d
            WHERE t.ioc_type = 'domain'
              AND d <> t.value
              AND d LIKE '%.' || t.value
        ) hits
    """)

    rows = (
        await session.execute(
            stmt,
            {
                "values": norm_values,
                "domains": alert_domains,
            },
        )
    ).all()

    return [
        {
            "value": r.value,
            "alert_value": r.alert_value,
            "ioc_type": r.ioc_type,
            "match_kind": r.match_kind,
            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
            "sources": r.sources or [],
        }
        for r in rows
    ]
