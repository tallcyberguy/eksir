"""Idempotent seed for the threat_feeds table — public OSINT feeds only.

Runs on every boot. Two parallel responsibilities:

1. **Cleanup**: delete any legacy SOCRadar feed rows on every boot. These
   were the historical seeds and need to be retired. Idempotent — once
   the rows are gone the DELETE is a no-op.

2. **Seed**: if the table is empty after cleanup, insert the public feeds
   below. Once an admin has touched feeds via the UI (adding / disabling),
   we never reseed.

Feed selection (Nov 2026):

  No-auth, plain-text:
    • Emerging Threats — compromised IPs
    • Tor Project — exit node list

  abuse.ch (requires free ABUSECH_AUTH_KEY from https://auth.abuse.ch):
    • URLhaus — malware URLs (plain text)
    • MalwareBazaar — recent malware SHA256s (plain text)
    • ThreatFox — mixed IOCs (CSV, parsed via parser_config)
    • SSLBL — malicious SSL cert SHA1s (CSV, parsed via parser_config)

If ABUSECH_AUTH_KEY isn't set, the 4 abuse.ch feeds will 401 on sync and
show a clear error in the admin UI. Setting the key (no code change) then
makes them work.
"""

from __future__ import annotations

import json

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.threat_intel.backfill")

# (name, url, kind_hint, parser_config). parser_config is a Python dict for
# CSV feeds, None for line-based feeds.
_SEED_FEEDS: list[tuple[str, str, str, dict | None]] = [
    # ── No-auth, plain-text IP lists ─────────────────────────────────────
    (
        "Emerging Threats — compromised IPs",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "ip",
        None,
    ),
    (
        "Tor Project — exit node list",
        "https://check.torproject.org/torbulkexitlist",
        "ip",
        None,
    ),
    # ── abuse.ch URLhaus: plain-text URL list (Auth-Key required) ────────
    (
        "URLhaus — plain-text URLs",
        "https://urlhaus.abuse.ch/downloads/text/",
        "url",
        None,
    ),
    # ── abuse.ch MalwareBazaar: plain SHA256 list (Auth-Key required) ────
    (
        "MalwareBazaar — recent SHA256",
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "hash",
        None,
    ),
    # ── abuse.ch ThreatFox: CSV of mixed IOCs (Auth-Key required) ────────
    # ThreatFox CSV columns: first_seen_utc, ioc_id, ioc_value, ioc_type,
    # threat_type, fk_malware, malware_alias, malware_printable, last_seen_utc,
    # confidence_level, reference, tags, anonymous, reporter.
    # We extract ioc_value, type-mapped from ioc_type. "ip:port" → "ip"
    # (port-strip happens in _parse_csv).
    (
        "ThreatFox — recent IOCs (CSV)",
        "https://threatfox.abuse.ch/export/csv/recent/",
        "auto",  # row-level type mapping wins; fallback is auto-classify
        {
            "format": "csv",
            "value_column": "ioc_value",
            "type_column": "ioc_type",
            "type_mapping": {
                "url": "url",
                "domain": "domain",
                "ip:port": "ip",
                "ipv4": "ip",
                "ipv6": "ip",
                "md5_hash": "hash",
                "sha1_hash": "hash",
                "sha256_hash": "hash",
            },
            "skip_comment_lines": True,
        },
    ),
    # ── abuse.ch SSLBL: CSV of SSL-cert SHA1s (Auth-Key required) ────────
    # SSLBL CSV columns: Listingdate, SHA1, Listingreason. Header is wrapped
    # in 9 lines of `# ...` comments which skip_comment_lines strips.
    (
        "SSLBL — SSL cert SHA1 blacklist",
        "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        "hash",
        {
            "format": "csv",
            "value_column": "SHA1",
            "skip_comment_lines": True,
        },
    ),
]


async def seed_threat_feeds(engine: AsyncEngine) -> None:
    """Per-boot lifecycle:
    1. Delete any legacy SOCRadar rows (idempotent — no-op once clean)
    2. If table empty, seed the public feeds above
    """
    async with engine.begin() as conn:
        # ── 1. Cleanup: retire SOCRadar feeds ──────────────────────────
        # `name LIKE 'SOCRadar%'` covers all 8 original seeds plus any
        # variants an admin might have renamed. Doesn't touch threat_iocs
        # rows that those feeds previously contributed — those are still
        # valid IOCs, just orphaned from a defunct source.
        result = await conn.execute(
            sql_text("DELETE FROM threat_feeds WHERE name LIKE 'SOCRadar%'")
        )
        if result.rowcount:
            logger.info("threat_intel.feeds.socradar_cleanup", deleted=result.rowcount)

        # ── 2. Seed if empty ───────────────────────────────────────────
        count = (await conn.execute(sql_text("SELECT COUNT(*) FROM threat_feeds"))).scalar() or 0
        if count > 0:
            return

        for name, url, kind, parser_config in _SEED_FEEDS:
            await conn.execute(
                sql_text("""
                INSERT INTO threat_feeds
                    (id, name, url, kind_hint, enabled, parser_config,
                     created_at, updated_at)
                VALUES (gen_random_uuid(), :name, :url, :kind, true,
                        cast(:parser_config AS jsonb),
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT (url) DO NOTHING
            """),
                {
                    "name": name,
                    "url": url,
                    "kind": kind,
                    "parser_config": json.dumps(parser_config) if parser_config else None,
                },
            )

        logger.info("threat_intel.feeds_seeded", count=len(_SEED_FEEDS))
