"""Threat-feed sync service.

For each enabled ThreatFeed: fetch the feed body, parse rows according to
the feed's `parser_config` (or line-based by default), classify each IOC,
and upsert into threat_iocs. Idempotent — re-running with the same feed
content is a no-op except for `last_seen_at` refreshes.

Per-feed failures are caught and recorded on the feed row; one bad feed
doesn't kill the run.

Two parsing modes:
  • Default (parser_config is NULL): one IOC per line, classifier picks
    up the rest. Works for Feodo Tracker, ET, Tor exit list, OpenPhish,
    URLhaus plain-text endpoint.
  • CSV (parser_config = {"format": "csv", ...}): pulls the value from
    a named column, optionally maps a type column to our IocKind, and
    optionally skips leading comment lines. Works for ThreatFox + SSLBL.

abuse.ch auth: if a feed URL contains `abuse.ch` AND settings.abusech_auth_key
is set, the request gets an `Auth-Key` header. Harmless on the older
unauthenticated endpoints (Feodo Tracker), required for the newer ones
(URLhaus, ThreatFox, MalwareBazaar, SSLBL).
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import ThreatFeed
from ..logging_config import get_logger
from ..settings import settings
from .classifier import IocKind, classify
from .stix_parse import indicators_to_iocs

logger = get_logger("isoc.threat_intel.sync")

# Most public feeds are tens of KB; abuse.ch CSV exports up to a few MB.
_FETCH_TIMEOUT = 60.0
_BATCH = 1000
# TAXII paging safety caps (a misbehaving/huge collection can't run forever).
_TAXII_MAX_PAGES = 50
_TAXII_MAX_OBJECTS = 50_000


async def sync_all(session: AsyncSession) -> dict:
    """Sync every enabled feed in series. Returns a summary dict."""
    feeds = (await session.scalars(select(ThreatFeed).where(ThreatFeed.enabled.is_(True)))).all()

    summary = {"feeds": len(feeds), "ok": 0, "errors": 0, "new_iocs": 0, "total_lines": 0}

    async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
        for feed in feeds:
            try:
                lines, new_count = await _sync_one(session, client, feed)
                summary["ok"] += 1
                summary["total_lines"] += lines
                summary["new_iocs"] += new_count
            except Exception as e:
                logger.exception(
                    "threat_intel.sync.feed_failed", feed_id=str(feed.id), feed_name=feed.name
                )
                feed.last_sync_at = datetime.now(timezone.utc)
                feed.last_sync_status = "error"
                feed.last_sync_error = str(e)[:1000]
                summary["errors"] += 1
            await session.commit()

    logger.info("threat_intel.sync.done", **summary)
    return summary


# Plain SQL upsert. JSONB array-append-if-missing is awkward in SQLAlchemy
# core; one parametrised statement keeps it readable. Each row updates only
# itself, so there's no bind-param collision between batched rows.
_UPSERT_SQL = sql_text("""
    INSERT INTO threat_iocs (id, value, ioc_type, first_seen_at, last_seen_at, sources)
    VALUES (gen_random_uuid(), :value, :ioc_type, :now, :now, cast(:source_arr AS jsonb))
    ON CONFLICT (value, ioc_type) DO UPDATE
        SET last_seen_at = EXCLUDED.last_seen_at,
            sources = CASE
                WHEN threat_iocs.sources @> cast(:source_arr AS jsonb)
                    THEN threat_iocs.sources
                ELSE threat_iocs.sources || cast(:source_arr AS jsonb)
            END
    RETURNING (xmax = 0) AS inserted
""")


def _request_headers(feed_url: str) -> dict[str, str]:
    """Default UA + abuse.ch Auth-Key header when configured.

    The Auth-Key header is harmless on unauthenticated abuse.ch endpoints
    (Feodo Tracker ignores it), so we send it for ANY abuse.ch URL when
    the key is set. Keeps the per-feed config simple.
    """
    h = {"User-Agent": "EKSIR-threat-intel/1.0"}
    key = getattr(settings, "abusech_auth_key", None)
    if key is not None and hasattr(key, "get_secret_value"):
        key = key.get_secret_value()
    if key and "abuse.ch" in feed_url:
        h["Auth-Key"] = key
    return h


def _parse_lines(text: str, kind_hint: str | None) -> list[tuple[IocKind, str]]:
    """Default parser: one IOC per line."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[IocKind, str]] = []
    for raw in text.splitlines():
        c = classify(raw, kind_hint)
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _parse_csv(
    text: str,
    config: dict,
    fallback_hint: str | None,
) -> list[tuple[IocKind, str]]:
    """CSV parser. Pulls `value_column` (required), optionally uses
    `type_column` + `type_mapping` to pick the kind per row, and strips
    leading comment lines if `skip_comment_lines` is true.

    Schema:
        {
            "format": "csv",
            "value_column": "ioc_value",
            "type_column": "ioc_type",          # optional
            "type_mapping": {                   # optional; default = identity
                "url": "url", "domain": "domain",
                "ip:port": "ip",                # special: ":port" suffix is stripped
                "sha256_hash": "hash",
                "md5_hash": "hash",
                "sha1_hash": "hash",
            },
            "skip_comment_lines": true,         # default true — strip `#…` rows
        }
    """
    value_col = config["value_column"]
    type_col = config.get("type_column")
    type_map = config.get("type_mapping", {})
    skip_comments = config.get("skip_comment_lines", True)

    # Some abuse.ch CSVs (ThreatFox, SSLBL) wrap the HEADER line itself in
    # a `# ` comment prefix, then the data rows are uncommented. If we
    # naively strip all `#` lines we lose the header — DictReader then
    # treats the first data row as field names and produces nothing.
    #
    # Strategy: walk the lines. Once we hit a non-comment line, the
    # previous `#`-prefixed line (if any) is the header — restore it by
    # stripping just the leading `# ` / `#`. Everything before that is
    # banner/license boilerplate; drop it.
    if skip_comments:
        raw_lines = text.splitlines()
        last_comment: str | None = None
        body_start = -1
        for i, ln in enumerate(raw_lines):
            stripped = ln.lstrip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                last_comment = stripped
            else:
                body_start = i
                break
        if body_start < 0:
            return []
        lines = raw_lines[body_start:]
        # If the last comment line looked CSV-shaped (has commas or quoted
        # tokens) and the body's first line ALSO has commas, prepend the
        # de-commented last_comment as the header.
        if last_comment and "," in last_comment and "," in (lines[0] or ""):
            header = last_comment.lstrip("#").strip()
            lines = [header, *lines]
    else:
        lines = text.splitlines()

    if not lines:
        return []

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    seen: set[tuple[str, str]] = set()
    out: list[tuple[IocKind, str]] = []

    for row in reader:
        value = (row.get(value_col) or "").strip().strip("\"'")
        if not value:
            continue

        # Determine kind. If we have a type column, map it; otherwise fall
        # back to the feed's declared kind_hint (or "auto").
        row_hint: str | None = fallback_hint
        if type_col:
            raw_type = (row.get(type_col) or "").strip().strip("\"'")
            mapped = type_map.get(raw_type, raw_type)
            if mapped in ("ip", "domain", "url", "hash"):
                row_hint = mapped
            # ThreatFox "ip:port" → "ip" but the value still has ":8080" tail
            if raw_type == "ip:port" and ":" in value:
                value = value.rsplit(":", 1)[0]

        c = classify(value, row_hint)
        if c and c not in seen:
            seen.add(c)
            out.append(c)

    return out


def _taxii_headers_auth(config: dict) -> tuple[dict[str, str], tuple[str, str] | None]:
    """Build the Accept header + optional httpx basic-auth tuple from the feed's
    `parser_config.auth`. Supports `{"type":"basic","username","password"}` and
    `{"type":"token"|"bearer","token":...}`; anything else = unauthenticated."""
    headers = {"Accept": "application/taxii+json;version=2.1"}
    auth = config.get("auth") or {}
    atype = (auth.get("type") or "none").lower()
    if atype == "basic":
        return headers, (auth.get("username", ""), auth.get("password", ""))
    if atype in ("token", "bearer") and auth.get("token"):
        headers["Authorization"] = f"Bearer {auth['token']}"
    return headers, None


async def _fetch_taxii(
    client: httpx.AsyncClient, feed: ThreatFeed, config: dict
) -> list[tuple[IocKind, str]]:
    """Page a TAXII 2.1 collection's objects endpoint and flatten its STIX
    Indicators to `(kind, value)` tuples. TAXII 2.1 is plain HTTP+JSON, so this
    uses the shared async httpx client directly (no blocking client / new dep).
    `collection_url` may live in parser_config or fall back to `feed.url`."""
    base = (config.get("collection_url") or feed.url).rstrip("/")
    url = f"{base}/objects/"
    headers, basic = _taxii_headers_auth(config)
    base_params: dict[str, str] = {}
    if config.get("added_after"):  # optional incremental watermark
        base_params["added_after"] = str(config["added_after"])

    objects: list[dict] = []
    next_id: str | None = None
    for _ in range(_TAXII_MAX_PAGES):
        params = dict(base_params)
        if next_id:
            params["next"] = next_id
        resp = await client.get(url, headers=headers, params=params, auth=basic)
        resp.raise_for_status()
        body = resp.json()
        objects.extend(body.get("objects") or [])
        if len(objects) >= _TAXII_MAX_OBJECTS:
            logger.warning("threat_intel.taxii.capped", feed=feed.name, objects=len(objects))
            break
        if body.get("more") and body.get("next"):
            next_id = str(body["next"])
        else:
            break
    return indicators_to_iocs(objects)


async def _sync_one(
    session: AsyncSession,
    client: httpx.AsyncClient,
    feed: ThreatFeed,
) -> tuple[int, int]:
    """Sync one feed. Returns (total_iocs_parsed, net_new_rows_inserted).

    Uses `xmax = 0` to distinguish a true INSERT from an UPDATE in the upsert —
    a stable Postgres-only trick that avoids a second round-trip per row.
    """
    started = datetime.now(timezone.utc)

    # Dispatch on parser_config.format. TAXII has its own protocol (no raw GET);
    # csv/lines fetch the URL as text.
    config = feed.parser_config or {}
    fmt = config.get("format")
    if fmt == "taxii":
        parsed = await _fetch_taxii(client, feed, config)
    else:
        resp = await client.get(feed.url, headers=_request_headers(feed.url))
        resp.raise_for_status()
        if fmt == "csv":
            parsed = _parse_csv(resp.text, config, feed.kind_hint)
        else:
            parsed = _parse_lines(resp.text, feed.kind_hint)

    new_count = 0
    now = datetime.now(timezone.utc)
    source_arr = json.dumps([str(feed.id)])

    # Run rows in chunks to keep one transaction tight without holding the
    # session forever on a 10k feed.
    for i in range(0, len(parsed), _BATCH):
        chunk = parsed[i : i + _BATCH]
        for ioc_type, value in chunk:
            row = (
                await session.execute(
                    _UPSERT_SQL,
                    {
                        "value": value,
                        "ioc_type": ioc_type,
                        "now": now,
                        "source_arr": source_arr,
                    },
                )
            ).one()
            if row.inserted:
                new_count += 1

    feed.last_sync_at = started
    feed.last_sync_status = "ok"
    feed.last_sync_error = None
    feed.last_sync_count = len(parsed)
    feed.last_sync_new_count = new_count
    logger.info(
        "threat_intel.sync.feed_ok",
        feed_name=feed.name,
        kind_hint=feed.kind_hint,
        parser=config.get("format", "lines"),
        parsed=len(parsed),
        new=new_count,
    )
    return len(parsed), new_count
