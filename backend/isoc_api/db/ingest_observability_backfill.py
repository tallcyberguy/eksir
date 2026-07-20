"""Per-source observability (PR #96) — idempotent column adds for ingest_sources.

PR #96 added `last_poll_ms` / `last_poll_count` / `total_ingested` to the
`IngestSourceConfig` model but shipped no backfill. On a fresh DB `create_all`
includes them, but on any deployment where `ingest_sources` predates #96 the
columns are missing, so every read of the Sources page 500'd with
`UndefinedColumnError: column ingest_sources.last_poll_ms does not exist`.

Runs every boot; `IF NOT EXISTS` makes it a no-op after first apply.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.ingest.backfill")


async def add_ingest_observability_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS last_poll_ms INTEGER")
        )
        await conn.execute(
            sql_text("ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS last_poll_count INTEGER")
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS "
                "total_ingested INTEGER NOT NULL DEFAULT 0"
            )
        )
        # ADR-0006 P1a schema-drift sentinel.
        await conn.execute(
            sql_text(
                "ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS field_fingerprint VARCHAR(64)"
            )
        )
    logger.info("ingest.observability_columns_ensured")
