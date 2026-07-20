"""Idempotent column add for the analyst verdict rationale.

Runs every boot. `IF NOT EXISTS` keeps it a no-op after first apply. Adds
`incidents.verdict_reason` — the analyst's short "why" captured at verdict time,
indexed to Qdrant so future identical alerts retrieve the analyst's rationale.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.verdict_reason.backfill")


async def add_verdict_reason_column(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS verdict_reason TEXT")
        )
    logger.info("verdict_reason.column_ensured")
