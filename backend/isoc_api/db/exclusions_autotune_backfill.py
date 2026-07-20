"""Idempotent schema adds for exclusion auto-tuning (feature F8).

Runs every boot. `IF NOT EXISTS` keeps it a no-op after first apply. The new
`exclusion_suggestions` table itself is created by `Base.metadata.create_all`
(checkfirst); this backfill only handles the column ADD that create_all can't
do on an existing `exclusions` table.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.exclusions_autotune.backfill")


async def add_exclusion_customer_scope(engine: AsyncEngine) -> None:
    """Add the per-customer `customer` scope column to `exclusions`."""
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE exclusions ADD COLUMN IF NOT EXISTS customer VARCHAR(128)")
        )
        await conn.execute(
            sql_text("CREATE INDEX IF NOT EXISTS ix_exclusions_customer ON exclusions (customer)")
        )
    logger.info("exclusions_autotune.columns_ensured")
