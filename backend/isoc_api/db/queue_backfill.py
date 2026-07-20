"""Investigation Queue (3.6) — idempotent schema adds for claim/snooze.

`assignee_id` already exists on `incidents`; this only adds the three net-new
columns create_all CANNOT add to an EXISTING deployment. Runs every boot;
`IF NOT EXISTS` makes it a no-op after first apply.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.queue.backfill")


async def add_queue_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ")
        )
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ")
        )
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS snoozed_by_id UUID")
        )
        await conn.execute(
            sql_text(
                "CREATE INDEX IF NOT EXISTS ix_incidents_snoozed_until ON incidents (snoozed_until)"
            )
        )
    logger.info("queue.columns_ensured")
