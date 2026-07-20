"""Idempotent column adds for timeline_events — pipeline stage visibility.

Runs every boot. `IF NOT EXISTS` keeps it a no-op after first apply. Adds the
level / step / duration_ms columns that drive the stage-checklist Timeline UI.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.timeline_steps.backfill")


async def add_timeline_step_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text(
                "ALTER TABLE timeline_events "
                "ADD COLUMN IF NOT EXISTS level VARCHAR(16) NOT NULL DEFAULT 'info'"
            )
        )
        await conn.execute(
            sql_text("ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS step VARCHAR(32)")
        )
        await conn.execute(
            sql_text("ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS duration_ms INTEGER")
        )
        await conn.execute(
            sql_text("CREATE INDEX IF NOT EXISTS ix_timeline_events_step ON timeline_events (step)")
        )
    logger.info("timeline_steps.columns_ensured")
