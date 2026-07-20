"""Shift Handoff — idempotent schema add for the analyst-written handoff note.

Adds `handoff_note` to `incidents` on existing deployments (create_all cannot add
a column to an existing table). Runs every boot; `IF NOT EXISTS` makes it a no-op
after first apply.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.handoff_note.backfill")


async def add_handoff_note_column(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS handoff_note TEXT")
        )
    logger.info("handoff_note.column_ensured")
