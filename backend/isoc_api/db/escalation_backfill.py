"""Incident L1 → L2 escalation — idempotent schema adds.

Adds the three escalation columns `create_all` CANNOT add to an EXISTING
`incidents` table. Runs every boot; `IF NOT EXISTS` makes it a no-op after first
apply. Mirrors db/queue_backfill.py (and Alembic 0017_incident_escalation).
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.escalation.backfill")


async def add_escalation_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ")
        )
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalated_by_id UUID")
        )
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalation_note TEXT")
        )
        await conn.execute(
            sql_text(
                "CREATE INDEX IF NOT EXISTS ix_incidents_escalated_at ON incidents (escalated_at)"
            )
        )
    logger.info("escalation.columns_ensured")
