"""F1 — idempotent schema adds for gate attribution + SLA lifecycle.

The `sla_events` table itself is created by `Base.metadata.create_all` (it's a
brand-new table, so create_all handles it). This backfill only does what
create_all CANNOT on an EXISTING deployment: add the two attribution columns to
`incidents`. Runs every boot; `IF NOT EXISTS` makes it a no-op after first apply.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.sla.backfill")


async def add_signoff_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS approved_by_id UUID")
        )
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS signed_off_at TIMESTAMPTZ")
        )
        # Response-time SLA: per-severity time-to-first-response target on sla_targets.
        await conn.execute(
            sql_text(
                "ALTER TABLE sla_targets ADD COLUMN IF NOT EXISTS response_target_minutes INTEGER"
            )
        )
    logger.info("sla.signoff_columns_ensured")
