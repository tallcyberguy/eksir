"""Idempotent column adds for customer_cases — analyst HTML override (editor).

Runs every boot. `IF NOT EXISTS` keeps it a no-op after first apply. Adds the
edited_html / body_source columns the notification HTML editor writes to.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.customer_case_html.backfill")


async def add_customer_case_html_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sql_text("ALTER TABLE customer_cases ADD COLUMN IF NOT EXISTS edited_html TEXT")
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE customer_cases "
                "ADD COLUMN IF NOT EXISTS body_source VARCHAR(16) NOT NULL DEFAULT 'generated'"
            )
        )
        # "Actions taken on your behalf" — what the SOC executed for the customer
        # (block/isolate/collect), grounded in the incident's executed actions.
        await conn.execute(
            sql_text("ALTER TABLE customer_cases ADD COLUMN IF NOT EXISTS actions_taken JSONB")
        )
    logger.info("customer_case_html.columns_ensured")
