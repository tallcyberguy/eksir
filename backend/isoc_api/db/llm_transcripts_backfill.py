"""Idempotent column adds for llm_calls — Phase: LLM transcripts.

Runs every boot. `IF NOT EXISTS` keeps it a no-op after first apply.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.llm_transcripts.backfill")


async def add_transcript_columns(engine: AsyncEngine) -> None:
    """Add system_prompt / user_prompt / response_text / error columns."""
    async with engine.begin() as conn:
        for col in ("system_prompt", "user_prompt", "response_text", "error"):
            await conn.execute(
                sql_text(f"ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS {col} TEXT")
            )
        # Discriminator — free-form short string (analyst_fast/analyst_deep/customer_brief/…).
        await conn.execute(
            sql_text("ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS purpose VARCHAR(32)")
        )
        await conn.execute(
            sql_text("CREATE INDEX IF NOT EXISTS ix_llm_calls_purpose ON llm_calls (purpose)")
        )
    logger.info("llm_transcripts.columns_ensured")
