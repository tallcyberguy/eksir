"""Idempotent migration: create the llm_config table on existing deployments.

Called from session.init_db() on every startup — safe to re-run because every
statement uses IF NOT EXISTS / IF NOT EXISTS guards.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


async def add_llm_config_table(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS llm_config (
                    id           INTEGER PRIMARY KEY DEFAULT 1,
                    endpoint_url VARCHAR(500) NOT NULL,
                    api_key_encrypted TEXT,
                    model_name   VARCHAR(200) NOT NULL,
                    temperature  NUMERIC(4, 2) NOT NULL DEFAULT 0.2,
                    max_tokens   INTEGER NOT NULL DEFAULT 4096,
                    updated_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
                    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
        )
