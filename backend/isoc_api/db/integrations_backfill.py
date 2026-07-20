"""Idempotent migration: create the `integrations` table on existing deployments.

Called from session.init_db() on every startup — safe to re-run (IF NOT EXISTS).
Mirrors llm_config_backfill. Stores admin-managed EDR/XDR API keys (ADR-0003/0005),
Fernet-encrypted at rest.

Also adds the OAuth client-credential columns PR #93 introduced on the model after
this table shipped (`client_id` / `client_secret_encrypted` / `oauth_tenant_id`).
create_all never ALTERs an existing table, so without these ADDs any deployment
whose `integrations` table predates #93 500'd on the Connectors page with
`UndefinedColumnError: column integrations.client_id does not exist`.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


async def add_integrations_table(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS integrations (
                    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    provider      VARCHAR(32) NOT NULL,
                    identifier    VARCHAR(128) NOT NULL,
                    label         VARCHAR(200),
                    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
                    region        VARCHAR(16),
                    base_url      VARCHAR(256),
                    api_key_encrypted TEXT,
                    updated_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_integration_provider_identifier UNIQUE (provider, identifier)
                )
            """)
        )
        await conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_integrations_provider ON integrations (provider)")
        )
        # PR #93 — OAuth client-credential fields added to the model after the
        # table shipped. Idempotent ADDs for deployments created before #93.
        for stmt in (
            "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS client_id VARCHAR(256)",
            "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS client_secret_encrypted TEXT",
            "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS oauth_tenant_id VARCHAR(128)",
        ):
            await conn.execute(text(stmt))
