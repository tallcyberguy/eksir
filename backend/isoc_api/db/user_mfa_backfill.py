"""Stage 3b/3c — idempotent column adds on `users` for MFA + token revocation.

`Base.metadata.create_all` never ALTERs an existing table, so on a deployment
whose `users` table predates these columns they must be added explicitly. Runs
every boot; `ADD COLUMN IF NOT EXISTS` makes it a no-op after first apply.

  totp_secret    — Fernet-encrypted TOTP secret (nullable; set on enrollment)
  mfa_enabled    — whether the second factor is active
  token_version  — bumped on logout/revoke to invalidate outstanding JWTs
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.user.mfa_backfill")


async def add_user_mfa_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(sql_text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT"))
        await conn.execute(
            sql_text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "mfa_enabled BOOLEAN NOT NULL DEFAULT false"
            )
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "token_version INTEGER NOT NULL DEFAULT 0"
            )
        )
    logger.info("user.mfa_columns_ensured")
