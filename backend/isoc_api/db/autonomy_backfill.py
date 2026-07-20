"""Autonomy guardrails (3.9) — seed the global default policy rows.

The `autonomy_threshold` table itself is created by `Base.metadata.create_all`
(brand-new table). This backfill only SEEDS the global default rows (tenant_id
NULL) idempotently via `ON CONFLICT DO NOTHING`, so the admin editor has a row
to show and reset to. Code defaults in `pipeline/guardrails.py` remain the real
fallback — these rows just make the defaults visible + editable.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger
from ..pipeline.guardrails import _DEFAULT_THRESHOLDS, BLAST_RADIUS

logger = get_logger("isoc.autonomy.backfill")


async def seed_autonomy_defaults(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for kind, br in BLAST_RADIUS.items():
            auto, review, esc = _DEFAULT_THRESHOLDS[br]
            # NULL tenant_id defeats `ON CONFLICT (action_kind, tenant_id)` (SQL
            # treats NULLs as distinct → it would insert a duplicate default every
            # boot). Guard with WHERE NOT EXISTS instead. `:kind` is reused, so
            # cast it for asyncpg type deduction.
            await conn.execute(
                sql_text(
                    "INSERT INTO autonomy_threshold "
                    "(id, action_kind, tenant_id, blast_radius, auto_confidence, "
                    " review_confidence, escalation_confidence, source, created_at, updated_at) "
                    "SELECT gen_random_uuid(), cast(:kind AS varchar), NULL, :br, :auto, "
                    " :review, :esc, 'default', now(), now() "
                    "WHERE NOT EXISTS (SELECT 1 FROM autonomy_threshold "
                    "WHERE action_kind = cast(:kind AS varchar) AND tenant_id IS NULL)"
                ),
                {"kind": kind, "br": br, "auto": auto, "review": review, "esc": esc},
            )
    logger.info("autonomy.defaults_seeded")
