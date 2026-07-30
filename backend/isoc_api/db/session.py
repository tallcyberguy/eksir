"""Async SQLAlchemy engine + session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..settings import settings
from .base import Base

_engine = create_async_engine(
    settings.database_url,
    echo=settings.is_dev,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=10,
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=_engine,
    expire_on_commit=False,
    autoflush=False,
)


async def init_db() -> None:
    """In dev: create tables. In prod: rely on Alembic migrations.

    The compose entrypoint runs `alembic upgrade head` before starting uvicorn,
    so this only creates tables on first boot if migrations aren't present.

    We unconditionally `CREATE SEQUENCE IF NOT EXISTS isoc_case_seq` first
    because `incidents.case_number` defaults to `nextval('isoc_case_seq')`.
    """
    from sqlalchemy import text as sql_text

    from . import models  # noqa: F401 — register mappers
    from .autonomy_backfill import seed_autonomy_defaults
    from .case_number_prefix_backfill import rename_case_number_prefixes
    from .customer_case_html_backfill import add_customer_case_html_columns
    from .escalation_backfill import add_escalation_columns
    from .exclusions_autotune_backfill import add_exclusion_customer_scope
    from .handoff_note_backfill import add_handoff_note_column
    from .ingest_observability_backfill import add_ingest_observability_columns
    from .integrations_backfill import add_integrations_table
    from .llm_config_backfill import add_llm_config_table
    from .llm_transcripts_backfill import add_transcript_columns
    from .queue_backfill import add_queue_columns
    from .rbac_backfill import seed_rbac
    from .sla_backfill import add_signoff_columns
    from .tenancy_backfill import backfill_tenants
    from .threat_intel_backfill import seed_threat_feeds
    from .timeline_steps_backfill import add_timeline_step_columns
    from .user_mfa_backfill import add_user_mfa_columns
    from .verdict_reason_backfill import add_verdict_reason_column

    async with _engine.begin() as conn:
        # Serialize schema bootstrap across uvicorn workers. The backend runs with
        # `--workers 2`, so each worker runs this lifespan concurrently. SQLAlchemy's
        # create_all is NOT concurrency-safe for a brand-new table — checkfirst does
        # a SELECT then a plain `CREATE TABLE` (no IF NOT EXISTS), so two workers can
        # both pass the check and the loser raises `relation already exists`. A
        # transaction-scoped advisory lock makes the first worker create everything
        # while the others wait, then find the tables present and skip. (The column
        # backfills below are already race-safe via ADD COLUMN IF NOT EXISTS.)
        await conn.execute(sql_text("SELECT pg_advisory_xact_lock(823641927)"))
        await conn.execute(sql_text("CREATE SEQUENCE IF NOT EXISTS isoc_case_seq START 1000"))
        # Sequence for customer-facing case numbers (CASE-000001…).
        await conn.execute(
            sql_text("CREATE SEQUENCE IF NOT EXISTS eksir_customer_case_seq START 1")
        )
        # `checkfirst=True` is the default — won't error if tables exist.
        await conn.run_sync(Base.metadata.create_all)

    # Phase-1 tenancy backfill: idempotent, runs every boot but only acts
    # on incidents that still lack a tenant_id.
    await backfill_tenants(_engine)

    # Seed the 8 SOCRadar feed rows on first boot.
    await seed_threat_feeds(_engine)

    # Phase: LLM transcripts — add system_prompt / user_prompt / response_text
    # columns to llm_calls on existing deployments.
    await add_transcript_columns(_engine)

    # Phase: Admin LLM settings — create llm_config table on existing deployments.
    await add_llm_config_table(_engine)

    # ADR-0003/0005: admin integration credentials — create `integrations` table.
    await add_integrations_table(_engine)

    # Feature F8: exclusion auto-tuning — add `customer` scope column to
    # exclusions on existing deployments (the suggestions table is create_all'd).
    await add_exclusion_customer_scope(_engine)

    # Pipeline visibility — add level/step/duration_ms to timeline_events.
    await add_timeline_step_columns(_engine)

    # Analyst verdict rationale — add `verdict_reason` to incidents.
    await add_verdict_reason_column(_engine)

    # Customer-notification editor — add edited_html / body_source to customer_cases.
    await add_customer_case_html_columns(_engine)

    # F1 — gate attribution: add approved_by_id / signed_off_at to incidents.
    # (The sla_events table is created by create_all above.)
    await add_signoff_columns(_engine)

    # Investigation Queue (3.6): claimed_at / snoozed_until / snoozed_by_id.
    await add_queue_columns(_engine)

    # L1 → L2 escalation: escalated_at / escalated_by_id / escalation_note.
    await add_escalation_columns(_engine)

    # Per-source observability (#96): last_poll_ms / last_poll_count / total_ingested
    # on ingest_sources (the model gained them but #96 shipped no backfill).
    await add_ingest_observability_columns(_engine)

    # Shift Handoff: analyst-written handoff_note on incidents.
    await add_handoff_note_column(_engine)

    # Naming cleanup: incidents → INC-, customer cases → CASE- (renumber existing).
    await rename_case_number_prefixes(_engine)

    # Autonomy guardrails (3.9): seed the global default policy rows (table is
    # create_all'd; this only seeds tenant_id-NULL defaults idempotently).
    await seed_autonomy_defaults(_engine)

    # RBAC (3.10): seed the permission catalogue + the three system roles + grants.
    await seed_rbac(_engine)

    # Stage 3b/3c: MFA (totp_secret / mfa_enabled) + revocation (token_version).
    await add_user_mfa_columns(_engine)


async def dispose_db() -> None:
    await _engine.dispose()


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields a session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
