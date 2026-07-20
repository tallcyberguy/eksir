"""Ingest source observability: per-poll metrics

Revision ID: 0016_ingest_source_metrics
Revises: 0015_integration_oauth_creds
Create Date: 2026-07-10 18:00:00

Additive columns on `ingest_sources` so the Sources page can show per-source
health: last poll duration (ms), alerts ingested last poll, and a running total.
Idempotent ADD COLUMN IF NOT EXISTS; no backfill.
"""

from __future__ import annotations

from alembic import op

revision = "0016_ingest_source_metrics"
down_revision = "0015_integration_oauth_creds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS last_poll_ms INTEGER")
    op.execute("ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS last_poll_count INTEGER")
    op.execute(
        "ALTER TABLE ingest_sources ADD COLUMN IF NOT EXISTS total_ingested INTEGER NOT NULL DEFAULT 0"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE ingest_sources DROP COLUMN IF EXISTS total_ingested")
    op.execute("ALTER TABLE ingest_sources DROP COLUMN IF EXISTS last_poll_count")
    op.execute("ALTER TABLE ingest_sources DROP COLUMN IF EXISTS last_poll_ms")
