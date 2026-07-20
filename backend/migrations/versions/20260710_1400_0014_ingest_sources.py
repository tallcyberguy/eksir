"""Pull ingestion sources: ingest_sources table

Revision ID: 0014_ingest_sources
Revises: 0013_incident_clusters
Create Date: 2026-07-10 14:00:00

Per repo convention (rev 0001), `Base.metadata.create_all` creates new tables on
startup; this mirrors it for Alembic deployments with `IF NOT EXISTS`. No
seed/backfill — the table starts empty and every row ships `enabled = false`, so
the `pull_ingest` cron is a no-op until an admin registers and enables a source.
"""

from __future__ import annotations

from alembic import op

revision = "0014_ingest_sources"
down_revision = "0013_incident_clusters"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_sources (
            id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            provider           VARCHAR(32) NOT NULL,
            identifier         VARCHAR(128) NOT NULL DEFAULT 'default',
            customer           VARCHAR(128),
            enabled            BOOLEAN NOT NULL DEFAULT false,
            interval_seconds   INTEGER NOT NULL DEFAULT 300,
            min_severity       VARCHAR(16),
            max_items          INTEGER NOT NULL DEFAULT 100,
            field_map          JSONB,
            cursor             JSONB NOT NULL DEFAULT '{}'::jsonb,
            consecutive_errors INTEGER NOT NULL DEFAULT 0,
            last_error         TEXT,
            last_poll_at       TIMESTAMPTZ,
            last_success_at    TIMESTAMPTZ,
            created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_ingest_source_provider_identifier
                UNIQUE (provider, identifier)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_ingest_sources_customer ON ingest_sources (customer)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ingest_sources")
