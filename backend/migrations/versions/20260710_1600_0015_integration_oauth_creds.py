"""Integration OAuth credentials: client_id / client_secret / oauth_tenant_id

Revision ID: 0015_integration_oauth_creds
Revises: 0014_ingest_sources
Create Date: 2026-07-10 16:00:00

Additive columns on `integrations` so providers that authenticate with OAuth
client credentials (CrowdStrike, Microsoft Defender) can store them alongside the
single-token providers (Vision One, SentinelOne). client_secret is Fernet-
encrypted like api_key. Idempotent ADD COLUMN IF NOT EXISTS; no backfill.
"""

from __future__ import annotations

from alembic import op

revision = "0015_integration_oauth_creds"
down_revision = "0014_ingest_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE integrations ADD COLUMN IF NOT EXISTS client_id VARCHAR(256)")
    op.execute("ALTER TABLE integrations ADD COLUMN IF NOT EXISTS client_secret_encrypted TEXT")
    op.execute("ALTER TABLE integrations ADD COLUMN IF NOT EXISTS oauth_tenant_id VARCHAR(128)")


def downgrade() -> None:
    op.execute("ALTER TABLE integrations DROP COLUMN IF EXISTS oauth_tenant_id")
    op.execute("ALTER TABLE integrations DROP COLUMN IF EXISTS client_secret_encrypted")
    op.execute("ALTER TABLE integrations DROP COLUMN IF EXISTS client_id")
