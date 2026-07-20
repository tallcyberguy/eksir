"""EASM (Phase 3): easm_assets table

Revision ID: 0011_easm_assets
Revises: 0009_saved_hunts
Create Date: 2026-06-29 11:00:00

Per repo convention (rev 0001), `Base.metadata.create_all` creates new tables;
this mirrors it for Alembic deployments with `IF NOT EXISTS`. No seed/backfill —
the register starts empty, so there is no boot-time seeder to crash.
"""

from __future__ import annotations

from alembic import op

revision = "0011_easm_assets"
down_revision = "0009_saved_hunts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS easm_assets (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            value           VARCHAR(255) NOT NULL,
            asset_type      VARCHAR(16) NOT NULL DEFAULT 'domain',
            tags            JSONB,
            notes           TEXT,
            enabled         BOOLEAN NOT NULL DEFAULT true,
            last_result     JSONB,
            last_scanned_at TIMESTAMPTZ,
            tenant_id       UUID REFERENCES tenants(id) ON DELETE SET NULL,
            created_by_id   UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_easm_assets_value ON easm_assets (value)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_easm_assets_tenant_id ON easm_assets (tenant_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS easm_assets")
