"""Hunt (3.13): saved_hunts table

Revision ID: 0009_saved_hunts
Revises: 0008_rbac
Create Date: 2026-06-29 09:00:00

Per repo convention (rev 0001), `Base.metadata.create_all` creates new tables;
this mirrors it for Alembic deployments with `IF NOT EXISTS`. No seed/backfill —
the table starts empty.
"""

from __future__ import annotations

from alembic import op

revision = "0009_saved_hunts"
down_revision = "0008_rbac"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS saved_hunts (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name          VARCHAR(200) NOT NULL,
            nl_query      TEXT NOT NULL,
            translated    JSONB,
            language      VARCHAR(16) NOT NULL DEFAULT 's1ql',
            time_range    VARCHAR(32),
            tenant_id     UUID REFERENCES tenants(id) ON DELETE SET NULL,
            created_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
            last_run_at   TIMESTAMPTZ,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_saved_hunts_tenant_id ON saved_hunts (tenant_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS saved_hunts")
