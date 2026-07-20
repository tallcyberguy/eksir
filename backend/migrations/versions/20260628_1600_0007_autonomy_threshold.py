"""Autonomy guardrails (3.9): autonomy_threshold table

Revision ID: 0007_autonomy_threshold
Revises: 0006_queue_claim
Create Date: 2026-06-28 16:00:00

Per the repo convention (revision 0001), `Base.metadata.create_all` creates new
tables; migrations exist for deployments that run Alembic instead. This creates
`autonomy_threshold` with `IF NOT EXISTS` so it coexists with create_all + the
boot seeder (`db/autonomy_backfill.py`). The default rows are seeded at boot, not
here, to keep the migration data-free.
"""

from __future__ import annotations

from alembic import op

revision = "0007_autonomy_threshold"
down_revision = "0006_queue_claim"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS autonomy_threshold (
            id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            action_kind           VARCHAR(32)  NOT NULL,
            tenant_id             UUID         REFERENCES tenants(id) ON DELETE SET NULL,
            blast_radius          VARCHAR(16)  NOT NULL DEFAULT 'high',
            auto_confidence       DOUBLE PRECISION NOT NULL DEFAULT 1.01,
            review_confidence     DOUBLE PRECISION NOT NULL DEFAULT 0.5,
            escalation_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            source                VARCHAR(16)  NOT NULL DEFAULT 'db',
            reason                TEXT,
            updated_by_id         UUID         REFERENCES users(id) ON DELETE SET NULL,
            created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
            CONSTRAINT uq_autonomy_kind_tenant UNIQUE (action_kind, tenant_id),
            CONSTRAINT ck_autonomy_order CHECK (
                escalation_confidence <= review_confidence
                AND review_confidence <= auto_confidence
            )
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_autonomy_threshold_action_kind "
        "ON autonomy_threshold (action_kind)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_autonomy_threshold_tenant_id "
        "ON autonomy_threshold (tenant_id)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS autonomy_threshold")
