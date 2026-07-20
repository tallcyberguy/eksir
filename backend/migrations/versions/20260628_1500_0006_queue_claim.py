"""Investigation Queue (3.6): incidents.claimed_at / snoozed_until / snoozed_by_id

Revision ID: 0006_queue_claim
Revises: 0005_sla_signoff
Create Date: 2026-06-28 15:00:00

Per the repo convention (revision 0001), tables are created by
`Base.metadata.create_all`; migrations only add what create_all can't on an
existing deployment. These three columns are added with `IF NOT EXISTS` so
create_all + the boot backfill (`db/queue_backfill.py`) + this migration coexist.
`assignee_id` already exists (F1-era) and is NOT touched here.
"""

from __future__ import annotations

from alembic import op

revision = "0006_queue_claim"
down_revision = "0005_sla_signoff"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS snoozed_by_id UUID")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_snoozed_until ON incidents (snoozed_until)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_incidents_snoozed_until")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS snoozed_by_id")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS snoozed_until")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS claimed_at")
