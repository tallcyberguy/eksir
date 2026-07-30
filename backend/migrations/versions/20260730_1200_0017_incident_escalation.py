"""Incident L1 -> L2 escalation: incidents.escalated_at / escalated_by_id / escalation_note

Revision ID: 0017_incident_escalation
Revises: 0016_ingest_source_metrics
Create Date: 2026-07-30 12:00:00

Per the repo convention (revision 0001), tables are created by
`Base.metadata.create_all`; migrations only add what create_all can't on an
existing deployment. These columns are added with `IF NOT EXISTS` so create_all
+ the boot backfill (`db/escalation_backfill.py`) + this migration coexist.
"""

from __future__ import annotations

from alembic import op

revision = "0017_incident_escalation"
down_revision = "0016_ingest_source_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalated_by_id UUID")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalation_note TEXT")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_escalated_at ON incidents (escalated_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_incidents_escalated_at")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS escalation_note")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS escalated_by_id")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS escalated_at")
