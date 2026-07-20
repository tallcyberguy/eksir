"""analyst verdict rationale: incidents.verdict_reason

Revision ID: 0004_verdict_reason
Revises: 0003_timeline_steps
Create Date: 2026-06-10 17:00:00

Column add only — per the repo convention (revision 0001) tables are created by
Base.metadata.create_all; migrations only do what create_all can't on an
existing deployment. IF NOT EXISTS so create_all + boot backfill + this
migration coexist without divergence.
"""

from __future__ import annotations

from alembic import op

revision = "0004_verdict_reason"
down_revision = "0003_timeline_steps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS verdict_reason TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS verdict_reason")
