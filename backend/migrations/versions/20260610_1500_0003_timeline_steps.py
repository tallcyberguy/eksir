"""pipeline stage visibility: timeline_events level/step/duration_ms

Revision ID: 0003_timeline_steps
Revises: 0002_exclusion_autotune
Create Date: 2026-06-10 15:00:00

Column adds only — per the repo convention (revision 0001) tables are created by
Base.metadata.create_all; migrations only do what create_all can't on an
existing deployment. All statements are IF NOT EXISTS so create_all + boot
backfill + this migration coexist without divergence.
"""

from __future__ import annotations

from alembic import op

revision = "0003_timeline_steps"
down_revision = "0002_exclusion_autotune"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE timeline_events "
        "ADD COLUMN IF NOT EXISTS level VARCHAR(16) NOT NULL DEFAULT 'info'"
    )
    op.execute("ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS step VARCHAR(32)")
    op.execute("ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS duration_ms INTEGER")
    op.execute("CREATE INDEX IF NOT EXISTS ix_timeline_events_step ON timeline_events (step)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_timeline_events_step")
    op.execute("ALTER TABLE timeline_events DROP COLUMN IF EXISTS duration_ms")
    op.execute("ALTER TABLE timeline_events DROP COLUMN IF EXISTS step")
    op.execute("ALTER TABLE timeline_events DROP COLUMN IF EXISTS level")
