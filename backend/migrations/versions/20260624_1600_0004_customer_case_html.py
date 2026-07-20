"""customer_cases: edited_html + body_source (analyst HTML override / editor)

Revision ID: 0004_customer_case_html
Revises: 0003_timeline_steps
Create Date: 2026-06-24 16:00:00

Column adds only — per the repo convention (revision 0001) tables are created by
Base.metadata.create_all; migrations only do what create_all can't on an
existing deployment. All statements are IF NOT EXISTS so create_all + boot
backfill + this migration coexist without divergence.
"""

from __future__ import annotations

from alembic import op

revision = "0004_customer_case_html"
down_revision = "0003_timeline_steps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE customer_cases ADD COLUMN IF NOT EXISTS edited_html TEXT")
    op.execute(
        "ALTER TABLE customer_cases "
        "ADD COLUMN IF NOT EXISTS body_source VARCHAR(16) NOT NULL DEFAULT 'generated'"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE customer_cases DROP COLUMN IF EXISTS body_source")
    op.execute("ALTER TABLE customer_cases DROP COLUMN IF EXISTS edited_html")
