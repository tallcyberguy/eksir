"""F1 gate attribution + SLA lifecycle: incidents.approved_by_id / signed_off_at

Revision ID: 0005_sla_signoff
Revises: 0004_verdict_reason, 0004_customer_case_html
Create Date: 2026-06-28 12:00:00

MERGE revision: 0003 had branched into two 0004 heads (verdict_reason and
customer_case_html). This revision merges them back into a single head AND adds
F1's two attribution columns in the same step.

Per the repo convention (revision 0001), tables are created by
`Base.metadata.create_all` and migrations only do what create_all can't on an
existing deployment — so the new `sla_events` table is NOT created here (it's a
brand-new table create_all handles); this migration only does the column ALTERs.
`IF NOT EXISTS` so create_all + the boot backfill + this migration coexist.
"""

from __future__ import annotations

from alembic import op

revision = "0005_sla_signoff"
down_revision = ("0004_verdict_reason", "0004_customer_case_html")
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS approved_by_id UUID")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS signed_off_at TIMESTAMPTZ")


def downgrade() -> None:
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS signed_off_at")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS approved_by_id")
