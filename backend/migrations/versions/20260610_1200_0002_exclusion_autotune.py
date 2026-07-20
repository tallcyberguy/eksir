"""exclusion auto-tuning (F8): customer scope + suggestions table

Revision ID: 0002_exclusion_autotune
Revises: 0001_initial
Create Date: 2026-06-10 12:00:00

Per the project convention established in revision 0001, TABLES themselves are
created by Base.metadata.create_all in init_db() — migrations deliberately leave
table DDL out so create_all (dev) and alembic (prod) can't diverge or race. The
new `exclusion_suggestions` table is therefore created by create_all; this
revision only performs the one thing create_all CANNOT do on an existing
deployment: add the `exclusions.customer` column. (An idempotent boot backfill
does the same; both use IF NOT EXISTS so they coexist safely.)
"""

from __future__ import annotations

from alembic import op

revision = "0002_exclusion_autotune"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Per-customer scope on exclusions (create_all can't ALTER an existing table).
    op.execute("ALTER TABLE exclusions ADD COLUMN IF NOT EXISTS customer VARCHAR(128)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_exclusions_customer ON exclusions (customer)")
    # NOTE: exclusion_suggestions is intentionally NOT created here — create_all
    # owns table creation (see revision 0001's rationale).


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_exclusions_customer")
    op.execute("ALTER TABLE exclusions DROP COLUMN IF EXISTS customer")
