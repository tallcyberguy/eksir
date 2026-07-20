"""initial schema + case_number sequence

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-23 12:00:00
"""

from __future__ import annotations

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Sequence used by incidents.case_number default
    op.execute("CREATE SEQUENCE IF NOT EXISTS isoc_case_seq START 1000")

    # NOTE: Tables themselves are created in init_db() on first boot via
    # Base.metadata.create_all (the SQLAlchemy 2.0 models are the source of truth
    # for the initial schema). Subsequent revisions will use autogenerate to
    # diff against the live DB.
    #
    # We deliberately leave the table DDL out of this revision so that the same
    # codebase can boot either via create_all (dev) or via alembic upgrade (prod)
    # without divergence. The sequence MUST exist before create_all runs because
    # incidents.case_number defaults reference it.


def downgrade() -> None:
    op.execute("DROP SEQUENCE IF EXISTS isoc_case_seq")
