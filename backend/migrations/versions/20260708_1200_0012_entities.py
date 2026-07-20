"""Entities (OCSF resolution): entities + incident_entities tables

Revision ID: 0012_entities
Revises: 0011_easm_assets
Create Date: 2026-07-08 12:00:00

Per repo convention (rev 0001), `Base.metadata.create_all` creates new tables;
this mirrors it for Alembic deployments with `IF NOT EXISTS`. No seed/backfill —
the tables start empty. The partial unique index dedupes GLOBAL (customer NULL)
entities the composite UNIQUE constraint cannot.
"""

from __future__ import annotations

from alembic import op

revision = "0012_entities"
down_revision = "0011_easm_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS entities (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            customer      VARCHAR(128),
            entity_type   VARCHAR(32) NOT NULL,
            canonical_key VARCHAR(512) NOT NULL,
            display_name  VARCHAR(512) NOT NULL,
            attributes    JSONB,
            first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
            risk_score    DOUBLE PRECISION,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_entity_customer_type_key
                UNIQUE (customer, entity_type, canonical_key)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_entities_customer ON entities (customer)")
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_entity_global_type_key
            ON entities (entity_type, canonical_key)
            WHERE customer IS NULL
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_entities (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            entity_id   UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            role        VARCHAR(16) NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_incident_entity_role
                UNIQUE (incident_id, entity_id, role)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_entities_incident_id "
        "ON incident_entities (incident_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_entities_entity_id "
        "ON incident_entities (entity_id)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS incident_entities")
    op.execute("DROP TABLE IF EXISTS entities")
