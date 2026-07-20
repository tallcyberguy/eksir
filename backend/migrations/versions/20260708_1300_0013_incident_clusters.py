"""Alert correlation (Phase 2a): incident_clusters + incident_cluster_members

Revision ID: 0013_incident_clusters
Revises: 0012_entities
Create Date: 2026-07-08 13:00:00

Per repo convention (rev 0001), `Base.metadata.create_all` creates new tables;
this mirrors it for Alembic deployments with `IF NOT EXISTS`. No seed/backfill —
the tables start empty. A reversible cluster layer over 1-alert-1-incident:
same-tenant incidents sharing a strong entity are grouped. `seed_incident_id`
is SET NULL (not RESTRICT) so purging an incident can't wedge the cluster; the
`incident_id` unique index enforces one incident -> at most one cluster.
"""

from __future__ import annotations

from alembic import op

revision = "0013_incident_clusters"
down_revision = "0012_entities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_clusters (
            id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        UUID REFERENCES tenants(id) ON DELETE SET NULL,
            seed_incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
            cluster_key      VARCHAR(64),
            title            VARCHAR(512),
            status           VARCHAR(16) NOT NULL DEFAULT 'open',
            member_count     INTEGER NOT NULL DEFAULT 1,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_clusters_tenant_id ON incident_clusters (tenant_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_clusters_cluster_key "
        "ON incident_clusters (cluster_key)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_clusters_created_at "
        "ON incident_clusters (created_at)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_cluster_members (
            id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            cluster_id       UUID NOT NULL REFERENCES incident_clusters(id) ON DELETE CASCADE,
            incident_id      UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            shared_entity_id UUID REFERENCES entities(id) ON DELETE SET NULL,
            method           VARCHAR(16) NOT NULL DEFAULT 'auto',
            attached_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            attached_by_id   UUID REFERENCES users(id) ON DELETE SET NULL,
            CONSTRAINT uq_cluster_incident UNIQUE (cluster_id, incident_id),
            CONSTRAINT uq_cluster_member_incident UNIQUE (incident_id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_cluster_members_cluster_id "
        "ON incident_cluster_members (cluster_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_incident_cluster_members_incident_id "
        "ON incident_cluster_members (incident_id)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS incident_cluster_members")
    op.execute("DROP TABLE IF EXISTS incident_clusters")
