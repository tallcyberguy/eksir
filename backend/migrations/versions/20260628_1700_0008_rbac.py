"""RBAC (3.10): permissions / roles / role_permissions / user_roles

Revision ID: 0008_rbac
Revises: 0007_autonomy_threshold
Create Date: 2026-06-28 17:00:00

Per repo convention (rev 0001), `Base.metadata.create_all` creates new tables;
this migration mirrors them for Alembic-driven deployments with `IF NOT EXISTS`
so it coexists with create_all + the boot seeder (`db/rbac_backfill.py`). The
catalogue + system roles are seeded at boot, not here (data-free migration).
"""

from __future__ import annotations

from alembic import op

revision = "0008_rbac"
down_revision = "0007_autonomy_threshold"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS permissions (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name        VARCHAR(100) NOT NULL UNIQUE,
            category    VARCHAR(64),
            description TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_permissions_name ON permissions (name)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_permissions_category ON permissions (category)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
            name        VARCHAR(100) NOT NULL,
            description TEXT,
            is_system   BOOLEAN NOT NULL DEFAULT false,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_roles_tenant_name UNIQUE (tenant_id, name)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_roles_tenant_id ON roles (tenant_id)")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_global_name "
        "ON roles (name) WHERE tenant_id IS NULL"
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
            assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (user_id, role_id)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_roles")
    op.execute("DROP TABLE IF EXISTS role_permissions")
    op.execute("DROP TABLE IF EXISTS roles")
    op.execute("DROP TABLE IF EXISTS permissions")
