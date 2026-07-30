"""RBAC (3.10) — seed the permission catalogue + the three system roles.

The four RBAC tables are created by `Base.metadata.create_all`; this idempotent
seeder fills them: the perm catalogue (`ON CONFLICT (name)`), the global system
roles (`WHERE NOT EXISTS` — NULL tenant_id defeats the unique constraint, so we
guard explicitly), and each role's grants (composite-PK `ON CONFLICT`). Grants
are derived from `auth.permissions.STATIC_FALLBACK` — one source of truth shared
with the live resolver.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..auth.permissions import (
    ALL_PERMS,
    CATALOGUE,
    EXTRA_SYSTEM_ROLES,
    STATIC_FALLBACK,
    WILDCARD,
)
from ..db.enums import Role
from ..logging_config import get_logger

logger = get_logger("isoc.rbac.backfill")

_ROLE_DESC = {
    Role.ADMIN: "Full administrative access (system role)",
    Role.ANALYST: "Triage, investigate and sign off cases (system role)",
    Role.VIEWER: "Read-only access (system role)",
}


async def seed_rbac(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for name, category, desc in CATALOGUE:
            await conn.execute(
                sql_text(
                    "INSERT INTO permissions (id, name, category, description) "
                    "VALUES (gen_random_uuid(), :n, :c, :d) ON CONFLICT (name) DO NOTHING"
                ),
                {"n": name, "c": category, "d": desc},
            )

        for role, desc in _ROLE_DESC.items():
            # `:name` is used in both the SELECT list and the WHERE — cast it so
            # asyncpg can deduce a single, consistent type (else
            # AmbiguousParameterError on $1).
            await conn.execute(
                sql_text(
                    "INSERT INTO roles (id, tenant_id, name, description, is_system, "
                    "created_at, updated_at) "
                    "SELECT gen_random_uuid(), NULL, cast(:name AS varchar), "
                    "cast(:desc AS text), true, now(), now() "
                    "WHERE NOT EXISTS (SELECT 1 FROM roles "
                    "WHERE name = cast(:name AS varchar) AND tenant_id IS NULL)"
                ),
                {"name": str(role), "desc": desc},
            )

        for role in (Role.ADMIN, Role.ANALYST, Role.VIEWER):
            fb = STATIC_FALLBACK[role]
            perms = ALL_PERMS if WILDCARD in fb else fb
            for perm in perms:
                await conn.execute(
                    sql_text(
                        "INSERT INTO role_permissions (role_id, permission_id) "
                        "SELECT r.id, p.id FROM roles r, permissions p "
                        "WHERE r.name = :role AND r.tenant_id IS NULL AND p.name = :perm "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {"role": str(role), "perm": perm},
                )

        # Extra seeded system roles (e.g. "L2 Analyst") beyond the coarse mirrors.
        for rname, (rdesc, rperms) in EXTRA_SYSTEM_ROLES.items():
            await conn.execute(
                sql_text(
                    "INSERT INTO roles (id, tenant_id, name, description, is_system, "
                    "created_at, updated_at) "
                    "SELECT gen_random_uuid(), NULL, cast(:name AS varchar), "
                    "cast(:desc AS text), true, now(), now() "
                    "WHERE NOT EXISTS (SELECT 1 FROM roles "
                    "WHERE name = cast(:name AS varchar) AND tenant_id IS NULL)"
                ),
                {"name": rname, "desc": rdesc},
            )
            for perm in rperms:
                await conn.execute(
                    sql_text(
                        "INSERT INTO role_permissions (role_id, permission_id) "
                        "SELECT r.id, p.id FROM roles r, permissions p "
                        "WHERE r.name = :role AND r.tenant_id IS NULL AND p.name = :perm "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {"role": rname, "perm": perm},
                )
    logger.info("rbac.seeded")
