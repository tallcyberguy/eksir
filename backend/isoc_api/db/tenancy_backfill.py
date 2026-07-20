"""One-time backfill: ensure every incident with a customer string has a
matching Tenant row and incidents.tenant_id set.

Idempotent — safe to run on every boot. After the first successful run with
no NULL tenant_ids left for incidents that have a customer, this is a no-op.

Phase 1 contract:
  • Each distinct non-null incidents.customer → one CLIENT tenant
  • Tenant name = customer string (unchanged)
  • Tenant slug = slugify(customer)
  • parent_id = NULL (the analyst can re-parent under an MSSP later)
  • Existing tenant_ids are never overwritten
"""

from __future__ import annotations

import re

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.tenancy.backfill")


def _slugify(name: str) -> str:
    """customer 'Polisan Kansai' → 'polisan-kansai'. Stable across runs."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", name).strip("-").lower()
    return slug or "unnamed"


async def backfill_tenants(engine: AsyncEngine) -> None:
    """Create CLIENT tenants for distinct incidents.customer values and
    backfill incidents.tenant_id where it's NULL."""
    async with engine.begin() as conn:
        # On existing deployments, `create_all` won't add the new tenant_id
        # column to the pre-existing incidents table — we ALTER it idempotently.
        await conn.execute(
            sql_text("""
            ALTER TABLE incidents
            ADD COLUMN IF NOT EXISTS tenant_id UUID
                REFERENCES tenants(id) ON DELETE SET NULL
        """)
        )
        await conn.execute(
            sql_text("CREATE INDEX IF NOT EXISTS ix_incidents_tenant_id ON incidents (tenant_id)")
        )

        # Customer-notification routing fields on tenants (Phase-CC1).
        await conn.execute(
            sql_text(
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notification_email    VARCHAR(255)"
            )
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notification_email_cc VARCHAR(512)"
            )
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS locale                VARCHAR(8)"
            )
        )

        # Soft-delete on incidents (admin-only archive/restore/purge flow).
        # NULL = visible. Set when admin clicks "Archive". Hard delete drops the row.
        await conn.execute(
            sql_text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
        )
        await conn.execute(
            sql_text("CREATE INDEX IF NOT EXISTS ix_incidents_deleted_at ON incidents (deleted_at)")
        )

        # ── Customer-case attribution + prior-cases-note ────────────────
        # New 1-liners under the structured Threat Intelligence table in the
        # customer notification email. Old cases stay readable (template
        # falls back to the legacy threat_intel_summary if these are NULL).
        await conn.execute(
            sql_text("ALTER TABLE customer_cases ADD COLUMN IF NOT EXISTS attribution VARCHAR(255)")
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE customer_cases ADD COLUMN IF NOT EXISTS prior_cases_note VARCHAR(255)"
            )
        )

        # ── Threat-feed parser_config (CSV-aware sync) ──────────────────
        # Optional JSONB per feed describing how to parse the response body.
        # NULL = legacy line-based parsing. Allows CSV feeds (abuse.ch
        # ThreatFox / SSLBL) to ship without a schema migration.
        await conn.execute(
            sql_text("ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS parser_config JSONB")
        )

        # ── Trigram indexes for /incidents free-text search ─────────────
        # The list endpoint does `ILIKE '%text%'` on title / rule_name /
        # case_number. Without these indexes that's a sequential scan and
        # gets painful past ~100k rows. pg_trgm + GIN turns it into a
        # 50ms indexed lookup even at 10M rows.
        #
        # The CREATE EXTENSION is a no-op if it's already enabled, but
        # requires the role to have CREATE on the database. Our compose
        # postgres user owns the DB so this works; if you ever move to a
        # managed Postgres with a non-owner app role, do this once as the
        # admin role and remove it from here.
        await conn.execute(sql_text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await conn.execute(
            sql_text(
                "CREATE INDEX IF NOT EXISTS ix_incidents_title_trgm "
                "ON incidents USING gin (title gin_trgm_ops)"
            )
        )
        await conn.execute(
            sql_text(
                "CREATE INDEX IF NOT EXISTS ix_incidents_rule_name_trgm "
                "ON incidents USING gin (rule_name gin_trgm_ops)"
            )
        )
        await conn.execute(
            sql_text(
                "CREATE INDEX IF NOT EXISTS ix_incidents_case_number_trgm "
                "ON incidents USING gin (case_number gin_trgm_ops)"
            )
        )

        # Dashboard layout (drag-drop persistence).
        # Both tables get a nullable JSONB column. NULL means "use the next
        # layer's value": effective_layout = user.dashboard_layout OR
        # tenant.dashboard_layout OR the built-in default in the frontend.
        await conn.execute(
            sql_text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS dashboard_layout JSONB")
        )
        await conn.execute(
            sql_text("ALTER TABLE users   ADD COLUMN IF NOT EXISTS dashboard_layout JSONB")
        )

        # Pull distinct customer strings that don't yet have a matching tenant.
        rows = (
            await conn.execute(
                sql_text("""
            SELECT DISTINCT customer
              FROM incidents
             WHERE customer IS NOT NULL
               AND customer <> ''
        """)
            )
        ).all()
        customers = [r[0] for r in rows]
        if not customers:
            return

        # Build name → slug map and de-dupe slug collisions (rare, but possible
        # when two customer strings normalise to the same slug).
        used_slugs: set[str] = set()
        existing = {r[0] for r in (await conn.execute(sql_text("SELECT slug FROM tenants"))).all()}
        used_slugs.update(existing)

        created = 0
        for customer in customers:
            base = _slugify(customer)
            slug = base
            n = 1
            while slug in used_slugs:
                n += 1
                slug = f"{base}-{n}"
            used_slugs.add(slug)

            res = await conn.execute(
                sql_text("""
                INSERT INTO tenants (id, name, slug, tier, created_at, updated_at)
                VALUES (gen_random_uuid(), :name, :slug, 'client', now(), now())
                ON CONFLICT (name) DO NOTHING
            """),
                {"name": customer, "slug": slug},
            )
            if res.rowcount:
                created += 1

        # Backfill incidents.tenant_id for any rows that still lack one.
        result = await conn.execute(
            sql_text("""
            UPDATE incidents
               SET tenant_id = t.id
              FROM tenants t
             WHERE incidents.customer = t.name
               AND incidents.tenant_id IS NULL
        """)
        )
        linked = result.rowcount or 0

        # Phase-5: audit_log gains tenant_id, idempotent ALTER + backfill from
        # the linked incident for target_type='incident' rows.
        await conn.execute(
            sql_text("""
            ALTER TABLE audit_log
            ADD COLUMN IF NOT EXISTS tenant_id UUID
                REFERENCES tenants(id) ON DELETE SET NULL
        """)
        )
        await conn.execute(
            sql_text("CREATE INDEX IF NOT EXISTS ix_audit_log_tenant_id ON audit_log (tenant_id)")
        )
        audit_res = await conn.execute(
            sql_text("""
            UPDATE audit_log
               SET tenant_id = i.tenant_id
              FROM incidents i
             WHERE audit_log.target_type = 'incident'
               AND audit_log.target_id = i.id
               AND audit_log.tenant_id IS NULL
               AND i.tenant_id IS NOT NULL
        """)
        )
        audit_linked = audit_res.rowcount or 0

        if created or linked or audit_linked:
            logger.info(
                "tenancy.backfill_done",
                tenants_created=created,
                incidents_linked=linked,
                audit_entries_linked=audit_linked,
            )
