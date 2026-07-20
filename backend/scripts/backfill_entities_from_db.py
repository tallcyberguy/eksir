"""Backfill the ``entities`` + ``incident_entities`` tables from existing incidents.

Entity resolution (``pipeline/ocsf.to_entities`` → ``adapters/entity_store``) only
runs for alerts ingested AFTER the entity subsystem shipped. Every incident already
in Postgres carries its ``normalized`` alert, so we can re-resolve entities for the
back catalogue and populate the entity graph without re-running the whole pipeline.

Mirrors ``_step_entities``: for each incident we run ``ocsf.to_entities`` and, per
candidate, UPSERT the entity + link it to the incident inside its own SAVEPOINT
(``begin_nested``) so one bad row never poisons the batch. UNLIKE the pipeline step
we do NOT write ``enrichment['entities']`` and emit NO timeline events — this is a
pure graph backfill. Idempotent (PG ON CONFLICT), so re-running is safe.

Iterates in keyset-pagination order on ``incidents.id`` and commits per batch, so
already-written rows are durable. The scan cursor is in-memory only: a crash
restarts the scan from the start (or from ``--start-after``). That is safe and
cheap thanks to ON CONFLICT — re-encountered incidents are no-op upserts, never
duplicates. Each batch prints the last id processed so a very large run can be
resumed with ``--start-after <id>``.

Run inside the backend container (isoc_api installed, DB reachable):

    python scripts/backfill_entities_from_db.py --dry-run
    python scripts/backfill_entities_from_db.py
    python scripts/backfill_entities_from_db.py --customer acme --limit 500
    python scripts/backfill_entities_from_db.py --start-after <last-id-from-a-prior-run>
"""

from __future__ import annotations

import argparse
import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from isoc_api.adapters import entity_store
from isoc_api.db.models import Incident
from isoc_api.db.session import AsyncSessionLocal
from isoc_api.logging_config import get_logger
from isoc_api.pipeline import ocsf

logger = get_logger("isoc.backfill.entities")


async def _run(args: argparse.Namespace) -> None:
    now = datetime.now(timezone.utc)
    last_id: uuid.UUID | None = args.start_after
    scanned = candidates = linked = failed = 0
    done = False

    async with AsyncSessionLocal() as session:
        while not done:
            # Clamp the page to the remaining --limit budget so the final partial
            # batch doesn't over-fetch a full page it won't process.
            page = args.batch_size
            if args.limit is not None:
                page = min(args.batch_size, args.limit - scanned)
                if page <= 0:
                    break
            # Keyset pagination on the incident id — stable, index-friendly, and
            # unaffected by rows changing under us mid-run.
            stmt = (
                select(Incident)
                .where(Incident.normalized.isnot(None))
                .order_by(Incident.id)
                .limit(page)
            )
            if args.customer is not None:
                stmt = stmt.where(Incident.customer == args.customer)
            if last_id is not None:
                stmt = stmt.where(Incident.id > last_id)

            incidents = (await session.execute(stmt)).scalars().all()
            if not incidents:
                break

            for inc in incidents:
                if args.limit is not None and scanned >= args.limit:
                    done = True  # cap reached — flush this batch, then stop
                    break
                last_id = inc.id
                scanned += 1

                ents = ocsf.to_entities(inc.normalized or {}, inc.customer)
                for e in ents:
                    candidates += 1
                    if args.dry_run:
                        continue
                    try:
                        # SAVEPOINT per candidate (mirrors _step_entities): one bad
                        # row rolls back only its savepoint, never the batch txn.
                        async with session.begin_nested():
                            entity_id = await entity_store.upsert_entity(session, e, now)
                            if entity_id is None:
                                continue
                            await entity_store.link_incident_entity(
                                session, inc.id, entity_id, e["role"] or "observable"
                            )
                        linked += 1
                    except Exception as ex:  # noqa: BLE001 — one bad candidate, keep going
                        failed += 1
                        logger.warning(
                            "backfill.entity_resolve_failed",
                            incident_id=str(inc.id),
                            entity_type=e.get("entity_type"),
                            error=str(ex),
                        )

                if scanned % args.log_every == 0:
                    print(
                        f"  … scanned={scanned} candidates={candidates} "
                        f"linked={linked} failed={failed} last_id={last_id}"
                    )

            # Commit per batch so progress is durable and the transaction isn't
            # held open across the whole back catalogue. (No-op writes on dry-run.)
            if args.dry_run:
                await session.rollback()
            else:
                await session.commit()

    verb = "would link" if args.dry_run else "linked"
    print(
        f"[entities] scanned={scanned} candidates={candidates} "
        f"{verb}={linked} failed={failed} last_id={last_id}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dry-run", action="store_true", help="resolve + count only; write/commit nothing"
    )
    ap.add_argument("--customer", default=None, help="restrict to one customer id")
    ap.add_argument("--limit", type=int, default=None, help="cap the number of incidents scanned")
    ap.add_argument(
        "--batch-size",
        type=int,
        default=200,
        help="incidents per keyset page / commit (default 200)",
    )
    ap.add_argument(
        "--log-every", type=int, default=100, help="print progress every N incidents (default 100)"
    )
    ap.add_argument(
        "--start-after",
        type=uuid.UUID,
        default=None,
        help="resume: skip incidents with id <= this (copy last_id from a prior run)",
    )
    args = ap.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
