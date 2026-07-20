"""One-time backfill: recover the missing ``customer`` on existing Qdrant points
from Postgres (fix #4 follow-up — see docs/PLAN-rag-retrieval-consistency.md).

Older points in ``alerts_v2`` were indexed before the pipeline threaded the
incident's customer into the write, so they carry ``customer: null`` and the
tenant-scoped similar/exact filter never matches them. Each point id equals the
originating incident's ``qdrant_alert_id``, so we can look the tenant up in the
DB and write it back (canonicalized). Payload-only (``set_payload``) — NO
re-embedding, vectors untouched. Idempotent.

Run inside the backend container (isoc_api installed, DB + QDRANT_URL reachable):

    python scripts/backfill_qdrant_customer_from_db.py --dry-run
    python scripts/backfill_qdrant_customer_from_db.py
"""

from __future__ import annotations

import argparse
import asyncio
import os

from qdrant_client import QdrantClient
from sqlalchemy import text

from isoc_api.adapters.store_adapter import canonical_customer
from isoc_api.db.session import AsyncSessionLocal

QDRANT_URL = os.environ.get("QDRANT_URL", "http://qdrant:6333")
COLLECTION = "alerts_v2"


async def _load_id_to_customer() -> dict[str, str]:
    """Map Qdrant point id (= incident.qdrant_alert_id) → incident.customer."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT qdrant_alert_id::text AS qid, customer FROM incidents "
                    "WHERE qdrant_alert_id IS NOT NULL AND coalesce(customer, '') <> ''"
                )
            )
        ).all()
    return {r.qid: r.customer for r in rows}


def _backfill(
    client: QdrantClient, id2customer: dict[str, str], dry_run: bool
) -> tuple[int, int, int]:
    scanned = matched = updated = 0
    offset = None
    while True:
        points, offset = client.scroll(
            collection_name=COLLECTION,
            limit=256,
            offset=offset,
            with_payload=["customer"],
            with_vectors=False,
        )
        for p in points:
            scanned += 1
            db_customer = id2customer.get(str(p.id))
            if not db_customer:
                continue
            matched += 1
            canon = canonical_customer(db_customer)
            current = (p.payload or {}).get("customer")
            if canon is None or current == canon:
                continue
            updated += 1
            if not dry_run:
                client.set_payload(
                    collection_name=COLLECTION, payload={"customer": canon}, points=[p.id]
                )
        if offset is None:
            break
    return scanned, matched, updated


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report counts, write nothing")
    args = ap.parse_args()

    id2customer = asyncio.run(_load_id_to_customer())
    client = QdrantClient(url=QDRANT_URL)
    scanned, matched, updated = _backfill(client, id2customer, args.dry_run)
    verb = "would update" if args.dry_run else "updated"
    print(
        f"[{COLLECTION}] db_rows={len(id2customer)} scanned={scanned} "
        f"matched_in_db={matched} {verb}={updated}"
    )


if __name__ == "__main__":
    main()
