"""Rebuild ``alerts_v2`` from CLOSED, analyst-verdicted incidents in Postgres.

The active Qdrant lost most previously-indexed verdicts (a past ``qdrant_data``
volume reset), so the vector memory is nearly empty. Postgres still holds the
normalized alert + verdict + customer for every closed incident, so we re-embed
and upsert them through the same path the gate uses (``store_adapter.index_alert``)
— which now stores the tenant (#4) and the richer embed_text (#3).

Each point is keyed by the incident id, so re-running is idempotent, and orphan
points left by old random-id writes are pruned afterward. Requires Ollama/bge-m3
reachable (one embed per alert + its IOCs).

Run inside the backend container:

    python scripts/reindex_alerts_from_db.py --dry-run
    python scripts/reindex_alerts_from_db.py
"""

from __future__ import annotations

import argparse
import asyncio
import os

from qdrant_client import QdrantClient
from sqlalchemy import text

from isoc_api.adapters import store_adapter
from isoc_api.db.session import AsyncSessionLocal

QDRANT_URL = os.environ.get("QDRANT_URL", "http://qdrant:6333")
COLLECTION = "alerts_v2"
# Real analyst dispositions only — 'pending' rows (awaiting sign-off) are not memory.
_VERDICTS = ("FP", "TP", "benign")


async def _load_incidents() -> list:
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT id::text AS id, customer, verdict::text AS verdict, "
                    "coalesce(verdict_reason, '') AS reason, normalized "
                    "FROM incidents "
                    "WHERE status = 'closed' AND normalized IS NOT NULL "
                    "AND verdict::text = ANY(:verdicts)"
                ),
                {"verdicts": list(_VERDICTS)},
            )
        ).all()
    return list(rows)


async def _reindex(rows: list, dry_run: bool) -> tuple[int, int, set[str]]:
    indexed = failed = 0
    keep_ids: set[str] = set()
    for r in rows:
        keep_ids.add(r.id)  # point id == incident id (see below)
        if dry_run:
            continue
        try:
            await store_adapter.index_alert(
                # alert_id = incident id → stable, idempotent point id.
                normalized={**(r.normalized or {}), "alert_id": r.id},
                verdict=str(r.verdict),
                verdict_reason=str(r.reason)[:4000],
                customer=r.customer,
                human_verified=True,
                feedback_source="analyst_decision",
            )
            indexed += 1
        except Exception as e:
            failed += 1
            print(f"  ! {r.id} ({r.customer}) failed: {e}")
    return indexed, failed, keep_ids


def _prune_orphans(client: QdrantClient, keep_ids: set[str], dry_run: bool) -> int:
    removed = 0
    offset = None
    while True:
        points, offset = client.scroll(
            collection_name=COLLECTION, limit=256, offset=offset, with_vectors=False
        )
        stale = [p.id for p in points if str(p.id) not in keep_ids]
        removed += len(stale)
        if stale and not dry_run:
            client.delete(collection_name=COLLECTION, points_selector=stale)
        if offset is None:
            break
    return removed


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report counts, embed/write nothing")
    args = ap.parse_args()

    rows = asyncio.run(_load_incidents())
    indexed, failed, keep_ids = asyncio.run(_reindex(rows, args.dry_run))
    client = QdrantClient(url=QDRANT_URL)
    removed = _prune_orphans(client, keep_ids, args.dry_run)
    tail = "to_remove" if args.dry_run else "removed"
    print(
        f"[{COLLECTION}] candidates={len(rows)} indexed={indexed} failed={failed} "
        f"orphans_{tail}={removed}"
    )


if __name__ == "__main__":
    main()
