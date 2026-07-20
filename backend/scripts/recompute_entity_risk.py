"""Recompute ``entities.risk_score`` from confirmed-verdict history (Phase 3).

Risk is normally refreshed at the verdict gate (``_commit_verdict``), so it only
moves for entities touched by NEW verdicts. This script recomputes the whole
back catalogue — run once after deploying entity risk (and any time the weights
in ``pipeline/entity_risk.py`` are retuned).

Deterministic + idempotent: risk derives entirely from existing incident
verdicts/scores, so re-running is always safe and converges to the same values.

Run inside the backend container:

    python scripts/recompute_entity_risk.py
    python scripts/recompute_entity_risk.py --customer acme --batch-size 500
"""

from __future__ import annotations

import argparse
import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from isoc_api.adapters import entity_store
from isoc_api.db.models import Entity
from isoc_api.db.session import AsyncSessionLocal
from isoc_api.logging_config import get_logger

logger = get_logger("isoc.recompute.entity_risk")


async def _run(args: argparse.Namespace) -> None:
    now = datetime.now(timezone.utc)
    last_id: uuid.UUID | None = None
    scanned = 0

    async with AsyncSessionLocal() as session:
        while True:
            page = args.batch_size
            if args.limit is not None:
                page = min(page, args.limit - scanned)
                if page <= 0:
                    break
            stmt = select(Entity.id).order_by(Entity.id).limit(page)
            if args.customer is not None:
                stmt = stmt.where(Entity.customer == args.customer)
            if last_id is not None:
                stmt = stmt.where(Entity.id > last_id)
            ids = list((await session.execute(stmt)).scalars().all())
            if not ids:
                break

            await entity_store.recompute_entity_risk(session, ids, now=now)
            await session.commit()

            scanned += len(ids)
            last_id = ids[-1]
            if scanned % args.log_every < len(ids):
                print(f"  … recomputed={scanned} last_id={last_id}")

    print(f"[entity-risk] recomputed={scanned} customer={args.customer or 'all'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--customer", default=None, help="restrict to one canonical customer slug")
    ap.add_argument("--limit", type=int, default=None, help="cap the number of entities")
    ap.add_argument("--batch-size", type=int, default=500, help="entities per batch (default 500)")
    ap.add_argument("--log-every", type=int, default=2000, help="progress cadence (default 2000)")
    args = ap.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
