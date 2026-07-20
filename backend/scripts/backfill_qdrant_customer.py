"""One-time backfill: canonicalize the ``customer`` payload on existing Qdrant
points (fix #4 — see docs/PLAN-rag-retrieval-consistency.md).

Similar/exact retrieval filters on an exact, case-sensitive ``MatchValue`` over
the stored ``customer`` field. Once the pipeline canonicalizes customer on both
write and query, existing points stored with a different casing would stop
matching until aligned. This script rewrites their ``customer`` to the canonical
form. Payload-only (``set_payload``) — NO re-embedding, vectors untouched.

Idempotent: points already canonical (or with an empty customer) are skipped, so
re-running is safe.

Run inside the backend container (isoc_api installed, QDRANT_URL set):

    python scripts/backfill_qdrant_customer.py --dry-run     # report only
    python scripts/backfill_qdrant_customer.py               # apply
    python scripts/backfill_qdrant_customer.py --collections alerts_v2

Rollout note: run this together with the deploy that canonicalizes queries. In
the brief window before it completes, affected customers' similar/exact/n_way may
under-return (safe direction — the case just escalates to the LLM, never a wrong
auto-close).
"""

from __future__ import annotations

import argparse
import os

from qdrant_client import QdrantClient

from isoc_api.adapters.store_adapter import canonical_customer

QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333")
DEFAULT_COLLECTIONS = ("alerts_v2", "iocs_v2")
_PAGE = 256


def backfill_collection(client: QdrantClient, collection: str, dry_run: bool) -> tuple[int, int]:
    scanned = 0
    updated = 0
    offset = None
    while True:
        points, offset = client.scroll(
            collection_name=collection,
            limit=_PAGE,
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )
        for p in points:
            scanned += 1
            current = (p.payload or {}).get("customer")
            canon = canonical_customer(current)
            # Leave empty customers (no filter uses them) and already-canonical rows.
            if canon is None or current == canon:
                continue
            updated += 1
            if not dry_run:
                client.set_payload(
                    collection_name=collection,
                    payload={"customer": canon},
                    points=[p.id],
                )
        if offset is None:
            break
    return scanned, updated


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report counts, write nothing")
    ap.add_argument(
        "--collections",
        nargs="*",
        default=list(DEFAULT_COLLECTIONS),
        help=f"collections to process (default: {' '.join(DEFAULT_COLLECTIONS)})",
    )
    args = ap.parse_args()

    client = QdrantClient(url=QDRANT_URL)
    for collection in args.collections:
        try:
            scanned, updated = backfill_collection(client, collection, args.dry_run)
        except Exception as e:  # missing collection etc. — report and continue
            print(f"[{collection}] SKIPPED — {e}")
            continue
        verb = "would update" if args.dry_run else "updated"
        print(f"[{collection}] scanned={scanned} {verb}={updated}")


if __name__ == "__main__":
    main()
