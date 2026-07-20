"""
One-time migration: dense-only collections → hybrid (dense + sparse) collections.

What it does:
  1. Scrolls all existing points from 'alerts' and 'iocs'
  2. Deletes and recreates both collections with named dense + sparse vector config
  3. Re-upserts all points: reuses existing dense vectors, computes new sparse vectors

Run once:
  cd /Users/huseyineksi/claude_s1_2_mcp_threat/alert-memory-mcp
  python3 migrate_to_hybrid.py
"""

import sys
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams,
    SparseVectorParams, SparseIndexParams,
    PointStruct,
)

from sparse_embedder import sparse_embed

QDRANT_URL     = "http://localhost:6333"
COLLECTION     = "alerts"
IOC_COLLECTION = "iocs"


def migrate_collection(client: QdrantClient, name: str):
    print(f"\n[migrate] Processing collection: {name}")

    # 1. Check if already migrated
    info = client.get_collection(name)
    if info.config.params.sparse_vectors is not None:
        print(f"[migrate] '{name}' already has sparse vectors — skipping.")
        return

    # 2. Scroll all existing points (payload + dense vector)
    points = []
    offset = None
    while True:
        batch, offset = client.scroll(
            collection_name=name,
            limit=100,
            offset=offset,
            with_payload=True,
            with_vectors=True,
        )
        points.extend(batch)
        if offset is None:
            break

    print(f"[migrate] Fetched {len(points)} points from '{name}'")

    # 3. Delete and recreate with hybrid config
    client.delete_collection(name)
    client.create_collection(
        collection_name=name,
        vectors_config={
            "dense": VectorParams(size=768, distance=Distance.COSINE),
        },
        sparse_vectors_config={
            "sparse": SparseVectorParams(
                index=SparseIndexParams(on_disk=False)
            ),
        },
    )
    print(f"[migrate] Recreated '{name}' with hybrid config")

    # 4. Re-upsert: reuse existing dense vector, compute sparse from embed_text
    migrated = 0
    skipped  = 0
    batch_size = 50

    new_points = []
    for p in points:
        payload = p.payload or {}

        # Get the existing dense vector
        raw_vec = p.vector
        if isinstance(raw_vec, dict):
            dense_vec = raw_vec.get("dense") or raw_vec.get("")
        elif isinstance(raw_vec, list):
            dense_vec = raw_vec
        else:
            dense_vec = None

        if not dense_vec:
            print(f"[migrate]   SKIP {p.id} — no dense vector found")
            skipped += 1
            continue

        # Build sparse from embed_text stored in payload
        embed_text = payload.get("embed_text", "")
        sparse_vec = sparse_embed(embed_text) if embed_text else sparse_embed(
            " ".join(str(v) for v in payload.values() if isinstance(v, str))
        )

        new_points.append(PointStruct(
            id=p.id,
            vector={"dense": dense_vec, "sparse": sparse_vec},
            payload=payload,
        ))
        migrated += 1

        if len(new_points) >= batch_size:
            client.upsert(collection_name=name, points=new_points)
            print(f"[migrate]   Upserted batch of {len(new_points)}")
            new_points = []

    if new_points:
        client.upsert(collection_name=name, points=new_points)
        print(f"[migrate]   Upserted final batch of {len(new_points)}")

    print(f"[migrate] Done: {migrated} migrated, {skipped} skipped")


def main():
    client = QdrantClient(url=QDRANT_URL)

    existing = [c.name for c in client.get_collections().collections]
    for col in (COLLECTION, IOC_COLLECTION):
        if col not in existing:
            print(f"[migrate] Collection '{col}' not found — skipping")
        else:
            migrate_collection(client, col)

    print("\n[migrate] Migration complete. Run store.stats() to verify.")


if __name__ == "__main__":
    main()
