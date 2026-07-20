"""
Migration: nomic-embed-text (768d) → BGE-M3 (1024d)

What it does:
  1. Scrolls all points from alerts, iocs, knowledge_base collections
  2. Creates new *_v2 collections (alerts_v2, iocs_v2, knowledge_base_v2)
     with 1024-dim dense vectors
  3. Re-embeds embed_text from each point's payload using BGE-M3
  4. Upserts all points to *_v2 collections (sparse vectors recomputed too)
  5. Reports counts for verification

The original collections (alerts, iocs, knowledge_base) are NOT deleted.
Run in parallel / validation mode first, then update COLLECTION constant in
store.py to switch over cleanly.

Migration plan:
  Step 1: python3 migrate_to_bge_m3.py            ← this script
  Step 2: Validate alerts_v2 search quality for ~1 week
  Step 3: In store.py, change:
              COLLECTION     = "alerts_v2"
              IOC_COLLECTION = "iocs_v2"
              KB_COLLECTION  = "knowledge_base_v2"
          and update embedder import to bge_embedder
  Step 4: Decommission v1 collections when satisfied

Run:
  cd /Users/huseyineksi/claude-cyber-space/alert-memory-mcp
  python3 migrate_to_bge_m3.py
"""

import sys
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams,
    SparseVectorParams, SparseIndexParams,
    PointStruct,
)

from bge_embedder import embed as bge_embed, EMBED_DIM as BGE_DIM
from sparse_embedder import sparse_embed

QDRANT_URL = "http://localhost:6333"

V1_COLLECTIONS = ("alerts",        "iocs",        "knowledge_base")
V2_COLLECTIONS = ("alerts_v2",     "iocs_v2",     "knowledge_base_v2")


def create_v2_collection(client: QdrantClient, name: str):
    existing = [c.name for c in client.get_collections().collections]
    if name in existing:
        print(f"[migrate] '{name}' already exists — skipping creation")
        return
    client.create_collection(
        collection_name=name,
        vectors_config={
            "dense": VectorParams(size=BGE_DIM, distance=Distance.COSINE),
        },
        sparse_vectors_config={
            "sparse": SparseVectorParams(
                index=SparseIndexParams(on_disk=False)
            ),
        },
    )
    print(f"[migrate] Created '{name}' (BGE-M3 {BGE_DIM}d + sparse)")


def migrate_collection(client: QdrantClient, src: str, dst: str):
    existing = [c.name for c in client.get_collections().collections]
    if src not in existing:
        print(f"[migrate] Source '{src}' not found — skipping")
        return

    info = client.get_collection(src)
    total_src = info.points_count
    print(f"\n[migrate] {src} → {dst} ({total_src} points)")

    # Scroll all points from source
    points = []
    offset = None
    while True:
        batch, offset = client.scroll(
            collection_name=src,
            limit=100,
            offset=offset,
            with_payload=True,
            with_vectors=False,   # don't need old vectors — re-embedding
        )
        points.extend(batch)
        if offset is None:
            break

    print(f"[migrate]   Fetched {len(points)} points")

    migrated = 0
    skipped  = 0
    errors   = 0
    batch_size = 20
    new_points = []

    for p in points:
        payload = p.payload or {}

        # Get embed_text from payload — this was stored at index time
        embed_text = payload.get("embed_text", "")
        if not embed_text:
            # Fallback: for IOC collection, reconstruct from payload fields
            ioc_type  = payload.get("ioc_type", "")
            ioc_value = payload.get("ioc_value", "")
            rule_name = payload.get("rule_name", "unknown rule")
            customer  = payload.get("customer", "")
            if ioc_type and ioc_value:
                embed_text = f"{ioc_type}: {ioc_value} seen in {rule_name} customer={customer}"
            # KB entries have a content field
            elif payload.get("content"):
                parts = []
                if payload.get("title"):
                    parts.append(f"Title: {payload['title']}")
                if payload.get("rule_name"):
                    parts.append(f"Rule: {payload['rule_name']}")
                if payload.get("tags"):
                    parts.append(f"Tags: {' '.join(payload['tags'])}")
                parts.append(payload["content"])
                embed_text = "\n".join(parts)

        if not embed_text:
            print(f"[migrate]   SKIP {p.id} — no embed_text or reconstructable text")
            skipped += 1
            continue

        try:
            dense_vec  = bge_embed(embed_text)
            sparse_vec = sparse_embed(embed_text)

            new_points.append(PointStruct(
                id=p.id,
                vector={"dense": dense_vec, "sparse": sparse_vec},
                payload=payload,
            ))
            migrated += 1

        except Exception as e:
            print(f"[migrate]   ERROR {p.id}: {e}")
            errors += 1
            continue

        if len(new_points) >= batch_size:
            client.upsert(collection_name=dst, points=new_points)
            print(f"[migrate]   Upserted {migrated} / {total_src}...")
            new_points = []

    if new_points:
        client.upsert(collection_name=dst, points=new_points)

    print(f"[migrate]   Done: {migrated} migrated, {skipped} skipped, {errors} errors")


def validate(client: QdrantClient):
    """Quick sanity check: query count + spot embedding."""
    print("\n[validate] Post-migration counts:")
    for v1, v2 in zip(V1_COLLECTIONS, V2_COLLECTIONS):
        existing = [c.name for c in client.get_collections().collections]
        c1 = client.get_collection(v1).points_count if v1 in existing else 0
        c2 = client.get_collection(v2).points_count if v2 in existing else 0
        match = "✓" if c1 == c2 else "✗ MISMATCH"
        print(f"  {v1}: {c1}  →  {v2}: {c2}  {match}")

    # Spot check: single semantic query against alerts_v2
    from bge_embedder import embed as bge_embed
    test_vec = bge_embed("brute force failed login Windows")
    results = client.query_points(
        collection_name="alerts_v2",
        query=test_vec,
        using="dense",
        limit=3,
        with_payload=True,
    ).points
    print(f"\n[validate] Spot query (brute force failed login) → top-3 from alerts_v2:")
    for r in results:
        p = r.payload or {}
        print(f"  score={r.score:.4f} rule={p.get('rule_name','?')[:60]} verdict={p.get('verdict','?')}")


def main():
    client = QdrantClient(url=QDRANT_URL)

    print("=" * 60)
    print("BGE-M3 Migration (nomic 768d → bge-m3 1024d)")
    print("=" * 60)

    # Create v2 collections
    for name in V2_COLLECTIONS:
        create_v2_collection(client, name)

    # Migrate each collection
    for src, dst in zip(V1_COLLECTIONS, V2_COLLECTIONS):
        migrate_collection(client, src, dst)

    # Validate
    validate(client)

    print("\n[migrate] Migration complete.")
    print("[migrate] Next steps:")
    print("  1. Review the spot-query results above for quality")
    print("  2. When satisfied, update store.py:")
    print("       COLLECTION     = 'alerts_v2'")
    print("       IOC_COLLECTION = 'iocs_v2'")
    print("       KB_COLLECTION  = 'knowledge_base_v2'")
    print("     and change embedder import to bge_embedder")
    print("  3. Decommission v1 collections when stable")


if __name__ == "__main__":
    main()
