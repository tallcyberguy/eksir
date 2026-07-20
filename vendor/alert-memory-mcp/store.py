"""
Qdrant vector store for normalized alerts — hybrid dense + sparse search.

Collections use named vectors:
  "dense"  — BGE-M3 1024-dim, cosine similarity  (Tier-3A upgrade from nomic 768d)
  "sparse" — BM25-style TF×IDF sparse vectors, dot product

Query strategy: Prefetch from both indexes, fuse with RRF (Reciprocal Rank Fusion).

Collections:
  alerts_v2           — analyst-triaged alert cases with verdicts  (BGE-M3)
  iocs_v2             — IP / hash indicators linked to alerts       (BGE-M3)
  knowledge_base_v2   — runbooks, allowlists, asset inventory       (BGE-M3)

Legacy collections (alerts, iocs, knowledge_base) — nomic 768d — kept for fallback.
To roll back: change COLLECTION / IOC_COLLECTION / KB_COLLECTION to v1 names
and swap embedder import back to `from embedder import embed, EMBED_DIM`.

Qdrant must be running:
  docker run -d --name qdrant -p 6333:6333 \
    -v $(pwd)/qdrant_data:/qdrant/storage qdrant/qdrant
"""

import logging
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams,
    SparseVector, SparseVectorParams, SparseIndexParams,
    PointStruct, Filter, FieldCondition, MatchValue,
    Prefetch, FusionQuery, Fusion, PointIdsList,
)
from typing import Optional
import uuid

from bge_embedder import embed, EMBED_DIM   # Tier-3A: BGE-M3 1024d
from sparse_embedder import sparse_embed
from normalizer import NormalizedAlert, infer_category, severity_label

log = logging.getLogger("soc.store")

import os as _os
# QDRANT_URL is overridable via env so containerised consumers (ISOC) can point
# at host.docker.internal:6333 while local CLI use of this script defaults
# to localhost.
QDRANT_URL     = _os.environ.get("QDRANT_URL", "http://localhost:6333")
COLLECTION     = "alerts_v2"        # BGE-M3 1024d (migrated from alerts)
IOC_COLLECTION = "iocs_v2"          # BGE-M3 1024d (migrated from iocs)
KB_COLLECTION  = "knowledge_base_v2"  # BGE-M3 1024d

# Prefetch multiplier for RRF — fetch N× candidates from each index before fusing
_PREFETCH_FACTOR = 4


def _cosine_sim(a, b) -> float | None:
    """True cosine similarity of two dense vectors, in [-1, 1] (≈[0, 1] for
    bge-m3). Used to surface an HONEST similarity score for display, separate
    from the RRF fusion score which only drives hybrid recall/ordering."""
    import math

    if not a or not b or len(a) != len(b):
        return None
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return None
    return dot / (math.sqrt(na) * math.sqrt(nb))


class AlertStore:

    def __init__(self):
        self.client = QdrantClient(url=QDRANT_URL)
        self._ensure_collections()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _ensure_collections(self):
        existing = [c.name for c in self.client.get_collections().collections]

        for name in (COLLECTION, IOC_COLLECTION, KB_COLLECTION):
            if name not in existing:
                self._create_hybrid_collection(name)
                print(f"[store] Created hybrid collection: {name}")
            else:
                # Verify the collection already has sparse vectors configured.
                # If not (legacy dense-only), warn — run migrate_to_hybrid.py.
                info = self.client.get_collection(name)
                if info.config.params.sparse_vectors is None:
                    print(
                        f"[store] WARNING: collection '{name}' is legacy dense-only. "
                        f"Run migrate_to_hybrid.py to upgrade to hybrid search."
                    )

    def _create_hybrid_collection(self, name: str):
        self.client.create_collection(
            collection_name=name,
            vectors_config={
                "dense": VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
            },
            sparse_vectors_config={
                "sparse": SparseVectorParams(
                    index=SparseIndexParams(on_disk=False)
                ),
            },
        )

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def index_alert(self, alert: NormalizedAlert) -> str:
        """
        Embed alert.embed_text (dense + sparse) and store in Qdrant.
        Returns alert_id.
        """
        dense  = embed(alert.embed_text)
        sparse = sparse_embed(alert.embed_text)
        payload = alert.to_qdrant_payload()

        self.client.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(
                id=_str_to_uuid(alert.alert_id),
                vector={"dense": dense, "sparse": sparse},
                payload=payload,
            )]
        )

        self._index_iocs(alert)

        # Tier-3B: metric logging — track indexing
        log.info(
            "alert indexed",
            extra={
                "alert_id":        alert.alert_id,
                "customer":        alert.customer,
                "rule_name":       alert.rule_name,
                "verdict":         alert.verdict,
                "human_verified":  alert.human_verified,
                "feedback_source": alert.feedback_source,
            },
        )

        return alert.alert_id

    def _index_iocs(self, alert: NormalizedAlert):
        """Index IP / hash indicators linked to this alert."""
        indicators = []

        if alert.src_ip and not _is_private(alert.src_ip):
            indicators.append(("ip", alert.src_ip))
        if alert.file_hash_sha256:
            indicators.append(("sha256", alert.file_hash_sha256))
        if alert.file_hash_sha1:
            indicators.append(("sha1", alert.file_hash_sha1))
        domain = _domain_from_url(alert.url)
        if domain:
            indicators.append(("domain", domain))

        for ioc_type, ioc_value in indicators:
            ioc_text = (
                f"{ioc_type}: {ioc_value} "
                f"seen in {alert.rule_name or 'unknown rule'} "
                f"customer={alert.customer}"
            )
            dense  = embed(ioc_text)
            sparse = sparse_embed(ioc_text)

            self.client.upsert(
                collection_name=IOC_COLLECTION,
                points=[PointStruct(
                    id=_str_to_uuid(str(uuid.uuid4())),
                    vector={"dense": dense, "sparse": sparse},
                    payload={
                        "ioc_type":  ioc_type,
                        "ioc_value": ioc_value,
                        "alert_id":  alert.alert_id,
                        "customer":  alert.customer,
                        "rule_name": alert.rule_name,
                        "timestamp": alert.timestamp,
                        "verdict":   alert.verdict,
                    }
                )]
            )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_similar(
        self,
        alert: NormalizedAlert,
        customer: Optional[str] = None,
        top_k: int = 5,
        min_score: float = 0.0,
    ) -> list[dict]:
        """
        Find similar past alerts using hybrid dense + sparse search with RRF fusion.

        Dense leg:  semantic similarity (catches same-behavior, different-wording)
        Sparse leg: token overlap (catches exact IPs, CVE IDs, rule name keywords)
        RRF:        merges both ranked lists without requiring score normalization

        Query embed_text is always rebuilt from structured fields so the query
        representation matches the format used at index time.
        """
        # Rebuild embed_text from structured fields for query/index consistency.
        # Overrides any manually set embed_text string.
        query_text = alert.build_embed_text() or alert.embed_text
        dense_vec  = embed(query_text)
        sparse_vec = sparse_embed(query_text)

        query_filter = None
        if customer:
            query_filter = Filter(
                must=[FieldCondition(
                    key="customer",
                    match=MatchValue(value=customer),
                )]
            )

        prefetch_limit = top_k * _PREFETCH_FACTOR

        results = self.client.query_points(
            collection_name=COLLECTION,
            prefetch=[
                Prefetch(
                    query=sparse_vec,
                    using="sparse",
                    limit=prefetch_limit,
                    filter=query_filter,
                ),
                Prefetch(
                    query=dense_vec,
                    using="dense",
                    limit=prefetch_limit,
                    filter=query_filter,
                ),
            ],
            query=FusionQuery(fusion=Fusion.RRF),
            limit=top_k,
            with_payload=True,
            with_vectors=["dense"],   # need the stored dense vec to compute TRUE cosine
        ).points

        out: list[dict] = []
        for r in results:
            if r.score < min_score:
                continue
            # r.score is the RRF fusion score — good for hybrid recall/ordering
            # but NOT a cosine and must never be displayed as a "% match".
            # Compute the TRUE dense cosine from the stored vector for honest display.
            stored_dense = r.vector.get("dense") if isinstance(r.vector, dict) else None
            cosine = _cosine_sim(dense_vec, stored_dense)
            out.append(
                {
                    "score":          round(r.score, 4),        # RRF fusion (ordering only)
                    "cosine":         round(cosine, 4) if cosine is not None else None,  # [0,1] display
                    "alert_id":       r.payload.get("alert_id"),
                    "rule_name":      r.payload.get("rule_name"),
                    "src_ip":         r.payload.get("src_ip"),
                    "customer":       r.payload.get("customer"),
                    "verdict":        r.payload.get("verdict"),
                    "verdict_reason": r.payload.get("verdict_reason"),
                    "human_verified": r.payload.get("human_verified"),
                    "timestamp":      r.payload.get("timestamp"),
                    "threat_category": r.payload.get("threat_category"),
                }
            )
        return out

    # ------------------------------------------------------------------
    # Short-circuit helpers (Tier-1 upgrade)
    # ------------------------------------------------------------------

    def find_exact_match(
        self,
        alert: NormalizedAlert,
        customer: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Exact-match short-circuit: if the single top result is a previously
        analyst-confirmed verdict (`human_verified=True`) for the same customer
        AND same rule_name, return it directly so the skill can present the
        prior verdict instead of re-running the full analysis.

        Returns None if no qualifying match found.

        Gating rules:
          - human_verified must be True (only analyst-confirmed seeds qualify)
          - same customer
          - same rule_name (exact string match — different rule names should
            not collapse even if embed text is similar)
          - verdict ∈ {FP, benign} only (TP cases always re-investigate)
        """
        hits = self.search_similar(alert, customer=customer, top_k=1)
        if not hits:
            return None

        top = hits[0]
        payload = self.client.retrieve(
            collection_name=COLLECTION,
            ids=[_str_to_uuid(top["alert_id"])],
            with_payload=True,
            with_vectors=False,
        )
        if not payload:
            return None
        full = payload[0].payload

        if not full.get("human_verified"):
            return None
        if full.get("rule_name") != alert.rule_name:
            return None
        if full.get("verdict") not in ("FP", "benign"):
            return None

        match = {
            "alert_id":       full.get("alert_id"),
            "rule_name":      full.get("rule_name"),
            "verdict":        full.get("verdict"),
            "verdict_reason": full.get("verdict_reason"),
            "customer":       full.get("customer"),
            "timestamp":      full.get("timestamp"),
            "score":          top["score"],
        }

        # Tier-3B: metric logging — track exact-match short-circuit firing
        log.info(
            "exact_match short-circuit fired",
            extra={
                "customer":        customer,
                "rule_name":       alert.rule_name,
                "prior_alert_id":  match["alert_id"],
                "prior_verdict":   match["verdict"],
                "score":           match["score"],
            },
        )

        return match

    def n_way_agreement(
        self,
        alert: NormalizedAlert,
        customer: Optional[str] = None,
        top_k: int = 5,
        min_agreement: int = 3,
    ) -> Optional[dict]:
        """
        N-way agreement short-circuit: if at least `min_agreement` of the
        top-k similar cases share the same verdict, return that verdict
        as a high-confidence suggestion.

        Returns None if no clear majority emerges.
        """
        hits = self.search_similar(alert, customer=customer, top_k=top_k)
        if len(hits) < min_agreement:
            return None

        verdict_counts: dict[str, int] = {}
        for h in hits:
            v = h.get("verdict")
            if v:
                verdict_counts[v] = verdict_counts.get(v, 0) + 1

        if not verdict_counts:
            return None

        winner, count = max(verdict_counts.items(), key=lambda kv: kv[1])
        if count < min_agreement:
            return None

        result = {
            "verdict":   winner,
            "agreement": f"{count}/{len(hits)}",
            "matches":   [h for h in hits if h.get("verdict") == winner],
        }

        # Tier-3B: metric logging — track agreement signal firing
        log.info(
            "n_way_agreement fired",
            extra={
                "customer":        customer,
                "rule_name":       alert.rule_name,
                "agreed_verdict":  winner,
                "agreement_ratio": f"{count}/{len(hits)}",
                "top_k":           top_k,
            },
        )

        return result

    # ------------------------------------------------------------------
    # Knowledge Base (Tier-2B)
    # ------------------------------------------------------------------

    def index_kb_entry(self, entry: dict) -> str:
        """
        Index a knowledge base entry (runbook, allowlist, asset inventory,
        incident report) into the knowledge_base collection.

        Required fields:
            type     — "runbook" | "allowlist" | "asset_inventory" | "incident_report"
            title    — short descriptive title
            content  — full text to embed and search

        Optional fields:
            customer  — customer scope (None = global, applies to all)
            rule_name — specific rule this entry relates to (None = all rules)
            tags      — list of tags e.g. ["phishing", "DDEI", "email"]

        Returns kb_id (UUID string).
        """
        kb_id = entry.get("kb_id") or str(uuid.uuid4())
        entry["kb_id"] = kb_id

        # Build embed text: title + content (tags appended for sparse matching)
        embed_text_parts = []
        if entry.get("title"):
            embed_text_parts.append(f"Title: {entry['title']}")
        if entry.get("rule_name"):
            embed_text_parts.append(f"Rule: {entry['rule_name']}")
        if entry.get("tags"):
            embed_text_parts.append(f"Tags: {' '.join(entry['tags'])}")
        embed_text_parts.append(entry.get("content", ""))
        embed_text = "\n".join(embed_text_parts)

        dense_vec  = embed(embed_text)
        sparse_vec = sparse_embed(embed_text)

        self.client.upsert(
            collection_name=KB_COLLECTION,
            points=[PointStruct(
                id=_str_to_uuid(kb_id),
                vector={"dense": dense_vec, "sparse": sparse_vec},
                payload=entry,
            )]
        )

        log.info("KB entry indexed", extra={"kb_id": kb_id, "type": entry.get("type"), "customer": entry.get("customer")})
        return kb_id

    def search_kb(
        self,
        query_text: str,
        customer: Optional[str] = None,
        rule_name: Optional[str] = None,
        top_k: int = 3,
    ) -> list[dict]:
        """
        Search the knowledge base for entries relevant to the current alert.

        Hybrid RRF search — same dense+sparse strategy as alerts collection.

        customer filter: returns global entries (customer=None) AND customer-specific
        entries. Pure customer-scoped filtering would miss global runbooks.

        Returns list of dicts with: kb_id, type, title, content, customer, rule_name,
        tags, score.
        """
        dense_vec  = embed(query_text)
        sparse_vec = sparse_embed(query_text)

        # No customer filter in Qdrant — we post-filter to include both
        # global entries AND customer-specific entries.
        prefetch_limit = top_k * _PREFETCH_FACTOR * 2  # wider net for post-filter

        results = self.client.query_points(
            collection_name=KB_COLLECTION,
            prefetch=[
                Prefetch(
                    query=sparse_vec,
                    using="sparse",
                    limit=prefetch_limit,
                ),
                Prefetch(
                    query=dense_vec,
                    using="dense",
                    limit=prefetch_limit,
                ),
            ],
            query=FusionQuery(fusion=Fusion.RRF),
            limit=prefetch_limit,
            with_payload=True,
        ).points

        hits = []
        for r in results:
            p = r.payload or {}
            entry_customer = p.get("customer")

            # Include if: global entry (customer is None/empty) OR matches requested customer
            if entry_customer and customer and entry_customer.upper() != customer.upper():
                continue

            # Optional rule_name filter — include if entry is for all rules or matches
            entry_rule = p.get("rule_name")
            if rule_name and entry_rule and entry_rule.lower() not in rule_name.lower():
                continue

            hits.append({
                "score":      round(r.score, 4),
                "kb_id":      p.get("kb_id"),
                "type":       p.get("type"),
                "title":      p.get("title"),
                "content":    p.get("content"),
                "customer":   p.get("customer"),
                "rule_name":  p.get("rule_name"),
                "tags":       p.get("tags", []),
            })

            if len(hits) >= top_k:
                break

        return hits

    def list_kb_entries(
        self,
        customer: Optional[str] = None,
        kb_type: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """
        List knowledge-base entries for management UIs (no embedding / no search).

        Uses scroll() to page through the collection. Optional payload filters on
        `type` and `customer`. Returns the stored payload fields plus kb_id.
        """
        conditions = []
        if kb_type:
            conditions.append(FieldCondition(key="type", match=MatchValue(value=kb_type)))
        if customer:
            conditions.append(FieldCondition(key="customer", match=MatchValue(value=customer)))
        scroll_filter = Filter(must=conditions) if conditions else None

        points, _next = self.client.scroll(
            collection_name=KB_COLLECTION,
            scroll_filter=scroll_filter,
            limit=limit,
            with_payload=True,
            with_vectors=False,
        )
        entries = []
        for pt in points:
            p = pt.payload or {}
            entries.append({
                "kb_id":      p.get("kb_id") or str(pt.id),
                "type":       p.get("type"),
                "title":      p.get("title"),
                "content":    p.get("content"),
                "customer":   p.get("customer"),
                "rule_name":  p.get("rule_name"),
                "tags":       p.get("tags", []),
                "created_at": p.get("created_at"),
            })
        return entries

    def delete_kb_entry(self, kb_id: str) -> bool:
        """Delete a single knowledge-base entry by kb_id. Returns True on success."""
        self.client.delete(
            collection_name=KB_COLLECTION,
            points_selector=PointIdsList(points=[_str_to_uuid(kb_id)]),
        )
        log.info("KB entry deleted", extra={"kb_id": kb_id})
        return True

    def search_ioc(self, indicator: str) -> list[dict]:
        """
        Check if an IP / hash was seen in past alerts across all customers.

        Uses sparse-only search: an IOC is an exact identifier (IP, hash), not a
        semantic concept — sparse token overlap is both faster and more precise here.
        Dense semantic search adds no value and can surface false neighbours.
        """
        ioc_text   = f"indicator: {indicator}"
        sparse_vec = sparse_embed(ioc_text)

        results = self.client.query_points(
            collection_name=IOC_COLLECTION,
            query=sparse_vec,
            using="sparse",
            limit=10,
            with_payload=True,
        ).points

        return [
            r.payload for r in results
            if r.payload.get("ioc_value", "").lower() == indicator.lower()
        ]

    # ------------------------------------------------------------------
    # Update verdict
    # ------------------------------------------------------------------

    def save_verdict(
        self,
        alert_id: str,
        verdict: str,
        reason: str,
        analyst: str = None,
    ) -> bool:
        """
        Attach an analyst verdict to a previously indexed alert.

        IMPORTANT: this does NOT re-embed the original point. Re-embedding with
        the verdict string contaminated the vector space — same alert pattern
        with FP vs TP verdicts pulled apart and polluted neighbour searches.

        Instead:
          1. Update payload of the original point (vector untouched).
          2. Mark human_verified=True + feedback_source="analyst_decision".
        """
        point_id = _str_to_uuid(alert_id)

        results = self.client.retrieve(
            collection_name=COLLECTION,
            ids=[point_id],
            with_payload=True,
            with_vectors=False,
        )
        if not results:
            return False

        # Payload-only update — vector remains as originally indexed.
        self.client.set_payload(
            collection_name=COLLECTION,
            payload={
                "verdict":          verdict,
                "verdict_reason":   reason,
                "analyst":          analyst,
                "human_verified":   True,
                "feedback_source":  "analyst_decision",
            },
            points=[point_id],
        )
        return True

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, customer: Optional[str] = None) -> dict:
        info = self.client.get_collection(COLLECTION)
        return {
            "total_alerts": info.points_count,
            "collection":   COLLECTION,
            "embed_dim":    EMBED_DIM,
            "search_mode":  "hybrid (dense + sparse, RRF)",
            "customer_filter": customer,
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _str_to_uuid(s: str) -> str:
    try:
        return str(uuid.UUID(s))
    except ValueError:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, s))


def _is_private(ip: str) -> bool:
    private_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "::1", "fe80"
    )
    return any(ip.startswith(p) for p in private_prefixes)


def _domain_from_url(url) -> Optional[str]:
    """Extract the lowercased hostname from a URL or bare domain.

    Returns None for empty input, or when the host is an IP literal (those are
    indexed as IP indicators, not domains). Handles scheme-less values like
    'evil.com/path' by treating the whole string as a netloc.
    """
    if not url or not isinstance(url, str):
        return None
    from urllib.parse import urlparse
    import re as _re

    candidate = url.strip()
    if "://" not in candidate:
        candidate = "//" + candidate
    host = urlparse(candidate).hostname
    if not host:
        return None
    # Skip IP literals (IPv4 dotted-quad or IPv6 with ':') — domain space only.
    if _re.fullmatch(r"[0-9.]+", host) or ":" in host:
        return None
    return host.lower()
