"""Adapter for `alert-memory-mcp/store.py` — the shared Qdrant vector DB.

All ISOC writes carry `source='isoc'` in the Qdrant payload so they are
distinguishable from records created by the SKILL workflow. This lets us
roll back ISOC-tagged records if a bug ever pollutes the store.
"""

from __future__ import annotations

import asyncio
import importlib
from functools import lru_cache
from typing import Any

from ..logging_config import get_logger
from . import _normalized_alert

logger = get_logger("isoc.adapter.store")


@lru_cache(maxsize=1)
def _store():
    mod = importlib.import_module("store")
    return mod.AlertStore()


@lru_cache(maxsize=1)
def _normalizer():
    return importlib.import_module("normalizer")


async def _run(fn, *args, **kwargs):
    """Run blocking Qdrant calls in a thread so we don't block the event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


def _has_embed_content(normalized: dict[str, Any]) -> bool:
    """True if the normalized alert has any field that would yield a non-empty
    embed_text. We check this before calling Qdrant ops so that unparseable
    alerts don't fail the whole pipeline at the embedder.
    """
    for k in (
        "rule_name",
        "src_ip",
        "dst_ip",
        "username",
        "hostname",
        "file_path",
        "file_hash_sha256",
        "cve",
        "mitre_technique",
    ):
        v = normalized.get(k)
        if isinstance(v, str) and v.strip():
            return True
    return False


def canonical_customer(customer: str | None) -> str | None:
    """Canonical form of a customer/tenant id for Qdrant matching: trimmed, inner
    whitespace collapsed, upper-cased. Returns None for empty input so the caller
    applies NO customer filter (cross-customer), matching prior behavior.

    Similar/exact retrieval filters on an exact, case-sensitive ``MatchValue`` over
    the stored ``customer`` field, so a casing/whitespace drift between ingest
    sources silently returns nothing. Canonicalizing on BOTH write (index_alert)
    and query keeps the filter robust without editing the vendored store. The
    Qdrant ``customer`` payload is not the app's display source (that's
    ``incident.customer`` in Postgres), so upper-casing it here is display-safe.
    Existing points are aligned by scripts/backfill_qdrant_customer.py.
    """
    if not customer or not isinstance(customer, str):
        return None
    return " ".join(customer.split()).upper() or None


def _inject_customer(normalized: dict[str, Any], customer: str | None) -> dict[str, Any]:
    """Thread the incident's customer into the dict that ``build()`` consumes.

    The customer lives on the incident row, not in ``normalized`` — but build()
    (via ``_clean_rule_name``) needs it to strip the customer prefix from
    rule_name identically at index and query, and the NormalizedAlert must carry
    it so retrieval can filter by tenant. Only fills when absent, and uses the RAW
    customer so the prefix-length slice in ``_clean_rule_name`` matches exactly —
    the Qdrant filter + the stored value are canonicalized separately.
    """
    if customer and customer.strip() and not str(normalized.get("customer") or "").strip():
        return {**normalized, "customer": customer}
    return normalized


async def find_exact_match(normalized: dict[str, Any], customer: str | None) -> dict | None:
    """Exact-match short-circuit candidate: the single most-similar prior that is
    analyst-confirmed (``human_verified``), same customer, same rule_name, verdict
    ∈ {FP, benign}.

    Reimplemented over ``store.search_similar`` instead of the vendored
    ``find_exact_match`` for two reasons:
      • the returned ``score`` is the TRUE cosine, not the RRF fusion score — so
        the downstream 0.9 gate (decision.evaluate / _short_circuit_block_reason)
        compares like-for-like;
      • rule_name is normalized on BOTH sides before comparing, so a SKILL-seeded
        prior stored with a raw rule_name still matches the cleaned query name
        (the vendored path compared cleaned-query vs raw-stored and silently missed).

    Only surfaces the candidate — the decision gate still applies the threshold.
    """
    if not _has_embed_content(normalized):
        logger.info("store.skip", op="find_exact_match", reason="empty_embed_content")
        return None
    query = _normalized_alert.build(_inject_customer(normalized, customer)).finalize()
    canon = canonical_customer(customer)
    try:
        hits = await _run(_store().search_similar, query, customer=canon, top_k=1, min_score=0.0)
    except Exception as e:
        logger.warning("store.exact_match_failed", error=str(e))
        return None
    if not hits:
        return None
    top = hits[0]
    if not top.get("human_verified"):
        return None
    if (top.get("verdict") or "").lower() not in ("fp", "benign"):
        return None
    # Normalize both sides — the stored name may be raw while the query name was
    # cleaned at build() time. Compare the semantic core, not the boilerplate.
    stored_rule = _normalized_alert.clean_rule_name(top.get("rule_name"), customer)
    if stored_rule != query.rule_name:
        return None
    cosine = top.get("cosine")
    return {
        "alert_id": top.get("alert_id"),
        "rule_name": top.get("rule_name"),
        "verdict": top.get("verdict"),
        "verdict_reason": top.get("verdict_reason"),
        "customer": top.get("customer"),
        "timestamp": top.get("timestamp"),
        # TRUE cosine now (was the RRF fusion score) so the 0.9 gate is meaningful.
        "score": round(cosine, 4) if isinstance(cosine, (int, float)) else 0.0,
    }


async def n_way_agreement(
    normalized: dict[str, Any],
    customer: str | None,
    top_k: int = 5,
    min_agreement: int = 3,
) -> dict | None:
    if not _has_embed_content(normalized):
        return None
    query = _normalized_alert.build(_inject_customer(normalized, customer)).finalize()
    canon = canonical_customer(customer)
    try:
        return await _run(
            _store().n_way_agreement,
            query,
            customer=canon,
            top_k=top_k,
            min_agreement=min_agreement,
        )
    except Exception as e:
        logger.warning("store.n_way_failed", error=str(e))
        return None


# Cosine floor for similar-case retrieval (honest bge-m3 [0,1] similarity). The
# vendored store filters on the RRF *fusion* score — rank-based, its scale
# unrelated to cosine — so the old 0.55 "min_score" pruned on the wrong axis.
# Below ~0.55 cosine the neighbours only share scaffolding (customer prefix,
# MITRE bracket codes, generic verbs) and poison n_way agreement downstream.
SIMILAR_COSINE_FLOOR = 0.55


def _passes_cosine(hit: dict[str, Any], floor: float) -> bool:
    c = hit.get("cosine")
    return isinstance(c, (int, float)) and c >= floor


async def search_similar(
    normalized: dict[str, Any],
    customer: str | None,
    top_k: int = 5,
    min_cosine: float = SIMILAR_COSINE_FLOOR,
) -> list[dict]:
    """Retrieve similar prior alerts, filtered to cosine ≥ ``min_cosine``.

    We fetch the RRF-ranked candidates UNFILTERED (min_score=0.0 into the vendored
    store) and apply the floor here on the honest cosine, because RRF is rank-based
    and comparing it to a cosine-scale threshold prunes the wrong matches.
    """
    if not _has_embed_content(normalized):
        return []
    query = _normalized_alert.build(_inject_customer(normalized, customer)).finalize()
    canon = canonical_customer(customer)
    try:
        hits = await _run(
            _store().search_similar,
            query,
            customer=canon,
            top_k=top_k,
            min_score=0.0,
        )
    except Exception as e:
        logger.warning("store.search_similar_failed", error=str(e))
        return []
    return [h for h in (hits or []) if _passes_cosine(h, min_cosine)]


async def search_kb(
    query_text: str,
    customer: str | None,
    rule_name: str | None,
    top_k: int = 3,
) -> list[dict]:
    return await _run(
        _store().search_kb,
        query_text=query_text,
        customer=customer,
        rule_name=rule_name,
        top_k=top_k,
    )


def _empty_history(indicator: str) -> dict:
    return {
        "indicator": indicator,
        "ioc_type": None,
        "seen": 0,
        "verdicts": {},
        "customers": [],
        "last_seen": None,
        "matches": [],
    }


async def lookup_ioc_history(indicator: str) -> dict:
    """Prior track record for one IP / file hash / domain across analyst-verified alerts.

    Wraps the vendored ``store.search_ioc`` (sparse exact-match on iocs_v2) and
    folds the raw per-alert rows into a verdict breakdown. Only IPs, SHA-1/SHA-256
    hashes and URL-derived domains are indexed there, and rows are written only at
    final-verdict time — so this is a confirmed-disposition history, not raw
    sightings. Read-only: safe for the LLM to auto-execute.
    """
    indicator = (indicator or "").strip()
    if not indicator:
        return _empty_history(indicator)
    try:
        rows = await _run(_store().search_ioc, indicator)
    except Exception as e:
        logger.warning("store.ioc_history_failed", indicator=indicator, error=str(e))
        return _empty_history(indicator)

    verdicts: dict[str, int] = {}
    customers: set[str] = set()
    for r in rows:
        v = r.get("verdict") or "unknown"
        verdicts[v] = verdicts.get(v, 0) + 1
        if r.get("customer"):
            customers.add(r["customer"])
    rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)

    return {
        "indicator": indicator,
        "ioc_type": rows[0].get("ioc_type") if rows else None,
        "seen": len(rows),
        "verdicts": verdicts,  # e.g. {"TP": 3, "FP": 1}
        "customers": sorted(customers),
        "last_seen": rows[0].get("timestamp") if rows else None,
        "matches": [
            {k: r.get(k) for k in ("alert_id", "rule_name", "customer", "verdict", "timestamp")}
            for r in rows[:10]
        ],
    }


# ── Knowledge-base management (create / list / delete) ──────────────────────
async def index_kb_entry(entry: dict[str, Any]) -> str:
    """Embed + upsert a KB entry (runbook/allowlist/asset_inventory/incident_report).
    Returns the kb_id."""
    return await _run(_store().index_kb_entry, entry)


async def list_kb(
    customer: str | None = None,
    kb_type: str | None = None,
    limit: int = 200,
) -> list[dict]:
    return await _run(_store().list_kb_entries, customer=customer, kb_type=kb_type, limit=limit)


async def delete_kb(kb_id: str) -> bool:
    return await _run(_store().delete_kb_entry, kb_id)


async def index_alert(
    normalized: dict[str, Any],
    verdict: str,
    verdict_reason: str,
    *,
    customer: str | None = None,
    threat_category: str | None = None,
    human_verified: bool = True,
    feedback_source: str = "analyst_decision",
) -> str:
    """Write the alert to Qdrant. Tags `source='isoc'` for traceability.

    ``customer`` is the incident's tenant (it lives on the incident row, not in
    ``normalized``). Passing it here is what makes tenant-scoped retrieval work —
    without it the point is stored with a null customer and the similar/exact
    filter never matches it.
    """
    norm_mod = _normalizer()
    alert = _normalized_alert.build(_inject_customer(normalized, customer))
    alert.verdict = verdict
    alert.verdict_reason = verdict_reason
    alert.threat_category = threat_category or norm_mod.infer_category(
        getattr(alert, "rule_name", "") or ""
    )
    alert.human_verified = human_verified
    alert.feedback_source = feedback_source
    # Canonicalize the stored customer so the case-sensitive similar/exact filter
    # matches regardless of the casing a source sent (see canonical_customer).
    alert.customer = canonical_customer(customer or getattr(alert, "customer", None))
    # Stash provenance — payload writer carries arbitrary attributes onto the row.
    alert.source = "isoc"
    alert = alert.finalize()

    alert_id = await _run(_store().index_alert, alert)
    logger.info("store.indexed", alert_id=str(alert_id), verdict=verdict)
    return str(alert_id)
