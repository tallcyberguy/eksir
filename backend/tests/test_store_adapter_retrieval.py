"""Unit tests for the cosine-based retrieval fixes (#1 score metric, #2 rule_name).

Pure tests — no Qdrant / vendored store needed. The vendored ``store`` and the
``_normalized_alert.build`` bridge (which needs the vendored NormalizedAlert) are
monkeypatched, so only the isoc-side gate logic is exercised.
"""

from __future__ import annotations

import os
import sys

import pytest

from isoc_api.adapters import _normalized_alert, store_adapter


def _add_vendored_path():
    """The real NormalizedAlert lives in the vendored alert-memory-mcp; add it to
    sys.path so the #3 tests can construct one (it imports only stdlib)."""
    p = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
    )
    if p not in sys.path:
        sys.path.insert(0, p)


# ── #2: rule_name normalized on both sides ──────────────────────────────────
def test_clean_rule_name_symmetry():
    raw = "CONTOSO: Exploit: Possible SQL Discovery [DE.CM.1] [TA0007]"
    core = "Exploit: Possible SQL Discovery"
    # A raw (SKILL-seeded) stored name cleans to the same core as the query name.
    assert _normalized_alert.clean_rule_name(raw, "CONTOSO") == core
    # Cleaning an already-clean name is idempotent.
    assert _normalized_alert.clean_rule_name(core, "CONTOSO") == core


# ── #4: customer canonicalization (case/whitespace-robust tenant filter) ────
def test_canonical_customer():
    assert store_adapter.canonical_customer("Contoso") == "CONTOSO"
    assert store_adapter.canonical_customer("  acme   corp ") == "ACME CORP"
    assert store_adapter.canonical_customer("ACME") == "ACME"  # idempotent
    # Empty / non-str → None so the caller applies NO filter (cross-customer).
    assert store_adapter.canonical_customer("") is None
    assert store_adapter.canonical_customer("   ") is None
    assert store_adapter.canonical_customer(None) is None


# ── #3: embed coverage (email / dst_ip / hash) ──────────────────────────────
def test_embed_text_includes_email_fields():
    _add_vendored_path()
    pytest.importorskip("normalizer")
    alert = _normalized_alert.build(
        {
            "rule_name": "ACME: Phishing Mail Detected",
            "sender": "attacker@evil.example",
            "recipient": "ceo@corp.example",
            "subject": "Urgent wire transfer",
            "customer": "ACME",
        }
    ).finalize()
    txt = alert.embed_text
    assert "Sender: attacker@evil.example" in txt
    assert "Recipient: ceo@corp.example" in txt
    assert "Subject: Urgent wire transfer" in txt
    # rule_name prefix still stripped (base behavior preserved).
    assert "Rule: Phishing Mail Detected" in txt


def test_embed_text_includes_dst_and_hash():
    _add_vendored_path()
    pytest.importorskip("normalizer")
    alert = _normalized_alert.build(
        {
            "rule_name": "C2 beacon",
            "dst_ip": "203.0.113.9",
            "dst_port": 443,
            "file_hash_sha256": "a" * 64,
        }
    ).finalize()
    txt = alert.embed_text
    assert "Destination: 203.0.113.9:443" in txt
    assert f"File hash: {'a' * 64}" in txt


def test_inject_customer():
    # The customer (which lives on the incident row, not in normalized) is threaded
    # into the dict build() consumes, using the RAW value.
    assert store_adapter._inject_customer({"rule_name": "x"}, "acme") == {
        "rule_name": "x",
        "customer": "acme",
    }
    # Never overrides an existing customer, and no-ops on empty input.
    assert store_adapter._inject_customer({"customer": "A"}, "B") == {"customer": "A"}
    assert store_adapter._inject_customer({"rule_name": "x"}, None) == {"rule_name": "x"}
    assert store_adapter._inject_customer({"rule_name": "x"}, "  ") == {"rule_name": "x"}


# ── #1: cosine floor filters on the honest [0,1] similarity ─────────────────
def test_passes_cosine_floor():
    assert store_adapter._passes_cosine({"cosine": 0.90}, 0.55) is True
    assert store_adapter._passes_cosine({"cosine": 0.55}, 0.55) is True
    assert store_adapter._passes_cosine({"cosine": 0.40}, 0.55) is False
    # A missing / null cosine (e.g. legacy row without a stored vector) is dropped,
    # never kept on RRF fallback — we won't let an unscoreable row drive n_way.
    assert store_adapter._passes_cosine({"cosine": None}, 0.55) is False
    assert store_adapter._passes_cosine({}, 0.55) is False


# ── Fakes for the async gate tests ──────────────────────────────────────────
class _FakeStore:
    def __init__(self, hits):
        self._hits = hits
        self.calls: list[dict] = []

    def search_similar(self, query, customer=None, top_k=5, min_score=0.0):
        self.calls.append({"customer": customer, "top_k": top_k, "min_score": min_score})
        return self._hits


class _FakeQuery:
    def __init__(self, rule_name):
        self.rule_name = rule_name

    def finalize(self):
        return self


def _patch(monkeypatch, hits, query_rule):
    store = _FakeStore(hits)
    monkeypatch.setattr(store_adapter, "_store", lambda: store)
    monkeypatch.setattr(store_adapter._normalized_alert, "build", lambda d: _FakeQuery(query_rule))
    return store


_QUERY_RULE = "Exploit: Possible SQL Discovery"
_STORED_RAW = "ACME: Exploit: Possible SQL Discovery [DE.CM.1]"
_NORMALIZED = {"rule_name": _STORED_RAW, "customer": "ACME"}


def _hit(**over):
    base = {
        "alert_id": "prior-1",
        "rule_name": _STORED_RAW,  # raw stored name → cleans to the query core
        "verdict": "FP",
        "verdict_reason": "known scanner",
        "customer": "ACME",
        "timestamp": "2026-06-01T00:00:00Z",
        "human_verified": True,
        "cosine": 0.95,
        "score": 0.6,  # RRF — must NOT leak into the returned score
    }
    base.update(over)
    return base


async def test_exact_match_returns_cosine_not_rrf(monkeypatch):
    _patch(monkeypatch, [_hit()], _QUERY_RULE)
    out = await store_adapter.find_exact_match(_NORMALIZED, "ACME")
    assert out is not None
    # The returned score is the honest cosine (0.95), not the RRF fusion score (0.6).
    assert out["score"] == 0.95
    assert out["verdict"] == "FP"
    assert out["alert_id"] == "prior-1"


async def test_exact_match_matches_seeded_raw_rule_name(monkeypatch):
    # Stored name is raw with customer prefix + bracket codes; query name is clean.
    # Normalizing both sides must make them compare equal.
    _patch(monkeypatch, [_hit(rule_name=_STORED_RAW)], _QUERY_RULE)
    out = await store_adapter.find_exact_match(_NORMALIZED, "ACME")
    assert out is not None


async def test_exact_match_rejects_unverified(monkeypatch):
    _patch(monkeypatch, [_hit(human_verified=False)], _QUERY_RULE)
    assert await store_adapter.find_exact_match(_NORMALIZED, "ACME") is None


async def test_exact_match_rejects_tp(monkeypatch):
    _patch(monkeypatch, [_hit(verdict="TP")], _QUERY_RULE)
    assert await store_adapter.find_exact_match(_NORMALIZED, "ACME") is None


async def test_exact_match_rejects_different_rule(monkeypatch):
    _patch(monkeypatch, [_hit(rule_name="ACME: Brute force [T1110]")], _QUERY_RULE)
    assert await store_adapter.find_exact_match(_NORMALIZED, "ACME") is None


async def test_exact_match_none_cosine_scores_zero(monkeypatch):
    # No stored vector → cosine None → score 0.0 so the 0.9 auto-close can't fire,
    # but the prior is still surfaced for the briefing.
    _patch(monkeypatch, [_hit(cosine=None)], _QUERY_RULE)
    out = await store_adapter.find_exact_match(_NORMALIZED, "ACME")
    assert out is not None
    assert out["score"] == 0.0


async def test_exact_match_no_hits(monkeypatch):
    _patch(monkeypatch, [], _QUERY_RULE)
    assert await store_adapter.find_exact_match(_NORMALIZED, "ACME") is None


async def test_search_similar_filters_by_cosine(monkeypatch):
    hits = [
        {"alert_id": "a", "cosine": 0.90, "verdict": "FP"},
        {"alert_id": "b", "cosine": 0.40, "verdict": "TP"},  # below floor → dropped
        {"alert_id": "c", "cosine": None, "verdict": "FP"},  # unscoreable → dropped
    ]
    store = _patch(monkeypatch, hits, "rule")
    out = await store_adapter.search_similar({"rule_name": "rule"}, "ACME", top_k=10)
    assert [h["alert_id"] for h in out] == ["a"]
    # The vendored call is made UNFILTERED (min_score=0.0); the floor is applied here.
    assert store.calls[0]["min_score"] == 0.0


async def test_search_similar_canonicalizes_customer(monkeypatch):
    store = _patch(monkeypatch, [], "rule")
    await store_adapter.search_similar({"rule_name": "rule"}, "  contoso corp ")
    # The mixed-case, padded tenant id reaches the store filter canonicalized.
    assert store.calls[0]["customer"] == "CONTOSO CORP"


class _FakeAlert:
    def __init__(self, customer=None):
        self.customer = customer
        self.rule_name = "Foo"

    def finalize(self):
        return self


async def test_index_alert_stores_canonical_customer(monkeypatch):
    captured: dict = {}

    class _S:
        def index_alert(self, alert):
            captured["customer"] = alert.customer
            return "id-1"

    class _N:
        def infer_category(self, s):
            return "malware"

    monkeypatch.setattr(store_adapter, "_store", lambda: _S())
    monkeypatch.setattr(store_adapter, "_normalizer", lambda: _N())
    monkeypatch.setattr(
        store_adapter._normalized_alert, "build", lambda d: _FakeAlert(customer=d.get("customer"))
    )
    out = await store_adapter.index_alert({"rule_name": "Foo"}, "TP", "reason", customer="acme")
    assert out == "id-1"
    # The tenant passed at the call site is stored canonicalized (was null before).
    assert captured["customer"] == "ACME"
