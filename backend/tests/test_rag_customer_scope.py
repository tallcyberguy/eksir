"""RAG customer-scoping (INC-001140 regression).

A different tenant's analyst-verified priors must NOT form an n_way majority for this
customer, and must be demoted in the reranked list the LLM reads. INC-001140 (a csvisor
alert) matched 3 EMINEVIM FP priors and reported "3/7 -> FP".
"""

from __future__ import annotations

from isoc_api.pipeline import rerank
from isoc_api.pipeline.orchestrator import _compute_n_way


def _prior(customer, verdict="FP", verified=True, cosine=0.70):
    return {
        "customer": customer,
        "verdict": verdict,
        "human_verified": verified,
        "cosine": cosine,
        "timestamp": "2026-07-01T00:00:00Z",
    }


def test_n_way_ignores_cross_customer_priors():
    # 3 EMINEVIM FP priors for a csvisor query must NOT form a majority.
    matches = [_prior("EMINEVIM") for _ in range(3)]
    assert _compute_n_way(matches, "csvisor", min_agreement=3) is None


def test_n_way_counts_only_same_customer():
    matches = [
        _prior("csvisor"),
        _prior("CSVISOR"),  # canonicalized to the same tenant (case-insensitive)
        _prior("csvisor"),
        _prior("EMINEVIM", verdict="TP"),  # different tenant -> excluded
    ]
    nway = _compute_n_way(matches, "csvisor", min_agreement=3)
    assert nway is not None
    assert nway["verdict"] == "FP"
    assert nway["agreement"] == "3/3"


def test_n_way_null_customer_matches_only_null():
    # A null-customer query counts only null-customer priors (conservative).
    assert _compute_n_way([_prior("csvisor")] * 3, None, min_agreement=3) is None
    assert _compute_n_way([_prior(None)] * 3, None, min_agreement=3) is not None


def test_rerank_demotes_cross_customer():
    same = _prior("csvisor", cosine=0.70)
    other = _prior("EMINEVIM", cosine=0.70)
    ranked = rerank.rerank([other, same], "csvisor")
    assert ranked[0]["customer"] == "csvisor"  # same-tenant wins despite equal cosine
    assert ranked[0]["adjusted_score"] > ranked[1]["adjusted_score"]


def test_rerank_no_customer_is_backward_compatible():
    # Called without a customer (default None): no cross-customer penalty applied.
    out = rerank.rerank([_prior("EMINEVIM"), _prior("csvisor")])
    assert len(out) == 2 and all("adjusted_score" in r for r in out)
