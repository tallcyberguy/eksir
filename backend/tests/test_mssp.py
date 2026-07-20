"""MSSP Dashboard — the pure per-tenant rollup builder."""

from __future__ import annotations

import uuid

from isoc_api.routes.mssp import build_overview


def test_build_overview_merges_and_sorts():
    t1, t2, t3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    tenants = [
        {"id": t1, "name": "Acme", "slug": "acme", "tier": "client", "tier_label": None},
        {"id": t2, "name": "Beta", "slug": "beta", "tier": "client", "tier_label": "Gold"},
        {"id": t3, "name": "Zeta", "slug": "zeta", "tier": "client", "tier_label": None},
    ]
    open_by = {
        t1: {"open": 5, "urgent": 1, "awaiting": 0},
        t2: {"open": 2, "urgent": 2, "awaiting": 3},
    }
    win_by = {t1: {"total": 10, "closed": 8}, t2: {"total": 4, "closed": 2}}

    out = build_overview(tenants, open_by, win_by, window_days=30)

    assert out["tenant_count"] == 3
    assert out["total_open"] == 7
    assert out["total_awaiting_signoff"] == 3
    assert out["total_urgent"] == 3
    # Sorted by attention: most awaiting first (Beta), then Acme, then the idle Zeta.
    assert [r["name"] for r in out["tenants"]] == ["Beta", "Acme", "Zeta"]
    beta = out["tenants"][0]
    assert beta["awaiting_signoff"] == 3 and beta["open"] == 2 and beta["tier_label"] == "Gold"
    # Tenant with no aggregates resolves to zeros, not missing keys.
    zeta = out["tenants"][2]
    assert zeta["open"] == 0 and zeta["total"] == 0 and zeta["closed"] == 0


def test_build_overview_empty():
    out = build_overview([], {}, {}, window_days=7)
    assert out["tenant_count"] == 0 and out["total_open"] == 0 and out["tenants"] == []
