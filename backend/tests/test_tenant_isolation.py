"""Strict per-customer credential isolation (multi-tenant safety).

With ``strict_tenant_creds`` ON, a NAMED customer must resolve its OWN credential row —
the shared 'default' row and the V1 env-var key fallbacks are refused, so an unmapped
customer fails closed instead of borrowing another tenant's / a shared key. Global lookups
(identifier None / 'default') are unaffected.
"""

from __future__ import annotations

from types import SimpleNamespace

from isoc_api.adapters import integration_store as istore


def test_candidate_identifiers_non_strict(monkeypatch):
    monkeypatch.setattr(istore.settings, "strict_tenant_creds", False)
    assert istore._candidate_identifiers("acme") == ["acme", "default"]  # customer → default
    assert istore._candidate_identifiers(None) == ["default"]


def test_candidate_identifiers_strict_drops_default_for_named(monkeypatch):
    monkeypatch.setattr(istore.settings, "strict_tenant_creds", True)
    assert istore._candidate_identifiers("acme") == ["acme"]  # no 'default' fallback
    assert istore._candidate_identifiers("default") == ["default"]  # global lookup unaffected
    assert istore._candidate_identifiers(None) == ["default"]  # global lookup unaffected


async def test_get_creds_v1_strict_refuses_env_fallback(monkeypatch):
    async def _no_row(customer):
        return None

    monkeypatch.setattr(istore, "_fetch_v1_row", _no_row)
    monkeypatch.setattr(
        istore.settings, "v1_api_key", SimpleNamespace(get_secret_value=lambda: "envkey")
    )
    monkeypatch.setattr(istore.settings, "v1_region", "eu")

    # strict OFF → the global env key is used
    monkeypatch.setattr(istore.settings, "strict_tenant_creds", False)
    c = await istore.get_creds_v1("acme")
    assert c is not None and c.source == "global"

    # strict ON → a NAMED customer with no own row is refused the env key → None
    monkeypatch.setattr(istore.settings, "strict_tenant_creds", True)
    assert await istore.get_creds_v1("acme") is None
    # a global lookup (no named customer) still resolves the env key
    assert (await istore.get_creds_v1(None)) is not None
