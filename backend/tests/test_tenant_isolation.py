"""Strict per-customer credential isolation (multi-tenant safety).

With ``strict_tenant_creds`` ON, a NAMED customer must resolve its OWN credential row:
the shared 'default' row is refused, so an unmapped customer fails closed instead of
borrowing another tenant's or a shared key. Global lookups (identifier None / 'default')
are unaffected. This decision (``_candidate_identifiers``) is shared by every provider's
``get_creds`` resolution, Vision One and Defender alike.
"""

from __future__ import annotations

from isoc_api.adapters import integration_store as istore


def test_candidate_identifiers_non_strict(monkeypatch):
    monkeypatch.setattr(istore.settings, "strict_tenant_creds", False)
    assert istore._candidate_identifiers("acme") == ["acme", "default"]  # customer -> default
    assert istore._candidate_identifiers(None) == ["default"]


def test_candidate_identifiers_strict_drops_default_for_named(monkeypatch):
    monkeypatch.setattr(istore.settings, "strict_tenant_creds", True)
    assert istore._candidate_identifiers("acme") == ["acme"]  # no 'default' fallback
    assert istore._candidate_identifiers("default") == ["default"]  # global lookup unaffected
    assert istore._candidate_identifiers(None) == ["default"]  # global lookup unaffected
