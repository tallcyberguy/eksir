"""F2 — tests for the generic credential resolution seam (pure parts).

The DB-backed `get_creds` / `_fetch_row` need Postgres and are validated on the
stack; here we lock the resolution-order contract and the Creds shape.
"""

from __future__ import annotations

from isoc_api.adapters.integration_store import (
    DEFAULT_IDENTIFIER,
    Creds,
    _candidate_identifiers,
)


def test_candidate_identifiers_specific_then_default():
    assert _candidate_identifiers("acme-corp") == ["acme-corp", "default"]


def test_candidate_identifiers_none_or_empty_is_default_only():
    assert _candidate_identifiers(None) == ["default"]
    assert _candidate_identifiers("") == ["default"]


def test_default_identifier_constant():
    assert DEFAULT_IDENTIFIER == "default"


def test_creds_defaults_source_integration():
    c = Creds(
        provider="crowdstrike",
        identifier="default",
        api_key="secret",  # pragma: allowlist secret
        base_url="https://api.crowdstrike.com",
        region=None,
    )
    assert c.source == "integration"
    assert c.provider == "crowdstrike"
    assert c.api_key == "secret"  # pragma: allowlist secret
