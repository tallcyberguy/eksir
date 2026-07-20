"""Unit tests for the connectors framework (registry + route builder)."""

from __future__ import annotations

import pytest

from isoc_api.adapters.connectors import registry
from isoc_api.routes.connectors import build_connector_list


def test_catalog_covers_all_keys_and_shapes():
    cat = registry.catalog()
    keys = {c["key"] for c in cat}
    # the six in-scope EDRs are present
    assert {
        "vision_one",
        "sentinelone",
        "crowdstrike",
        "cortex_xdr",
        "microsoft_defender",
        "guardduty",
    } <= keys
    for c in cat:
        assert c["category"] in {"edr", "ti", "recon"}
        # every connector needs some credential — a token or OAuth client creds
        assert "api_key" in c["fields"] or "client_id" in c["fields"]
        assert c["adapter_status"] in {"live", "planned"}
        assert all(cap in {"enrich", "respond", "hunt"} for cap in c["capabilities"])


def test_connector_keys_unique_and_match_specs():
    keys = registry.connector_keys()
    assert len(keys) == len(set(keys))
    assert len(keys) == len(registry.CONNECTORS)


def test_live_connectors_have_adapters():
    live = {c["key"] for c in registry.catalog() if c["adapter_status"] == "live"}
    # V1 + S1 + the two OAuth EDRs (CrowdStrike, Defender) are live; Cortex XDR is still planned.
    assert {"vision_one", "sentinelone", "crowdstrike", "microsoft_defender"} <= live
    assert "cortex_xdr" not in live


def test_get_spec_and_capabilities():
    assert registry.get_spec("sentinelone").label == "SentinelOne"
    assert "hunt" in registry.capabilities_for("sentinelone")
    assert registry.get_spec("nope") is None
    assert registry.capabilities_for("nope") == ()


def test_vision_one_needs_region_field():
    v1 = registry.get_spec("vision_one")
    assert "region" in v1.fields
    assert v1.region_options  # non-empty region choices


def test_build_connector_list_merges_catalog_metadata():
    out = build_connector_list(
        [
            {
                "id": "1",
                "provider": "vision_one",
                "identifier": "acme",
                "label": None,
                "enabled": True,
                "region": "eu",
                "base_url": None,
                "has_key": True,
            },
            {
                "id": "2",
                "provider": "cortex_xdr",
                "identifier": "default",
                "label": "CX",
                "enabled": False,
                "region": None,
                "base_url": "x",
                "has_key": False,
            },
        ]
    )
    by_id = {c["id"]: c for c in out["connectors"]}
    assert by_id["1"]["capabilities"] == ["enrich", "respond"]
    assert by_id["1"]["adapter_status"] == "live"
    assert by_id["1"]["label_catalog"] == "Trend Micro Vision One"
    assert by_id["2"]["adapter_status"] == "planned"  # cortex_xdr still planned
    # the full catalog rides along for the UI form
    assert len(out["catalog"]) == len(registry.CONNECTORS)


def test_build_connector_list_unknown_provider_degrades():
    out = build_connector_list(
        [
            {
                "id": "9",
                "provider": "mystery",
                "identifier": "x",
                "label": None,
                "enabled": True,
                "region": None,
                "base_url": None,
                "has_key": True,
            }
        ]
    )
    c = out["connectors"][0]
    assert c["capabilities"] == []
    assert c["adapter_status"] == "planned"
    assert c["label_catalog"] == "mystery"


# ── Pull ingestion source control plane (pure helpers) ──────────────────
def test_pullable_catalog_only_lists_providers_with_an_adapter():
    from isoc_api.routes.connectors import pullable_catalog

    keys = {c["key"] for c in pullable_catalog()}
    # V1 + S1 + CrowdStrike + Defender have live pull adapters; Cortex XDR does not yet.
    assert {"vision_one", "sentinelone", "crowdstrike", "microsoft_defender"} <= keys
    assert "cortex_xdr" not in keys


def test_validate_source_provider_rejects_non_pullable():
    from fastapi import HTTPException

    from isoc_api.routes.connectors import _validate_source_provider

    _validate_source_provider("vision_one")  # no raise
    _validate_source_provider("sentinelone")  # no raise (now has an adapter)
    _validate_source_provider("crowdstrike")  # no raise (now live)
    with pytest.raises(HTTPException) as ei:
        _validate_source_provider("cortex_xdr")  # still planned
    assert ei.value.status_code == 400


def test_validate_min_severity():
    from fastapi import HTTPException

    from isoc_api.routes.connectors import _validate_min_severity

    _validate_min_severity(None)  # allowed (no floor)
    _validate_min_severity("high")
    with pytest.raises(HTTPException):
        _validate_min_severity("bogus")


def test_oauth_edrs_use_client_credentials_not_api_key():
    cs = registry.get_spec("crowdstrike")
    df = registry.get_spec("microsoft_defender")
    assert cs.fields == ("client_id", "client_secret", "base_url")
    assert df.fields == ("client_id", "client_secret", "oauth_tenant_id")
    assert "api_key" not in cs.fields and "api_key" not in df.fields
    # token providers still use a single key
    assert "api_key" in registry.get_spec("vision_one").fields
    assert "api_key" in registry.get_spec("sentinelone").fields


def test_creds_dataclass_carries_oauth_fields():
    from isoc_api.adapters.integration_store import Creds

    c = Creds(
        provider="crowdstrike",
        identifier="acme",
        api_key="",
        base_url="https://api.eu-1.crowdstrike.com",
        region=None,
        client_id="cid",
        client_secret="sec",  # pragma: allowlist secret
        oauth_tenant_id=None,
    )
    assert c.client_id == "cid"
    assert c.client_secret == "sec"  # pragma: allowlist secret
    # defaults are empty/None when a provider uses a single api_key
    d = Creds(provider="sentinelone", identifier="default", api_key="k", base_url="x", region=None)
    assert d.client_id is None and d.client_secret == ""


def test_source_dict_serializes_row_with_health():
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from isoc_api.routes.connectors import source_dict

    now = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
    row = SimpleNamespace(
        id="abc",
        provider="vision_one",
        identifier="acme",
        customer="acme",
        enabled=True,
        interval_seconds=300,
        min_severity="medium",
        max_items=100,
        consecutive_errors=2,
        last_error="boom",
        field_map=None,
        last_poll_ms=240,
        last_poll_count=3,
        total_ingested=42,
        last_poll_at=now,
        last_success_at=None,
        created_at=now,
    )
    d = source_dict(row, now=now)
    assert d["provider"] == "vision_one"
    assert d["label"] == "Trend Micro Vision One"  # resolved from the catalog
    assert d["enabled"] is True
    assert d["consecutive_errors"] == 2
    assert d["last_error"] == "boom"
    assert d["last_poll_at"] == now.isoformat()
    assert d["last_success_at"] is None
