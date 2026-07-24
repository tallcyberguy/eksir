"""Tests for the Vision One workbench/OAT read-only enrichment (ADR-0005).

Covers the transform/cap logic (where bugs hide) using the REAL API response
shapes captured live 2026-06-22, plus the fail-soft contract of `_fetch_v1`.
The thin HTTP wrappers (get_workbench_alert/get_oat_detections) are exercised
manually against the live API, not mocked here.
"""

from __future__ import annotations

from types import SimpleNamespace

from isoc_api.adapters import integration_store, v1_adapter
from isoc_api.pipeline import orchestrator

# A trimmed but faithful slice of a real GET /v3.0/workbench/alerts/{id} body.
WB_DETAIL = {
    "schemaVersion": "1.21",
    "id": "WB-30189-20260526-00008",
    "status": "Open",
    "investigationResult": "No Findings",
    "model": "Credential Dumping via Mimikatz",
    "modelId": "8ed8d643",
    "score": 68,
    "severity": "high",
    "createdDateTime": "2026-05-26T10:00:12Z",
    "incidentId": "IC-30189-20260521-00000",
    "description": "A user obtained account logon information via Mimikatz.",
    "impactScope": {
        "desktopCount": 1,
        "serverCount": 0,
        "accountCount": 1,
        "entities": [
            {"entityType": "account", "entityValue": "csv-04\\user"},
            {
                "entityType": "host",
                "entityValue": {"guid": "B0EF", "name": "CSV-04", "ips": ["192.168.10.17"]},
            },
        ],
    },
    "matchedRules": [
        {
            "name": "Potential Credential Dumping via Mimikatz",
            "matchedFilters": [
                {
                    "name": "Possible Credential Dumping",
                    "mitreTechniqueIds": ["T1059.003", "T1003", "T1003.001"],
                }
            ],
        }
    ],
    "indicators": [
        {
            "id": 1,
            "type": "command_line",
            "field": "objectCmd",
            "value": 'mimikatz.exe "sekurlsa::pth /user:Administrator"',
        },
        {"id": 10, "type": "text", "field": "endpointHostName", "value": "CSV-04"},
    ],
}


def test_cap_workbench_keeps_evidence_and_flattens_mitre():
    capped = orchestrator._cap_workbench(WB_DETAIL)
    assert capped["model"] == "Credential Dumping via Mimikatz"
    assert capped["score"] == 68
    assert capped["status"] == "Open"
    # MITRE techniques flattened + deduped + sorted from matchedFilters
    assert capped["mitreTechniqueIds"] == ["T1003", "T1003.001", "T1059.003"]
    # host entity value is reduced to {name, ips, guid}; account kept verbatim
    types = {e["type"]: e["value"] for e in capped["impactScope"]["entities"]}
    assert types["account"] == "csv-04\\user"
    assert types["host"] == {"name": "CSV-04", "ips": ["192.168.10.17"], "guid": "B0EF"}
    # indicators carry the command line
    fields = {i["field"]: i["value"] for i in capped["indicators"]}
    assert "sekurlsa::pth" in fields["objectCmd"]


def test_cap_workbench_truncates_long_command():
    big = dict(WB_DETAIL)
    big["indicators"] = [{"field": "processCmd", "type": "command_line", "value": "A" * 5000}]
    capped = orchestrator._cap_workbench(big)
    val = capped["indicators"][0]["value"]
    assert len(val) <= orchestrator._V1_CMD_TRUNC + 1  # +1 for the ellipsis char
    assert val.endswith("…")


def test_v1_host_prefers_impact_scope_host():
    assert orchestrator._v1_host(WB_DETAIL) == "CSV-04"


def test_v1_oat_window_brackets_created_time(monkeypatch):
    monkeypatch.setattr(orchestrator.settings, "v1_oat_window_hours", 6)
    start, end = orchestrator._v1_oat_window("2026-05-26T10:00:12Z")
    assert start == "2026-05-26T04:00:12Z"
    assert end == "2026-05-26T16:00:12Z"


def test_cap_oat_filters_noise_and_dedupes(monkeypatch):
    monkeypatch.setattr(orchestrator.settings, "v1_oat_risk_floor", "medium")
    monkeypatch.setattr(orchestrator.settings, "v1_oat_max_items", 20)
    rows = [
        # below-floor noise — dropped
        {
            "detail": {"endpointHostName": "CSV-04"},
            "filters": [
                {"name": "Uncommon File Path", "riskLevel": "low", "mitreTechniqueIds": ["T1"]}
            ],
        },
        # wrong host — dropped even though risk is high
        {
            "detail": {"endpointHostName": "OTHER-HOST"},
            "filters": [{"name": "Bad", "riskLevel": "high", "mitreTechniqueIds": ["T2"]}],
        },
        # kept
        {
            "detectedDateTime": "2026-05-26T07:35:18Z",
            "detail": {"endpointHostName": "CSV-04"},
            "filters": [
                {
                    "name": "Mimikatz",
                    "riskLevel": "high",
                    "mitreTechniqueIds": ["T1003"],
                    "highlightedObjects": [{"field": "processCmd", "value": "mimikatz.exe"}],
                }
            ],
        },
        # duplicate of the kept one (same name+techniques) — deduped
        {
            "detail": {"endpointHostName": "CSV-04"},
            "filters": [
                {"name": "Mimikatz", "riskLevel": "critical", "mitreTechniqueIds": ["T1003"]}
            ],
        },
    ]
    out = orchestrator._cap_oat(rows, host="CSV-04")
    assert len(out) == 1
    assert out[0]["name"] == "Mimikatz"
    assert out[0]["endpoint"] == "CSV-04"
    assert out[0]["highlighted"][0]["value"] == "mimikatz.exe"


async def test_get_creds_none_when_unconfigured(monkeypatch):
    """Vision One resolves through the generic get_creds now (no V1 env fallback);
    an unconfigured provider returns None."""

    async def _no_row(provider, identifier):
        return None

    monkeypatch.setattr(integration_store, "_fetch_row", _no_row)
    assert await integration_store.get_creds("vision_one", "acme") is None


def test_base_url_region_routing():
    assert v1_adapter._base_url("sg") == "https://api.sg.xdr.trendmicro.com/"
    assert v1_adapter._base_url("eu") == "https://api.eu.xdr.trendmicro.com/"
    assert v1_adapter._base_url("us") == "https://api.xdr.trendmicro.com/"


async def test_fetch_v1_oat_failure_keeps_workbench(monkeypatch):
    """An OAT failure must NOT lose the workbench detail (own try/except)."""
    monkeypatch.setattr(orchestrator.settings, "v1_oat_enabled", True)

    async def _creds(provider, identifier=None):
        api_key = "tok"  # pragma: allowlist secret
        return SimpleNamespace(api_key=api_key, region="eu", source="integration")

    monkeypatch.setattr(integration_store, "get_creds", _creds)

    async def ok_wb(alert_id, **kw):
        return WB_DETAIL

    async def boom_oat(**kw):
        raise RuntimeError("oat down")

    monkeypatch.setattr(v1_adapter, "get_workbench_alert", ok_wb)
    monkeypatch.setattr(v1_adapter, "get_oat_detections", boom_oat)

    inc = SimpleNamespace(
        customer="acme", id="ID", normalized={"v1_console_host": "portal.eu.xdr.trendmicro.com"}
    )
    out = await orchestrator._fetch_v1(inc, "WB-30189-20260526-00008")
    assert out["workbench"]["model"] == "Credential Dumping via Mimikatz"
    assert out["region"] == "eu"
    assert "oat_error" in out and "oat down" in out["oat_error"]


async def test_fetch_v1_raises_when_unconfigured(monkeypatch):
    async def _none(provider, identifier=None):
        return None

    monkeypatch.setattr(integration_store, "get_creds", _none)
    inc = SimpleNamespace(customer="acme", id="ID", normalized={})
    try:
        await orchestrator._fetch_v1(inc, "WB-1")
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "not configured" in str(e)


# ── Response-action write path: per-customer credential routing (fail-closed) ──
async def test_run_proposed_actions_fails_closed_without_creds(monkeypatch):
    from isoc_api.routes import cases

    async def _none(provider, identifier=None):
        return None

    called = {"n": 0}

    async def _must_not_fire(*a, **k):
        called["n"] += 1
        return {}

    monkeypatch.setattr(cases.integration_store, "get_creds", _none)
    monkeypatch.setattr(cases.v1_adapter, "isolate_endpoint", _must_not_fire)

    inc = SimpleNamespace(customer="acme", normalized={}, enrichment={})
    enrichment = {
        "proposed_actions": [
            {"id": "act0", "kind": "isolate_host", "params": {"endpoint_name": "H1"}}
        ]
    }
    out = await cases._run_proposed_actions(
        None, inc, enrichment, ["act0"], SimpleNamespace(email="a@b.c")
    )
    assert out[0]["status"] == "failed"
    assert "credentials" in out[0]["error"]
    assert called["n"] == 0  # never fired against a fallback/wrong tenant


async def test_run_proposed_actions_routes_per_customer_creds(monkeypatch):
    from isoc_api.routes import cases

    async def _creds(provider, identifier=None):
        api_key = "CUST_KEY"  # pragma: allowlist secret
        return SimpleNamespace(region="us", api_key=api_key, source="integration")

    seen = {}

    async def _iso(endpoint_name=None, description="", *, region=None, api_key=None):
        seen.update(endpoint_name=endpoint_name, region=region, api_key=api_key)
        return {"id": "task-1"}

    monkeypatch.setattr(cases.integration_store, "get_creds", _creds)
    monkeypatch.setattr(cases.v1_adapter, "isolate_endpoint", _iso)

    inc = SimpleNamespace(customer="acme", normalized={"v1_region": "us"}, enrichment={})
    enrichment = {
        "proposed_actions": [
            {"id": "act0", "kind": "isolate_host", "params": {"endpoint_name": "H1"}}
        ]
    }
    out = await cases._run_proposed_actions(
        None, inc, enrichment, ["act0"], SimpleNamespace(email="a@b.c")
    )
    assert out[0]["status"] == "executed"
    api_key = "CUST_KEY"  # pragma: allowlist secret
    assert seen == {"endpoint_name": "H1", "region": "us", "api_key": api_key}
