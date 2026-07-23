"""Tests for the Microsoft Defender read-only enrichment / hunting functions.

Covers the two-audience token selection (Graph vs Defender-for-Endpoint API), the
URL / body / param shaping of each read call, result capping, and DefenderError on
a non-2xx. The token + data HTTP calls are served by a fake httpx client injected
via ``defender_adapter.httpx`` so no live tenant is needed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from isoc_api.adapters import defender_adapter as da
from isoc_api.adapters import ocsf_defender
from isoc_api.llm import tools as llm_tools

_SECRET = "sec"  # pragma: allowlist secret
_CREDS = {"tenant_id": "tid", "client_id": "cid", "client_secret": _SECRET}


class _FakeClient:
    """Serves queued httpx.Response objects across post()/get(), capturing calls."""

    def __init__(self, responses: list[httpx.Response], capture: dict):
        # Shared queue (NOT copied): _token and the data call build separate
        # clients but must consume from one ordered queue [token, data, ...].
        self._responses = responses
        self._capture = capture

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *_a) -> bool:
        return False

    async def post(self, url, data=None, json=None, headers=None):
        self._capture["calls"].append({"m": "POST", "url": url, "data": data, "json": json})
        return self._responses.pop(0)

    async def get(self, url, params=None):
        self._capture["calls"].append({"m": "GET", "url": url, "params": params})
        return self._responses.pop(0)

    async def patch(self, url, json=None, headers=None):
        self._capture["calls"].append({"m": "PATCH", "url": url, "json": json})
        return self._responses.pop(0)


def _install(monkeypatch, responses: list[httpx.Response]) -> dict:
    """Point defender_adapter.httpx.AsyncClient at a fake serving ``responses``."""
    capture: dict = {"calls": [], "ctor": []}

    def _factory(**kwargs):
        capture["ctor"].append(kwargs)
        return _FakeClient(responses, capture)

    monkeypatch.setattr(da.httpx, "AsyncClient", _factory)
    return capture


def _token_resp() -> httpx.Response:
    return httpx.Response(200, json={"access_token": "tok", "expires_in": 3599})


# ── run_hunting_query (Graph) ────────────────────────────────────────────────


async def test_run_hunting_query_uses_graph_scope_and_posts_kql(monkeypatch):
    cap = _install(
        monkeypatch,
        [_token_resp(), httpx.Response(200, json={"results": [{"a": 1}, {"a": 2}], "schema": []})],
    )
    out = await da.run_hunting_query("DeviceProcessEvents | limit 2", **_CREDS)

    assert [r["a"] for r in out] == [1, 2]
    token_call, hunt_call = cap["calls"]
    # token audience = Graph (default scope)
    assert token_call["data"]["scope"] == da._GRAPH_SCOPE
    # hunting hits the Graph runHuntingQuery endpoint with the KQL in the body
    assert hunt_call["url"] == f"{da._GRAPH}/security/runHuntingQuery"
    assert hunt_call["json"] == {"Query": "DeviceProcessEvents | limit 2"}


async def test_run_hunting_query_caps_records(monkeypatch):
    rows = [{"a": i} for i in range(10)]
    _install(monkeypatch, [_token_resp(), httpx.Response(200, json={"results": rows})])
    out = await da.run_hunting_query("q", max_records=3, **_CREDS)
    assert len(out) == 3


async def test_run_hunting_query_empty_results(monkeypatch):
    _install(monkeypatch, [_token_resp(), httpx.Response(200, json={"schema": []})])
    out = await da.run_hunting_query("q", **_CREDS)
    assert out == []


# ── MDE detail calls (machine / file / ip) ───────────────────────────────────


async def test_get_machine_uses_mde_scope_and_path(monkeypatch):
    cap = _install(
        monkeypatch,
        [_token_resp(), httpx.Response(200, json={"id": "m1", "riskScore": "High"})],
    )
    out = await da.get_machine("m1", **_CREDS)

    assert out == {"id": "m1", "riskScore": "High"}
    token_call, get_call = cap["calls"]
    assert token_call["data"]["scope"] == da._MDE_SCOPE  # Defender-for-Endpoint audience
    assert get_call["url"] == f"{da._MDE}/machines/m1"


async def test_get_file_stats_path(monkeypatch):
    cap = _install(
        monkeypatch,
        [_token_resp(), httpx.Response(200, json={"sha1": "abc", "orgPrevalence": "1"})],
    )
    out = await da.get_file_stats("abc", **_CREDS)
    assert out["orgPrevalence"] == "1"
    assert cap["calls"][1]["url"] == f"{da._MDE}/files/abc/stats"


async def test_get_ip_stats_path(monkeypatch):
    cap = _install(
        monkeypatch,
        [_token_resp(), httpx.Response(200, json={"ipAddress": "1.2.3.4", "orgPrevalence": "0"})],
    )
    out = await da.get_ip_stats("1.2.3.4", **_CREDS)
    assert out["ipAddress"] == "1.2.3.4"
    assert cap["calls"][1]["url"] == f"{da._MDE}/ips/1.2.3.4/stats"


# ── error degradation ────────────────────────────────────────────────────────


async def test_non_2xx_raises_defender_error(monkeypatch):
    _install(monkeypatch, [_token_resp(), httpx.Response(404, text="not found")])
    with pytest.raises(da.DefenderError) as exc:
        await da.get_machine("missing", **_CREDS)
    assert exc.value.status == 404


# ── creds-bound tool handlers (llm/tools.make_defender_handlers) ──────────────

_DEF_CREDS = SimpleNamespace(oauth_tenant_id="tid", client_id="cid", client_secret=_SECRET)


def test_make_defender_handlers_exposes_four_tools():
    handlers = llm_tools.make_defender_handlers(_DEF_CREDS)
    assert set(handlers) == {
        "defender_run_hunt",
        "defender_get_machine",
        "defender_file_stats",
        "defender_ip_stats",
    }
    # tool schemas advertised alongside the handlers
    assert {t["function"]["name"] for t in llm_tools.DEFENDER_TOOLS} == set(handlers)


async def test_handler_maps_creds_and_calls_adapter(monkeypatch):
    seen: dict = {}

    async def _fake_get_machine(machine_id, *, tenant_id, client_id, client_secret):
        seen.update(
            machine_id=machine_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        return {"id": machine_id, "riskScore": "High"}

    monkeypatch.setattr(da, "get_machine", _fake_get_machine)
    handlers = llm_tools.make_defender_handlers(_DEF_CREDS)
    out = await handlers["defender_get_machine"]({"machine_id": "m1"})

    assert out == {"id": "m1", "riskScore": "High"}
    # oauth_tenant_id on the creds row maps to the adapter's tenant_id kwarg
    assert seen == {
        "machine_id": "m1",
        "tenant_id": "tid",
        "client_id": "cid",
        "client_secret": _SECRET,
    }


async def test_run_hunt_handler_shapes_result(monkeypatch):
    async def _fake_hunt(kql, *, tenant_id, client_id, client_secret, max_records):
        return [{"DeviceName": "H1"}, {"DeviceName": "H2"}]

    monkeypatch.setattr(da, "run_hunting_query", _fake_hunt)
    handlers = llm_tools.make_defender_handlers(_DEF_CREDS)
    out = await handlers["defender_run_hunt"]({"kql": "DeviceProcessEvents | limit 2"})
    assert out == {"count": 2, "results": [{"DeviceName": "H1"}, {"DeviceName": "H2"}]}


async def test_handler_missing_arg_returns_error(monkeypatch):
    handlers = llm_tools.make_defender_handlers(_DEF_CREDS)
    assert await handlers["defender_run_hunt"]({}) == {
        "error": "kql (advanced-hunting query) is required"
    }
    assert (await handlers["defender_file_stats"]({"sha1": "  "}))["error"] == "sha1 is required"


async def test_run_hunt_slims_wide_rows(monkeypatch):
    long_cmd = "powershell " + "A" * 800  # oversized field must be truncated

    async def _fake_hunt(kql, *, tenant_id, client_id, client_secret, max_records):
        return [{"DeviceName": "H1", "InitiatingProcessCommandLine": long_cmd}]

    monkeypatch.setattr(da, "run_hunting_query", _fake_hunt)
    handlers = llm_tools.make_defender_handlers(_DEF_CREDS)
    out = await handlers["defender_run_hunt"]({"kql": "q"})

    row = out["results"][0]
    assert row["DeviceName"] == "H1"  # short field untouched
    assert row["InitiatingProcessCommandLine"].endswith("…")  # long field truncated
    assert len(row["InitiatingProcessCommandLine"]) < len(long_cmd)


# ── Phase 3: gated response actions (Defender for Endpoint API, write) ─────────


async def test_isolate_machine_posts_to_mde_with_comment(monkeypatch):
    cap = _install(
        monkeypatch, [_token_resp(), httpx.Response(201, json={"id": "act-1", "type": "Isolate"})]
    )
    out = await da.isolate_machine("m1", "confirmed TP — contain", **_CREDS)
    assert out["type"] == "Isolate"
    token_call, post_call = cap["calls"]
    assert token_call["data"]["scope"] == da._MDE_SCOPE  # action uses the MDE audience
    assert post_call["m"] == "POST"
    assert post_call["url"] == f"{da._MDE}/machines/m1/isolate"
    assert post_call["json"] == {"Comment": "confirmed TP — contain", "IsolationType": "Full"}


async def test_unisolate_machine_posts(monkeypatch):
    cap = _install(monkeypatch, [_token_resp(), httpx.Response(201, json={"type": "Unisolate"})])
    await da.unisolate_machine("m1", "restore after review", **_CREDS)
    assert cap["calls"][1]["url"] == f"{da._MDE}/machines/m1/unisolate"
    assert cap["calls"][1]["json"] == {"Comment": "restore after review"}


async def test_run_av_scan_posts_with_scan_type(monkeypatch):
    cap = _install(
        monkeypatch, [_token_resp(), httpx.Response(201, json={"type": "AntiVirusScan"})]
    )
    await da.run_av_scan("m1", "scan it", scan_type="Full", **_CREDS)
    assert cap["calls"][1]["url"] == f"{da._MDE}/machines/m1/runAntiVirusScan"
    assert cap["calls"][1]["json"] == {"Comment": "scan it", "ScanType": "Full"}


async def test_action_non_2xx_raises(monkeypatch):
    _install(monkeypatch, [_token_resp(), httpx.Response(404, text="machine not found")])
    with pytest.raises(da.DefenderError) as exc:
        await da.isolate_machine("bogus", "x", **_CREDS)
    assert exc.value.status == 404


def test_defenderactions_router_exposes_gated_paths():
    from isoc_api.routes import defenderactions

    paths = {r.path for r in defenderactions.router.routes}
    assert "/{incident_id}/isolate" in paths
    assert "/{incident_id}/unisolate" in paths
    assert "/{incident_id}/scan" in paths
    assert "/{incident_id}/update-alert" in paths
    assert "/{incident_id}/blocklist" in paths
    assert "/{incident_id}/disable-user" in paths
    assert "/{incident_id}/enable-user" in paths


async def test_set_user_enabled_patches_graph_user(monkeypatch):
    cap = _install(monkeypatch, [_token_resp(), httpx.Response(204)])
    out = await da.set_user_enabled("user-1", False, **_CREDS)
    assert out == {}  # 204 No Content
    token_call, patch_call = cap["calls"]
    assert token_call["data"]["scope"] == da._GRAPH_SCOPE  # User.EnableDisableAccount.All → Graph
    assert patch_call["url"] == f"{da._GRAPH}/users/user-1"
    assert patch_call["json"] == {"accountEnabled": False}


def test_entra_user_id_helper():
    obj = {
        "evidence": [
            {
                "@odata.type": "x.userEvidence",
                "userAccount": {"azureAdUserId": "obj-9", "userPrincipalName": "u@x.com"},
            }
        ]
    }
    assert ocsf_defender.entra_user_id(obj) == "obj-9"  # object id preferred
    upn = {
        "evidence": [
            {"@odata.type": "userEvidence", "userAccount": {"userPrincipalName": "u@x.com"}}
        ]
    }
    assert ocsf_defender.entra_user_id(upn) == "u@x.com"  # UPN fallback
    bare = {"evidence": [{"@odata.type": "userEvidence", "userAccount": {"accountName": "u"}}]}
    assert ocsf_defender.entra_user_id(bare) is None  # sAMAccountName not Graph-addressable


def test_propose_defender_disable_user_for_identity_tp():
    from isoc_api.pipeline import agent_routing

    l2 = SimpleNamespace(verdict="true_positive", hunt_focus="c2")
    normalized = {
        "source_product": "microsoft_defender",
        "raw": json.dumps(
            {
                "evidence": [
                    {"@odata.type": "userEvidence", "userAccount": {"azureAdUserId": "obj-9"}}
                ]
            }
        ),
    }
    acts = agent_routing.propose_response_actions(l2, {}, normalized)
    du = [a for a in acts if a.kind == "disable_user"]
    assert du and du[0].provider == "microsoft_defender"
    assert du[0].params == {"user_id": "obj-9"}


async def test_run_proposed_actions_defender_disable_user(monkeypatch):
    from isoc_api.routes import cases

    seen: dict = {}

    async def _set_enabled(user_id, enabled, **kw):
        seen.update(user_id=user_id, enabled=enabled)
        return {}

    async def _def_creds(provider, identifier=None):
        return SimpleNamespace(
            oauth_tenant_id="t", client_id="c", client_secret=_SECRET, source="integration"
        )

    monkeypatch.setattr(cases.defender_adapter, "set_user_enabled", _set_enabled)
    monkeypatch.setattr(cases.integration_store, "get_creds", _def_creds)

    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "disable_user",
                "provider": "microsoft_defender",
                "params": {"user_id": "obj-9"},
                "justification": "compromised",
            }
        ]
    }
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment=enrichment)
    user = SimpleNamespace(email="a@b.c")
    executed = await cases._run_proposed_actions(None, inc, enrichment, ["act0"], user)

    assert seen == {"user_id": "obj-9", "enabled": False}  # dispatched → disable
    assert executed[0]["status"] == "executed"


async def test_add_indicator_posts_to_mde(monkeypatch):
    cap = _install(monkeypatch, [_token_resp(), httpx.Response(201, json={"id": "ind-9"})])
    out = await da.add_indicator("1.2.3.4", "IpAddress", action="Block", title="t", **_CREDS)
    assert out["id"] == "ind-9"
    token_call, post_call = cap["calls"]
    assert token_call["data"]["scope"] == da._MDE_SCOPE  # Ti.ReadWrite → MDE audience
    assert post_call["url"] == f"{da._MDE}/indicators"
    assert post_call["json"]["indicatorValue"] == "1.2.3.4"
    assert post_call["json"]["indicatorType"] == "IpAddress"
    assert post_call["json"]["action"] == "Block"


def test_propose_defender_scan_isolate_and_blocklist():
    from isoc_api.pipeline import agent_routing

    l2 = SimpleNamespace(verdict="true_positive", hunt_focus="lateral_movement")
    normalized = {
        "source_product": "microsoft_defender",
        "raw": json.dumps(
            {"evidence": [{"@odata.type": "deviceEvidence", "mdeDeviceId": "dev-1"}]}
        ),
    }
    enrichment = {"triage": [{"verdict": "malicious", "query": {"ioc": "1.2.3.4", "type": "ip"}}]}
    acts = agent_routing.propose_response_actions(l2, enrichment, normalized)
    kinds = {(a.kind, a.provider) for a in acts}
    assert ("scan_endpoint", "microsoft_defender") in kinds
    assert ("isolate_host", "microsoft_defender") in kinds  # strong signal → isolate too
    bl = [a for a in acts if a.kind == "blocklist_ioc"]
    assert bl and bl[0].provider == "microsoft_defender"
    assert bl[0].params == {"indicator_type": "IpAddress", "value": "1.2.3.4"}


async def test_run_proposed_actions_defender_scan_and_blocklist(monkeypatch):
    from isoc_api.routes import cases

    calls: dict = {}

    async def _scan(machine_id, comment, **kw):
        calls["scan"] = machine_id
        return {"id": "scan-1"}

    async def _indicator(value, itype, **kw):
        calls["indicator"] = (value, itype)
        return {"id": "ind-1"}

    async def _def_creds(provider, identifier=None):
        return SimpleNamespace(
            oauth_tenant_id="t", client_id="c", client_secret=_SECRET, source="integration"
        )

    monkeypatch.setattr(cases.defender_adapter, "run_av_scan", _scan)
    monkeypatch.setattr(cases.defender_adapter, "add_indicator", _indicator)
    monkeypatch.setattr(cases.integration_store, "get_creds", _def_creds)

    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "scan_endpoint",
                "provider": "microsoft_defender",
                "params": {"machine_id": "dev-1"},
                "justification": "scan",
            },
            {
                "id": "act1",
                "kind": "blocklist_ioc",
                "provider": "microsoft_defender",
                "params": {"indicator_type": "IpAddress", "value": "1.2.3.4"},
                "justification": "block",
            },
        ]
    }
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment=enrichment)
    user = SimpleNamespace(email="a@b.c")
    executed = await cases._run_proposed_actions(None, inc, enrichment, ["act0", "act1"], user)

    assert calls["scan"] == "dev-1"
    assert calls["indicator"] == ("1.2.3.4", "IpAddress")
    assert all(e["status"] == "executed" for e in executed)


# ── Alert write-back + verdict mirror ─────────────────────────────────────────


def test_verdict_to_defender_status_mapping():
    assert da.verdict_to_defender_status("TP") == ("resolved", "truePositive")
    assert da.verdict_to_defender_status("FP") == ("resolved", "falsePositive")
    assert da.verdict_to_defender_status("benign") == ("resolved", "informationalExpectedActivity")
    assert da.verdict_to_defender_status("inconclusive") is None


async def test_update_alert_patches_graph_alert(monkeypatch):
    cap = _install(
        monkeypatch,
        [_token_resp(), httpx.Response(200, json={"id": "a1", "status": "resolved"})],
    )
    out = await da.update_alert("a1", status="resolved", classification="truePositive", **_CREDS)
    assert out["status"] == "resolved"
    token_call, patch_call = cap["calls"]
    assert token_call["data"]["scope"] == da._GRAPH_SCOPE  # write-back uses the Graph audience
    assert patch_call["m"] == "PATCH"
    assert patch_call["url"] == f"{da._GRAPH}/security/alerts_v2/a1"
    assert patch_call["json"] == {"status": "resolved", "classification": "truePositive"}


async def test_mirror_verdict_writeback_gated(monkeypatch):
    from isoc_api.adapters import integration_store
    from isoc_api.settings import settings

    calls: list = []

    async def _fake_update(alert_id, **kw):
        calls.append(alert_id)
        return {}

    async def _creds(provider, identifier=None):
        return SimpleNamespace(oauth_tenant_id="tid", client_id="cid", client_secret=_SECRET)

    monkeypatch.setattr(da, "update_alert", _fake_update)
    monkeypatch.setattr(integration_store, "get_creds", _creds)
    inc = SimpleNamespace(
        normalized={"source_product": "microsoft_defender", "alert_id": "a9"}, customer="acme"
    )

    monkeypatch.setattr(settings, "defender_status_writeback_enabled", False)
    await da.mirror_verdict_to_defender(inc, "TP")
    assert calls == []  # flag off → no write

    monkeypatch.setattr(settings, "defender_status_writeback_enabled", True)
    await da.mirror_verdict_to_defender(inc, "TP")
    assert calls == ["a9"]  # flag on + Defender source → writes back

    other = SimpleNamespace(
        normalized={"source_product": "visionone", "alert_id": "x"}, customer="acme"
    )
    await da.mirror_verdict_to_defender(other, "TP")
    assert calls == ["a9"]  # non-Defender source → no write


# ── manager proposes Defender action at the gate (provider-aware) ─────────────


def test_mde_device_id_helper():
    dev = {
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "dev-9"}
        ]
    }
    assert ocsf_defender.mde_device_id(dev) == "dev-9"
    assert ocsf_defender.mde_device_id(json.dumps(dev)) == "dev-9"  # JSON-string form
    email = {"evidence": [{"@odata.type": "#microsoft.graph.security.mailboxEvidence"}]}
    assert ocsf_defender.mde_device_id(email) is None  # email alert → no device


def test_propose_defender_isolate_for_endpoint_tp():
    from isoc_api.pipeline import agent_routing

    l2 = SimpleNamespace(verdict="true_positive", hunt_focus="lateral_movement")
    normalized = {
        "source_product": "microsoft_defender",
        "raw": json.dumps(
            {"evidence": [{"@odata.type": "deviceEvidence", "mdeDeviceId": "dev-1"}]}
        ),
    }
    acts = agent_routing.propose_response_actions(l2, {}, normalized)
    iso = [a for a in acts if a.kind == "isolate_host"]  # scan is also proposed alongside
    assert iso and iso[0].provider == "microsoft_defender"
    assert iso[0].params == {"machine_id": "dev-1"}


def test_propose_no_defender_action_for_email_alert():
    from isoc_api.pipeline import agent_routing

    l2 = SimpleNamespace(verdict="true_positive", hunt_focus="lateral_movement")
    normalized = {
        "source_product": "microsoft_defender",
        "raw": json.dumps({"evidence": [{"@odata.type": "analyzedMessageEvidence"}]}),
    }
    assert agent_routing.propose_response_actions(l2, {}, normalized) == []  # no device → none


async def test_run_proposed_actions_routes_defender(monkeypatch):
    from isoc_api.routes import cases

    calls: dict = {}

    async def _fake_isolate(machine_id, comment, *, tenant_id, client_id, client_secret):
        calls["machine_id"] = machine_id
        return {"id": "action-123"}

    async def _def_creds(provider, identifier=None):
        # The V1 creds are resolved up front but unused (this is a Defender-only
        # action); only the Defender resolution must return a credential.
        if provider != "microsoft_defender":
            return None
        return SimpleNamespace(
            oauth_tenant_id="t", client_id="c", client_secret=_SECRET, source="integration"
        )

    monkeypatch.setattr(cases.defender_adapter, "isolate_machine", _fake_isolate)
    monkeypatch.setattr(cases.integration_store, "get_creds", _def_creds)

    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "isolate_host",
                "provider": "microsoft_defender",
                "params": {"machine_id": "dev-1"},
                "justification": "contain",
            }
        ]
    }
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment=enrichment)
    user = SimpleNamespace(email="a@b.c")
    executed = await cases._run_proposed_actions(None, inc, enrichment, ["act0"], user)

    assert calls["machine_id"] == "dev-1"  # routed to the Defender adapter, not V1
    assert executed[0]["provider"] == "microsoft_defender"
    assert executed[0]["status"] == "executed"
    assert executed[0]["task_id"] == "action-123"
