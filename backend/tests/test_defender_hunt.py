"""Tests for the Defender live-hunt wiring in the manager-chat re-task (Phase 2).

Mirrors the V1 activity-search gating: the live Defender advanced-hunting tool is handed to
the hunter only when ``defender_tools_enabled`` is on AND the customer has microsoft_defender
creds. Analyst-triggered path only — the automated hunt stays query-building only.
"""

from __future__ import annotations

from types import SimpleNamespace

from isoc_api.pipeline import manager_chat

_SECRET = "sec"  # pragma: allowlist secret


async def test_defender_hunt_tool_off_by_flag(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", False)
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment={})
    assert await manager_chat._defender_hunt_tool(inc) is None


async def test_defender_hunt_tool_on_with_creds(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", True)

    async def _creds(provider, identifier=None):
        assert provider == "microsoft_defender"
        return SimpleNamespace(oauth_tenant_id="tid", client_id="cid", client_secret=_SECRET)

    monkeypatch.setattr(manager_chat.integration_store, "get_creds", _creds)
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment={})
    live = await manager_chat._defender_hunt_tool(inc)
    assert live is not None
    tools_list, dispatch, system = live
    assert tools_list[0]["function"]["name"] == "defender_run_hunt"
    assert "defender_run_hunt" in dispatch
    assert system is manager_chat.prompts.HUNT_SYSTEM_LIVE


async def test_defender_hunt_tool_none_without_creds(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", True)

    async def _none(provider, identifier=None):
        return None

    monkeypatch.setattr(manager_chat.integration_store, "get_creds", _none)
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment={})
    assert await manager_chat._defender_hunt_tool(inc) is None


def test_hunt_live_state_reflects_flags_and_availability(monkeypatch):
    # available when either source resolved a live tool
    assert manager_chat._hunt_live_state(object(), None) == "available"
    assert manager_chat._hunt_live_state(None, object()) == "available"
    # neither available + both flags off -> disabled_by_config
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", False)
    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", False)
    assert manager_chat._hunt_live_state(None, None) == "disabled_by_config"
    # a flag on but no creds resolved -> no_credentials
    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", True)
    assert manager_chat._hunt_live_state(None, None) == "no_credentials"


# ── provider-aware manager-chat action revision ───────────────────────────────


def _kind_enum(tool):
    return tool["function"]["parameters"]["properties"]["actions"]["items"]["properties"]["kind"][
        "enum"
    ]


def test_provider_for_by_source():
    md = SimpleNamespace(normalized={"source_product": "microsoft_defender"})
    v1 = SimpleNamespace(normalized={"source_product": "visionone"})
    unknown = SimpleNamespace(normalized={})
    assert manager_chat._provider_for(md) == "microsoft_defender"
    assert manager_chat._provider_for(v1) == "vision_one"
    assert manager_chat._provider_for(unknown) == "vision_one"  # default back-compat


def test_propose_actions_tool_offers_the_incidents_edr_kinds():
    md_tool = manager_chat._propose_actions_tool(
        manager_chat._PROVIDER_ACTIONS["microsoft_defender"]
    )
    assert "scan_endpoint" in _kind_enum(md_tool)  # Defender kind offered
    assert "disable_user" in _kind_enum(md_tool)  # identity containment offered
    assert "collect_file" not in _kind_enum(md_tool)  # V1-only kind not offered
    v1_tool = manager_chat._propose_actions_tool(manager_chat._PROVIDER_ACTIONS["vision_one"])
    assert set(_kind_enum(v1_tool)) == set(manager_chat._VALID_ACTION_KINDS)


def test_build_revised_actions_defender_stamps_provider_and_filters():
    vocab = manager_chat._PROVIDER_ACTIONS["microsoft_defender"]
    actions = [
        {"kind": "isolate_host", "params": {"machine_id": "d1"}, "justification": "x"},
        {"kind": "scan_endpoint", "params": {"machine_id": "d1"}},
        {"kind": "blocklist_ioc", "params": {"indicator_type": "IpAddress", "value": "1.2.3.4"}},
        {"kind": "disable_user", "params": {"user_id": "obj-9"}},
        {"kind": "disable_user", "params": {}},  # no user_id → dropped
        {"kind": "isolate_host", "params": {}},  # no machine_id → dropped
        {
            "kind": "collect_file",
            "params": {"file_path": "/x", "endpoint_name": "h"},
        },  # V1 → dropped
    ]
    out = manager_chat._build_revised_actions(vocab, "microsoft_defender", actions)
    assert [a["kind"] for a in out] == [
        "isolate_host",
        "scan_endpoint",
        "blocklist_ioc",
        "disable_user",
    ]
    assert all(a["provider"] == "microsoft_defender" for a in out)  # stamped from incident
    assert [a["id"] for a in out] == ["act0", "act1", "act2", "act3"]  # renumbered, no gaps


def test_build_revised_actions_v1_keeps_v1_kinds():
    vocab = manager_chat._PROVIDER_ACTIONS["vision_one"]
    actions = [
        {"kind": "isolate_host", "params": {"endpoint_name": "h"}},
        {"kind": "scan_endpoint", "params": {"machine_id": "d1"}},  # not a V1 kind → dropped
        {"kind": "blocklist_ioc", "params": {"ioc_type": "ip", "value": "1.2.3.4"}},
    ]
    out = manager_chat._build_revised_actions(vocab, "vision_one", actions)
    assert [a["kind"] for a in out] == ["isolate_host", "blocklist_ioc"]
    assert all(a["provider"] == "vision_one" for a in out)
