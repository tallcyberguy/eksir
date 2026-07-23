"""Tests for the V1 Endpoint Activity Data search (analyst-triggered hunt tool).

Covers the adapter's nextLink pagination + header/param shaping, the creds-bound
dispatch handler (slimming + binding), and the manager-chat gating that keeps the
live search OFF unless the flag is on AND the customer has V1 creds.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from isoc_api.adapters import v1_adapter
from isoc_api.llm import tools as llm_tools
from isoc_api.pipeline import manager_chat


class _FakeGetClient:
    """Serves a fixed list of response bodies across successive GETs."""

    def __init__(self, pages: list[dict], capture: dict):
        self._pages = list(pages)
        self._capture = capture
        self._i = 0

    async def __aenter__(self) -> "_FakeGetClient":
        return self

    async def __aexit__(self, *_a) -> bool:
        return False

    async def get(self, url, params=None, headers=None):
        self._capture.setdefault("calls", []).append(
            {"url": url, "params": params, "headers": headers}
        )
        body = self._pages[self._i]
        self._i += 1
        return httpx.Response(200, json=body)


# ── adapter ──────────────────────────────────────────────────────────────────


async def test_get_endpoint_activity_follows_nextlink(monkeypatch):
    cap: dict = {}
    pages = [
        {
            "items": [{"a": 1}],
            "nextLink": "https://api.eu.xdr.trendmicro.com/v3.0/search/endpointActivities?skipToken=X",
        },
        {"items": [{"a": 2}]},
    ]
    monkeypatch.setattr(v1_adapter, "_client", lambda **_kw: _FakeGetClient(pages, cap))
    out = await v1_adapter.get_endpoint_activity(
        "endpointHostName:HOST", start="S", end="E", top=100, select="endpointHostName"
    )
    assert [r["a"] for r in out] == [1, 2]
    first = cap["calls"][0]
    assert first["url"] == "v3.0/search/endpointActivities"
    assert first["headers"]["TMV1-Query"] == "endpointHostName:HOST"
    assert first["params"]["startDateTime"] == "S"
    assert first["params"]["endDateTime"] == "E"
    assert first["params"]["top"] == 100
    assert first["params"]["select"] == "endpointHostName"
    # page 2 follows the absolute nextLink and re-sends the query header
    assert cap["calls"][1]["url"].endswith("skipToken=X")
    assert cap["calls"][1]["headers"]["TMV1-Query"] == "endpointHostName:HOST"


async def test_get_endpoint_activity_caps_records(monkeypatch):
    pages = [
        {"items": [{"a": i} for i in range(3)], "nextLink": "https://x/next"},
        {"items": [{"a": i} for i in range(3, 6)], "nextLink": "https://x/next2"},
    ]
    monkeypatch.setattr(v1_adapter, "_client", lambda **_kw: _FakeGetClient(pages, {}))
    out = await v1_adapter.get_endpoint_activity("q", max_records=4)
    assert len(out) == 4  # stops once the cap is reached, never fetches a 3rd page


async def test_get_endpoint_activity_requires_query():
    with pytest.raises(v1_adapter.VisionOneError, match="TMV1-Query"):
        await v1_adapter.get_endpoint_activity("")


# ── dispatch handler ─────────────────────────────────────────────────────────


async def test_activity_handler_slims_and_binds_creds(monkeypatch):
    seen: dict = {}

    async def _fake(query, *, start=None, end=None, top=50, select=None, **kw):
        seen.update(query=query, start=start, end=end, top=top, **kw)
        return [{"objectRawDataStr": "A" * 1000, "endpointHostName": "H"}]

    monkeypatch.setattr(llm_tools.v1_adapter, "get_endpoint_activity", _fake)
    creds = SimpleNamespace(region="eu", api_key="tok")  # pragma: allowlist secret
    handler = llm_tools.make_endpoint_activity_handler(creds, start="S", end="E", max_records=50)
    out = await handler({"query": "endpointHostName:H", "top": 100})

    assert out["count"] == 1
    rec = out["records"][0]
    assert rec["endpointHostName"] == "H"
    assert rec["objectRawDataStr"].endswith("…")  # oversized field truncated
    assert len(rec["objectRawDataStr"]) <= llm_tools._ACTIVITY_FIELD_TRUNC + 1
    # model args + bound creds/window flow through to the adapter
    assert seen["region"] == "eu"
    assert seen["api_key"] == "tok"  # pragma: allowlist secret
    assert seen["top"] == 100
    assert (seen["start"], seen["end"], seen["max_records"]) == ("S", "E", 50)


async def test_activity_handler_rejects_empty_query():
    creds = SimpleNamespace(region="eu", api_key="tok")  # pragma: allowlist secret
    handler = llm_tools.make_endpoint_activity_handler(creds)
    out = await handler({"query": "  "})
    assert "error" in out


async def test_activity_handler_appends_to_collector(monkeypatch):
    async def _fake(query, **kw):
        return [{"endpointHostName": "H"}]

    monkeypatch.setattr(llm_tools.v1_adapter, "get_endpoint_activity", _fake)
    collected: list = []
    handler = llm_tools.make_endpoint_activity_handler(
        SimpleNamespace(region="eu", api_key="t"),
        collector=collected,  # pragma: allowlist secret
    )
    await handler({"query": "endpointHostName:H"})
    assert collected[0]["query"] == "endpointHostName:H"
    assert collected[0]["count"] == 1
    assert collected[0]["records"][0]["endpointHostName"] == "H"


# ── contract + persistence ───────────────────────────────────────────────────


def test_huntresult_parses_affected_hosts():
    from isoc_api.pipeline import contracts

    txt = '```json\n{"spread_assessment":"lateral_confirmed","affected_hosts":["A","B"],"executed":true}\n```'
    hr = contracts.parse_into(contracts.HuntResult, txt)
    assert hr.affected_hosts == ["A", "B"]
    assert hr.executed is True


async def test_run_hunt_persists_evidence_and_count(monkeypatch):
    """A live hunt captures the matched records under enrichment.hunt_evidence and
    stamps a lean evidence_count onto stages.hunt for the UI/download button."""
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", True)

    async def _creds(provider, identifier=None):
        return SimpleNamespace(region="eu", api_key="tok")  # pragma: allowlist secret

    monkeypatch.setattr(manager_chat.integration_store, "get_creds", _creds)

    async def _activity(query, **kw):
        return [{"endpointHostName": "H2"}, {"endpointHostName": "H3"}]

    monkeypatch.setattr(manager_chat.llm_tools.v1_adapter, "get_endpoint_activity", _activity)

    # Silence the persona-stage bookkeeping + briefing/IOC helpers.
    async def _noop_start(session, inc, stage):
        return 0.0

    async def _noop_done(session, inc, stage, t0, display=""):
        return None

    monkeypatch.setattr(manager_chat, "_persona_stage_start", _noop_start)
    monkeypatch.setattr(manager_chat, "_persona_stage_done", _noop_done)
    monkeypatch.setattr(manager_chat, "_llm_call_row", lambda **kw: object())
    monkeypatch.setattr(manager_chat, "render_case_briefing", lambda inc: "brief")
    monkeypatch.setattr(manager_chat, "_hunt_iocs", lambda e: [])

    # complete_with_tools: simulate the model invoking the search once (fills the
    # collector), then returning a HuntResult.
    async def _cwt(*, system, user, tools, dispatch, model=None, gated=True, on_tool_call=None):
        await dispatch["get_endpoint_activity"]({"query": "endpointHostName:H2"})
        return SimpleNamespace(
            status="ok",
            text=(
                '```json\n{"spread_assessment":"lateral_confirmed","executed":true,'
                '"affected_hosts":["H2","H3"],"queries":[],"reasoning":"seen on H2,H3"}\n```'
            ),
        )

    monkeypatch.setattr(manager_chat, "complete_with_tools", _cwt)

    inc = SimpleNamespace(
        id="ID",
        customer="acme",
        normalized={"timestamp": "2026-07-01T12:00:00Z"},
        enrichment={},
    )
    session = SimpleNamespace(add=lambda x: None)
    out = await manager_chat._run_hunt(
        session, inc, {"verdict": "true_positive"}, instruction="check spread"
    )

    assert out["spread_assessment"] == "lateral_confirmed"
    assert out["live_search"] == "executed"  # ran live
    hunt = inc.enrichment["stages"]["hunt"]
    assert hunt["affected_hosts"] == ["H2", "H3"]
    assert hunt["evidence_count"] == 2
    ev = inc.enrichment["hunt_evidence"]
    assert ev[0]["count"] == 2 and len(ev[0]["records"]) == 2


async def test_run_hunt_reports_disabled_when_flag_off(monkeypatch):
    """With the live-search flag off, the hunter stages queries only and the
    run_hunt result tells the manager it's disabled (so it won't over-promise)."""
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", False)

    async def _noop_start(session, inc, stage):
        return 0.0

    async def _noop_done(session, inc, stage, t0, display=""):
        return None

    monkeypatch.setattr(manager_chat, "_persona_stage_start", _noop_start)
    monkeypatch.setattr(manager_chat, "_persona_stage_done", _noop_done)
    monkeypatch.setattr(manager_chat, "_llm_call_row", lambda **kw: object())
    monkeypatch.setattr(manager_chat, "render_case_briefing", lambda inc: "brief")
    monkeypatch.setattr(manager_chat, "_hunt_iocs", lambda e: [])

    async def _complete(**kw):
        return SimpleNamespace(
            status="ok",
            text='```json\n{"spread_assessment":"unknown","executed":false,"queries":[]}\n```',
        )

    monkeypatch.setattr(manager_chat, "complete", _complete)
    inc = SimpleNamespace(id="ID", customer="acme", normalized={}, enrichment={})
    out = await manager_chat._run_hunt(
        SimpleNamespace(add=lambda x: None), inc, {"verdict": "true_positive"}
    )
    assert out["live_search"] == "disabled_by_config"
    assert out["executed"] is False


# ── manager-chat gating (human-triggered only) ───────────────────────────────


async def test_hunt_activity_tool_off_by_flag(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", False)
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment={})
    assert await manager_chat._hunt_activity_tool(inc) is None


async def test_hunt_activity_tool_on_with_creds(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", True)

    async def _creds(provider, identifier=None):
        return SimpleNamespace(region="eu", api_key="tok")  # pragma: allowlist secret

    monkeypatch.setattr(manager_chat.integration_store, "get_creds", _creds)
    inc = SimpleNamespace(
        customer="acme", normalized={"timestamp": "2026-07-01T12:00:00Z"}, enrichment={}
    )
    live = await manager_chat._hunt_activity_tool(inc)
    assert live is not None
    tools_list, dispatch, system = live
    assert tools_list[0]["function"]["name"] == "get_endpoint_activity"
    assert "get_endpoint_activity" in dispatch
    assert system is manager_chat.prompts.HUNT_SYSTEM_LIVE


async def test_hunt_activity_tool_none_without_creds(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", True)

    async def _none(provider, identifier=None):
        return None

    monkeypatch.setattr(manager_chat.integration_store, "get_creds", _none)
    inc = SimpleNamespace(customer="acme", normalized={}, enrichment={})
    assert await manager_chat._hunt_activity_tool(inc) is None


def test_hunt_window_brackets_alert_time(monkeypatch):
    monkeypatch.setattr(manager_chat.settings, "v1_activity_window_hours", 24)
    inc = SimpleNamespace(enrichment={}, normalized={"timestamp": "2026-07-01T12:00:00Z"})
    assert manager_chat._hunt_window(inc) == ("2026-06-30T12:00:00Z", "2026-07-02T12:00:00Z")


def test_hunt_window_none_without_time():
    inc = SimpleNamespace(enrichment={}, normalized={})
    assert manager_chat._hunt_window(inc) == (None, None)
