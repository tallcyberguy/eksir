"""Unit tests for the LLM tool surface:
  - adapters.store_adapter.lookup_ioc_history  (verdict aggregation)
  - llm.client.complete_with_tools             (flag gate + tool loop)

No live Qdrant / LiteLLM: the store and the OpenAI client are faked.
"""

from __future__ import annotations

from types import SimpleNamespace

from isoc_api.adapters import store_adapter
from isoc_api.llm import client as llm_client

# ── store_adapter.lookup_ioc_history ────────────────────────────────────────


class _FakeStore:
    def __init__(self, rows):
        self._rows = rows

    def search_ioc(self, indicator):  # sync, like the vendored store
        return list(self._rows)


async def test_lookup_ioc_history_aggregates_verdicts(monkeypatch):
    rows = [
        {
            "ioc_type": "ip",
            "ioc_value": "1.2.3.4",
            "alert_id": "a1",
            "customer": "acme",
            "rule_name": "r1",
            "timestamp": "2026-01-01T00:00:00Z",
            "verdict": "TP",
        },
        {
            "ioc_type": "ip",
            "ioc_value": "1.2.3.4",
            "alert_id": "a2",
            "customer": "acme",
            "rule_name": "r2",
            "timestamp": "2026-02-01T00:00:00Z",
            "verdict": "TP",
        },
        {
            "ioc_type": "ip",
            "ioc_value": "1.2.3.4",
            "alert_id": "a3",
            "customer": "globex",
            "rule_name": "r3",
            "timestamp": "2026-03-01T00:00:00Z",
            "verdict": "FP",
        },
    ]
    monkeypatch.setattr(store_adapter, "_store", lambda: _FakeStore(rows))

    out = await store_adapter.lookup_ioc_history("1.2.3.4")

    assert out["seen"] == 3
    assert out["verdicts"] == {"TP": 2, "FP": 1}
    assert out["customers"] == ["acme", "globex"]
    assert out["ioc_type"] == "ip"
    assert out["last_seen"] == "2026-03-01T00:00:00Z"  # newest first
    assert out["matches"][0]["alert_id"] == "a3"  # sorted desc by timestamp
    assert len(out["matches"]) == 3


async def test_lookup_ioc_history_empty(monkeypatch):
    monkeypatch.setattr(store_adapter, "_store", lambda: _FakeStore([]))
    out = await store_adapter.lookup_ioc_history("nope.example")
    assert out == {
        "indicator": "nope.example",
        "ioc_type": None,
        "seen": 0,
        "verdicts": {},
        "customers": [],
        "last_seen": None,
        "matches": [],
    }


async def test_lookup_ioc_history_blank_indicator():
    out = await store_adapter.lookup_ioc_history("   ")
    assert out["seen"] == 0 and out["matches"] == []


async def test_lookup_ioc_history_handles_store_error(monkeypatch):
    class _Boom:
        def search_ioc(self, indicator):
            raise RuntimeError("qdrant down")

    monkeypatch.setattr(store_adapter, "_store", lambda: _Boom())
    out = await store_adapter.lookup_ioc_history("1.2.3.4")
    assert out["seen"] == 0 and out["matches"] == []  # degrades, does not raise


# ── client.complete_with_tools ──────────────────────────────────────────────


def _msg(content=None, tool_calls=None):
    class _M:
        def __init__(self, content, tool_calls):
            self.content = content
            self.tool_calls = tool_calls

        def model_dump(self, exclude_none=False):
            d = {"role": "assistant", "content": self.content, "tool_calls": self.tool_calls}
            return {k: v for k, v in d.items() if v is not None} if exclude_none else d

    return _M(content, tool_calls)


def _resp(message, model="anthropic/claude-opus-4-8", pt=10, ct=5):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message)],
        usage=SimpleNamespace(prompt_tokens=pt, completion_tokens=ct),
        model=model,
    )


def _tool_call(call_id, name, arguments):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


async def test_complete_with_tools_disabled_falls_back(monkeypatch):
    monkeypatch.setattr(llm_client.settings, "isoc_enable_llm_tools", False)

    hits = {}

    async def fake_complete(*, system, user, model=None, max_tokens=None, temperature=None):
        hits["called"] = True
        return llm_client.LLMResult(
            text="plain",
            model="m",
            provider=None,
            input_tokens=1,
            output_tokens=1,
            latency_ms=0,
            prompt_hash="h",
            status="ok",
        )

    monkeypatch.setattr(llm_client, "complete", fake_complete)

    out = await llm_client.complete_with_tools(system="s", user="u", tools=[], dispatch={})
    assert hits.get("called") is True
    assert out.text == "plain"


async def test_complete_with_tools_executes_tool_call(monkeypatch):
    monkeypatch.setattr(llm_client.settings, "isoc_enable_llm_tools", True)

    responses = [
        _resp(
            _msg(tool_calls=[_tool_call("tc1", "lookup_ioc_history", '{"indicator": "1.2.3.4"}')]),
            pt=10,
            ct=5,
        ),
        _resp(_msg(content="final verdict text"), pt=20, ct=8),
    ]

    async def fake_create(**kwargs):
        return responses.pop(0)

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create))
    )

    async def fake_resolve(model, max_tokens, temperature):
        return fake_client, "claude-opus-4-8", 4096, 0.2

    monkeypatch.setattr(llm_client, "_resolve_call", fake_resolve)

    dispatched = {}

    async def fake_tool(args):
        dispatched["args"] = args
        return {"seen": 3, "verdicts": {"TP": 3}}

    out = await llm_client.complete_with_tools(
        system="s",
        user="u",
        tools=[{"type": "function", "function": {"name": "lookup_ioc_history"}}],
        dispatch={"lookup_ioc_history": fake_tool},
    )

    assert dispatched["args"] == {"indicator": "1.2.3.4"}  # parsed + dispatched
    assert out.text == "final verdict text"  # loop continued to answer
    assert out.status == "ok"
    assert out.input_tokens == 30  # 10 + 20 summed
    assert out.output_tokens == 13  # 5 + 8 summed
