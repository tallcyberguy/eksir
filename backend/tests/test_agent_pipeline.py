"""Unit tests for the agent-persona pipeline:
  - contracts JSON parsing (tolerant, nested, last-block-wins)
  - agent_routing decisions + proposed-action building
  - orchestrator L1 mapping helper
  - cases gate helpers (_verdict_from_str, _run_proposed_actions)

Pure functions / mocked V1 — no live Qdrant, LiteLLM, or DB.
"""

from __future__ import annotations

import uuid as _uuid
from types import SimpleNamespace

from isoc_api.db.enums import Verdict
from isoc_api.llm import client as llm_client
from isoc_api.pipeline import agent_routing, contracts, manager_chat, orchestrator
from isoc_api.routes import cases

# ── contracts.parse_json_block / parse_into ─────────────────────────────────


def test_parse_json_block_fenced_with_prose():
    text = 'Here is my report.\n\n```json\n{"verdict": "benign"}\n```\n'
    assert contracts.parse_json_block(text) == {"verdict": "benign"}


def test_parse_json_block_balanced_nested():
    text = 'noise {"a": [{"b": 1}], "c": "has } brace"} trailing'
    assert contracts.parse_json_block(text) == {"a": [{"b": 1}], "c": "has } brace"}


def test_parse_json_block_last_fenced_wins():
    text = '```json\n{"v": 1}\n```\nmiddle\n```json\n{"v": 2}\n```'
    assert contracts.parse_json_block(text) == {"v": 2}


def test_parse_json_block_none():
    assert contracts.parse_json_block("no json at all") is None
    assert contracts.parse_json_block("") is None


def test_parse_into_analysis_verdict():
    text = (
        "## Alert Analysis\n**Recommendation: TRUE POSITIVE** | Confidence: HIGH\n\n"
        "```json\n"
        '{"verdict": "true_positive", "confidence": "high", '
        '"mitre_techniques": ["T1059"], "hunt_recommended": true, '
        '"hunt_focus": "lateral_movement", "reasoning": "x"}\n'
        "```\n"
    )
    av = contracts.parse_into(contracts.AnalysisVerdict, text)
    assert av is not None
    assert av.verdict == "true_positive"
    assert av.hunt_recommended is True
    assert av.hunt_focus == "lateral_movement"
    assert av.mitre_techniques == ["T1059"]


def test_parse_into_returns_none_on_no_json():
    assert contracts.parse_into(contracts.AnalysisVerdict, "prose only") is None


# ── agent_routing ───────────────────────────────────────────────────────────


def _triage(disp="needs_analysis"):
    return contracts.TriageResult(obvious_disposition=disp)


def test_escalate_obvious_fp_low_sev_no_malicious_does_not_escalate():
    assert agent_routing.should_escalate_to_l2(_triage("likely_fp"), {}, "low", "recon") is False


def test_escalate_needs_analysis():
    assert agent_routing.should_escalate_to_l2(_triage("needs_analysis"), {}, "low", "recon")


def test_escalate_on_malicious_ioc():
    enr = {"triage": [{"verdict": "malicious"}]}
    assert agent_routing.should_escalate_to_l2(_triage("likely_fp"), enr, "low", "recon")


def test_escalate_on_high_severity():
    assert agent_routing.should_escalate_to_l2(_triage("likely_fp"), {}, "critical", "recon")


def test_escalate_on_threat_category():
    assert agent_routing.should_escalate_to_l2(_triage("likely_fp"), {}, "low", "ransomware")


def test_should_hunt():
    assert agent_routing.should_hunt(
        contracts.AnalysisVerdict(verdict="true_positive", hunt_recommended=True)
    )
    assert not agent_routing.should_hunt(
        contracts.AnalysisVerdict(verdict="false_positive", hunt_recommended=True)
    )
    assert not agent_routing.should_hunt(
        contracts.AnalysisVerdict(verdict="true_positive", hunt_recommended=False)
    )


def test_should_run_forensics():
    inconclusive = contracts.AnalysisVerdict(verdict="inconclusive")
    tp = contracts.AnalysisVerdict(verdict="true_positive")
    assert agent_routing.should_run_forensics(inconclusive, None)
    assert agent_routing.should_run_forensics(
        tp, contracts.HuntResult(spread_assessment="lateral_confirmed")
    )
    assert not agent_routing.should_run_forensics(
        tp, contracts.HuntResult(spread_assessment="isolated")
    )


def test_map_verdict_to_isoc():
    assert agent_routing.map_verdict_to_isoc("true_positive") == "TP"
    assert agent_routing.map_verdict_to_isoc("false_positive") == "FP"
    assert agent_routing.map_verdict_to_isoc("benign") == "benign"
    assert agent_routing.map_verdict_to_isoc("garbage") == "pending"


def test_propose_actions_only_on_tp():
    fp = contracts.AnalysisVerdict(verdict="false_positive")
    enr = {"triage": [{"query": {"ioc": "1.2.3.4", "type": "ipv4"}, "verdict": "malicious"}]}
    assert agent_routing.propose_response_actions(fp, enr, {}) == []


def test_propose_actions_blocklist_and_isolate():
    tp = contracts.AnalysisVerdict(verdict="true_positive", hunt_focus="lateral_movement")
    enr = {
        "triage": [
            {"query": {"ioc": "1.2.3.4", "type": "ipv4"}, "verdict": "malicious"},
            {"query": {"ioc": "8.8.8.8", "type": "ipv4"}, "verdict": "clean"},
        ]
    }
    actions = agent_routing.propose_response_actions(tp, enr, {"hostname": "WS01"})
    kinds = [a.kind for a in actions]
    assert "blocklist_ioc" in kinds and "isolate_host" in kinds
    block = next(a for a in actions if a.kind == "blocklist_ioc")
    assert block.params["ioc_type"] == "ip" and block.params["value"] == "1.2.3.4"
    iso = next(a for a in actions if a.kind == "isolate_host")
    assert iso.params["endpoint_name"] == "WS01"


def test_propose_collect_file_only_when_hash_unknown():
    """collect_file is proposed only for a hash TI has never seen, and only when
    a path + endpoint exist so the action is runnable."""
    tp = contracts.AnalysisVerdict(verdict="true_positive")
    unknown = {"query": {"ioc": "a" * 64, "type": "sha256"}, "verdict": "clean_or_unknown"}

    # unknown hash + path + host → proposed with endpoint_name + file_path
    actions = agent_routing.propose_response_actions(
        tp, {"triage": [unknown]}, {"hostname": "WS01", "file_path": "C:/tmp/x.exe"}
    )
    collect = [a for a in actions if a.kind == "collect_file"]
    assert len(collect) == 1
    assert collect[0].params == {"file_path": "C:/tmp/x.exe", "endpoint_name": "WS01"}

    # known-malicious hash → block it, don't collect it
    known = {"query": {"ioc": "b" * 64, "type": "sha256"}, "verdict": "malicious"}
    actions = agent_routing.propose_response_actions(
        tp, {"triage": [known]}, {"hostname": "WS01", "file_path": "C:/tmp/x.exe"}
    )
    assert not any(a.kind == "collect_file" for a in actions)

    # unknown hash but no path → not runnable, so not proposed
    actions = agent_routing.propose_response_actions(
        tp, {"triage": [unknown]}, {"hostname": "WS01"}
    )
    assert not any(a.kind == "collect_file" for a in actions)


def test_propose_collect_file_prefers_v1_agent_guid():
    """When the V1 workbench enrichment carries the host agentGuid, the proposal
    uses it (FedRAMP-correct) alongside the hostname fallback."""
    tp = contracts.AnalysisVerdict(verdict="true_positive")
    enr = {
        "triage": [{"query": {"ioc": "a" * 40, "type": "sha1"}, "verdict": "unknown"}],
        "v1": {
            "workbench": {
                "impactScope": {
                    "entities": [{"type": "host", "value": {"name": "WS01", "guid": "GUID-1"}}]
                }
            }
        },
    }
    actions = agent_routing.propose_response_actions(
        tp, enr, {"hostname": "WS01", "file_path": "C:/tmp/x.exe"}
    )
    collect = next(a for a in actions if a.kind == "collect_file")
    assert collect.params["agent_guid"] == "GUID-1"
    assert collect.params["endpoint_name"] == "WS01"
    assert collect.params["file_path"] == "C:/tmp/x.exe"


# ── orchestrator helper ─────────────────────────────────────────────────────


def test_triage_result_from_fast():
    assert (
        orchestrator._triage_result_from_fast({"verdict": "FP", "confidence": "HIGH"}, "low")[
            "obvious_disposition"
        ]
        == "likely_fp"
    )
    assert (
        orchestrator._triage_result_from_fast({"verdict": "TP", "confidence": "LOW"}, "high")[
            "obvious_disposition"
        ]
        == "likely_tp"
    )
    assert (
        orchestrator._triage_result_from_fast({"verdict": "FP", "confidence": "MEDIUM"}, "low")[
            "obvious_disposition"
        ]
        == "needs_analysis"
    )


# ── cases gate helpers ──────────────────────────────────────────────────────


def test_verdict_from_str():
    assert cases._verdict_from_str("TP") == Verdict.TP
    assert cases._verdict_from_str("benign") == Verdict.BENIGN
    assert cases._verdict_from_str(None) == Verdict.PENDING
    assert cases._verdict_from_str("nonsense") == Verdict.PENDING


async def test_run_proposed_actions_executes_only_checked(monkeypatch):
    calls = []

    async def fake_blocklist(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    async def fake_get_creds_v1(*_a, **_k):
        return SimpleNamespace(api_key="k", region="eu", source="integration")

    monkeypatch.setattr(cases.integration_store, "get_creds_v1", fake_get_creds_v1)
    monkeypatch.setattr(cases.v1_adapter, "add_to_blocklist", fake_blocklist)

    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "blocklist_ioc",
                "params": {"ioc_type": "ip", "value": "1.2.3.4"},
                "justification": "bad",
                "status": "pending",
            },
            {
                "id": "act1",
                "kind": "blocklist_ioc",
                "params": {"ioc_type": "ip", "value": "9.9.9.9"},
                "justification": "bad",
                "status": "pending",
            },
        ]
    }
    inc = SimpleNamespace(enrichment=enrichment, customer="acme", normalized={})
    user = SimpleNamespace(email="a@x.io")

    executed = await cases._run_proposed_actions(None, inc, enrichment, ["act0"], user)

    assert len(calls) == 1 and calls[0]["value"] == "1.2.3.4"  # only act0 ran
    assert len(executed) == 1 and executed[0]["status"] == "executed"
    assert enrichment["proposed_actions"][0]["status"] == "executed"
    assert enrichment["proposed_actions"][1]["status"] == "pending"  # untouched
    assert len(enrichment["v1_actions"]) == 1


def test_create_case_action_shape():
    from isoc_api.pipeline import agent_routing

    a = agent_routing.create_case_action(3)
    assert a.kind == "create_case"
    assert a.id == "act3"
    assert a.params == {}
    assert a.autonomy == "review"  # → pre-checked at the gate (never escalate)
    assert a.blast_radius == "low"


async def test_run_proposed_actions_skips_create_case(monkeypatch):
    """The create_case nudge is handled in approve_incident, not the V1 executor —
    it must be skipped here (no V1 call, no 'unknown action kind' failure)."""
    calls = []

    async def fake_blocklist(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    async def fake_get_creds_v1(*_a, **_k):
        return SimpleNamespace(api_key="k", region="eu", source="integration")

    monkeypatch.setattr(cases.integration_store, "get_creds_v1", fake_get_creds_v1)
    monkeypatch.setattr(cases.v1_adapter, "add_to_blocklist", fake_blocklist)

    enrichment = {
        "proposed_actions": [
            {"id": "act0", "kind": "create_case", "params": {}, "status": "pending"},
        ]
    }
    inc = SimpleNamespace(enrichment=enrichment, customer="acme", normalized={})
    user = SimpleNamespace(email="a@x.io")

    executed = await cases._run_proposed_actions(None, inc, enrichment, ["act0"], user)

    assert calls == []  # no V1 call fired
    assert executed == []  # not handled here
    assert enrichment["proposed_actions"][0]["status"] == "pending"  # untouched by the executor


async def test_run_proposed_actions_records_failure(monkeypatch):
    async def no_creds(*_a, **_k):  # no V1 credentials configured for this customer
        return None

    monkeypatch.setattr(cases.integration_store, "get_creds_v1", no_creds)
    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "isolate_host",
                "params": {"endpoint_name": "WS01"},
                "justification": "tp",
                "status": "pending",
            },
        ]
    }
    inc = SimpleNamespace(enrichment=enrichment, customer="acme", normalized={})
    user = SimpleNamespace(email="a@x.io")

    executed = await cases._run_proposed_actions(None, inc, enrichment, ["act0"], user)

    assert executed[0]["status"] == "failed"  # degrades, does not raise
    assert enrichment["proposed_actions"][0]["status"] == "failed"


async def test_run_proposed_actions_207_item_failure_marks_failed(monkeypatch):
    """A per-item failure inside a V1 207 must NOT be recorded as executed."""

    async def _creds(*_a, **_k):
        return SimpleNamespace(region="eu", api_key="k", source="integration")

    async def _collect(**_k):
        return [{"status": 400, "body": {"error": {"message": "path not found"}}}]

    monkeypatch.setattr(cases.integration_store, "get_creds_v1", _creds)
    monkeypatch.setattr(cases.v1_adapter, "collect_file", _collect)
    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "collect_file",
                "params": {"file_path": "C:/x", "endpoint_name": "H"},
            }
        ]
    }
    inc = SimpleNamespace(enrichment=enrichment, customer="acme", normalized={})
    out = await cases._run_proposed_actions(
        None, inc, enrichment, ["act0"], SimpleNamespace(email="a@x.io")
    )
    assert out[0]["status"] == "failed"
    assert "path not found" in out[0]["error"]
    assert enrichment["proposed_actions"][0]["status"] == "failed"


async def test_run_proposed_actions_captures_task_id(monkeypatch):
    """A successful collect captures the V1 response-task id (for polling/download)."""

    async def _creds(*_a, **_k):
        return SimpleNamespace(region="eu", api_key="k", source="integration")

    async def _collect(**_k):
        return [
            {
                "status": 202,
                "headers": [{"name": "Operation-Location", "value": ".../v3.0/response/tasks/T-9"}],
            }
        ]

    monkeypatch.setattr(cases.integration_store, "get_creds_v1", _creds)
    monkeypatch.setattr(cases.v1_adapter, "collect_file", _collect)
    enrichment = {
        "proposed_actions": [
            {
                "id": "act0",
                "kind": "collect_file",
                "params": {"file_path": "C:/x", "endpoint_name": "H"},
            }
        ]
    }
    inc = SimpleNamespace(enrichment=enrichment, customer="acme", normalized={})
    out = await cases._run_proposed_actions(
        None, inc, enrichment, ["act0"], SimpleNamespace(email="a@x.io")
    )
    assert out[0]["status"] == "executed"
    assert out[0]["task_id"] == "T-9"
    assert enrichment["proposed_actions"][0]["task_id"] == "T-9"
    assert enrichment["v1_actions"][-1]["payload"]["task_id"] == "T-9"


def test_hunt_query_language_visionone_uses_tmv1():
    from isoc_api.llm import prompts

    for sp in ("visionone", "TrendMicro", "trend micro vision one"):
        lang = prompts.hunt_query_language(sp)
        assert "TMV1-Query" in lang and 'platform":"tmv1' in lang
    # non-V1 stacks keep the S1QL/Sigma/KQL menu, not TMV1
    other = prompts.hunt_query_language("sentinelone")
    assert "TMV1-Query" not in other and "s1ql" in other


def test_build_hunt_prompt_embeds_v1_query_language():
    from isoc_api.llm import prompts

    p = prompts.build_hunt_prompt("brief", {"hunt_focus": "c2"}, [], source_product="visionone")
    assert "## Query language" in p and "TMV1-Query" in p


def test_manager_valid_collect_params():
    assert manager_chat._valid_collect_params({"file_path": "C:/x", "endpoint_name": "H"})
    assert manager_chat._valid_collect_params({"file_path": "C:/x", "agent_guid": "G"})
    assert not manager_chat._valid_collect_params({"file_path": "\\", "endpoint_name": "H"})
    assert not manager_chat._valid_collect_params({"file_path": "   ", "endpoint_name": "H"})
    assert not manager_chat._valid_collect_params({"file_path": "C:/x"})  # no target


# ── manager chat (conversational gate) ──────────────────────────────────────


class _FakeSession:
    def add(self, *a, **k):
        pass

    async def flush(self):
        pass


def _fake_incident(enrichment):
    return SimpleNamespace(
        id=_uuid.uuid4(),
        case_number="CASE-X",
        rule_name="r",
        severity="high",
        normalized={},
        autoclose_match={},
        llm_report_markdown="report",
        enrichment=enrichment,
    )


def _ok(text):
    return llm_client.LLMResult(
        text=text,
        model="m",
        provider=None,
        input_tokens=1,
        output_tokens=1,
        latency_ms=0,
        prompt_hash="h",
        status="ok",
    )


async def test_complete_with_tools_gated_false_runs_tools_when_flag_off(monkeypatch):
    monkeypatch.setattr(llm_client.settings, "isoc_enable_llm_tools", False)
    seen: dict = {}

    async def fake_create(**kw):
        seen.update(kw)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="answer", tool_calls=None))],
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2),
            model="anthropic/claude",
        )

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create))
    )

    async def fake_resolve(model, max_tokens, temperature):
        return fake_client, "claude", 100, 0.2

    monkeypatch.setattr(llm_client, "_resolve_call", fake_resolve)

    out = await llm_client.complete_with_tools(
        system="s",
        user="u",
        tools=[{"type": "function", "function": {"name": "x"}}],
        dispatch={},
        gated=False,
    )
    assert out.text == "answer"
    assert "tools" in seen  # tool loop ran — did NOT fall back to plain complete()


async def test_manager_run_hunt_persists(monkeypatch):
    async def fake_complete(*, system, user, model, **kw):
        return _ok(
            '```json\n{"spread_assessment": "isolated", "queries": [{"platform": "s1ql", "query": "x"}]}\n```'
        )

    monkeypatch.setattr(manager_chat, "complete", fake_complete)
    inc = _fake_incident({"stages": {"l2": {"verdict": "true_positive"}}})

    out = await manager_chat._run_hunt(
        _FakeSession(),
        inc,
        {"verdict": "true_positive", "hunt_focus": "c2"},
        instruction="check beaconing",
    )

    assert out["spread_assessment"] == "isolated"
    assert inc.enrichment["stages"]["hunt"]["spread_assessment"] == "isolated"


async def test_manager_turn_dispatches_and_persists(monkeypatch):
    async def fake_cwt(**kw):
        # Simulate the manager calling the propose_actions tool, then replying.
        await kw["dispatch"]["propose_actions"](
            {
                "actions": [
                    {"kind": "blocklist_ioc", "params": {"ioc_type": "ip", "value": "5.5.5.5"}}
                ]
            }
        )
        return _ok("Swapped the block to 5.5.5.5.")

    monkeypatch.setattr(manager_chat, "complete_with_tools", fake_cwt)
    inc = _fake_incident(
        {"proposal": {"proposed_verdict": "TP"}, "proposed_actions": [], "stages": {}}
    )

    reply = await manager_chat.manager_turn(_FakeSession(), inc, "block 5.5.5.5 instead")

    assert reply == "Swapped the block to 5.5.5.5."
    assert inc.enrichment["proposed_actions"][0]["params"]["value"] == "5.5.5.5"
    chat = inc.enrichment["manager_chat"]
    assert chat[0]["role"] == "analyst" and chat[1]["role"] == "manager"
