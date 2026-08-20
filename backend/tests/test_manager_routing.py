"""Guards on the manager's hunt-vs-forensics routing contract.

Background (INC-001152): an analyst asked the manager to "check the sign-in logs
for user X" and the manager called `run_forensics`, which is reasoning-only and has
no tools, so it truthfully answered "that data is not in the briefing" and no query
was ever run. An A/B against the live model reproduced it: the shipped tool
descriptions routed 5 of 7 analyst phrasings to the wrong agent; after stating the
capability boundary explicitly it was 7/7, stable over repeated runs.

Routing itself is a model decision and cannot be asserted here. What IS assertable,
and what actually broke, is the contract the prompts state:
  * run_forensics must declare that it cannot fetch data.
  * run_hunt must declare that it is the tool that queries telemetry.
  * every `live_search` state the prompt names must be one the code can emit;
    the prompt used to promise "no_v1_credentials", which `_hunt_live_state` never
    returns, so the manager could describe a state that does not exist.

Pure: no DB, no network, no model call.
"""

from __future__ import annotations

import re

from isoc_api.llm import prompts
from isoc_api.pipeline import manager_chat


def _tool(name: str) -> dict:
    for t in manager_chat.MANAGER_TOOLS:
        if t["function"]["name"] == name:
            return t["function"]
    raise AssertionError(f"{name} is not in MANAGER_TOOLS")


# ── the capability boundary must be stated on the tools themselves ──────────
def test_forensics_tool_declares_it_cannot_fetch_data():
    desc = _tool("run_forensics")["description"].lower()
    assert "cannot" in desc
    assert "no tools" in desc or "has no tools" in desc
    # It must point the model at the alternative, not just say "no".
    assert "run_hunt" in desc


def test_hunt_tool_declares_it_is_the_query_capable_agent():
    desc = _tool("run_hunt")["description"].lower()
    assert "quer" in desc  # query / queries
    assert "sign-in" in desc or "authentication" in desc
    # It must not describe itself as Vision-One-only: Defender hunting is wired
    # too (manager_chat._defender_hunt_tool), and naming one EDR taught the model
    # that a Defender incident had no live search.
    assert "defender" in desc


def test_both_edrs_are_named_so_neither_looks_unsupported():
    desc = _tool("run_hunt")["description"].lower()
    assert "defender" in desc and "vision one" in desc


# ── the system prompt must carry the routing rule ───────────────────────────
def test_system_prompt_states_the_routing_rule():
    sys = prompts.MANAGER_CHAT_SYSTEM
    assert "ROUTING RULE" in sys
    lower = sys.lower()
    # The decisive test the model should apply.
    assert "not already in the briefing" in lower
    # The specific failure mode that shipped, called out by name.
    assert "sign-in" in lower


def test_system_prompt_forbids_answering_data_unavailable_without_hunting():
    lower = prompts.MANAGER_CHAT_SYSTEM.lower()
    assert "not available" in lower or "unavailable" in lower
    assert "run_hunt" in lower


# ── prompt/code drift on live_search states ─────────────────────────────────
# The states _hunt_live_state + _run_hunt can actually produce.
EMITTED_STATES = {"executed", "available", "disabled_by_config", "no_credentials"}


def test_every_live_search_state_named_in_the_prompt_is_one_the_code_emits():
    """The regression: the prompt documented "no_v1_credentials", which no code
    path returns, so the manager could report a nonexistent state to the analyst."""
    # Digits matter: the stale string was "no_v1_credentials", so a [a-z_]+ class
    # silently skips the very token this test exists to catch.
    quoted = set(re.findall(r'"([a-z0-9_]+)"', prompts.MANAGER_CHAT_SYSTEM))
    # Only consider tokens that look like live_search states.
    named = {
        q
        for q in quoted
        if q in EMITTED_STATES or q.endswith("_credentials") or q.endswith("_config")
    }
    assert named, "the prompt should still describe the live_search states"
    unknown = named - EMITTED_STATES
    assert not unknown, f"prompt names live_search state(s) the code never emits: {unknown}"


def test_hunt_live_state_only_returns_documented_states(monkeypatch):
    """Pin the producer side, so adding a state without documenting it fails here."""
    for v1, defender in ((True, True), (True, False), (False, True), (False, False)):
        monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", v1)
        monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", defender)
        assert manager_chat._hunt_live_state(None, None) in EMITTED_STATES
    assert manager_chat._hunt_live_state(object(), None) == "available"
    assert manager_chat._hunt_live_state(None, object()) == "available"


def test_disabled_by_config_requires_both_providers_off(monkeypatch):
    """It says "disabled by config", so it must not fire when one EDR is enabled
    and merely lacks credentials, that is "no_credentials"."""
    monkeypatch.setattr(manager_chat.settings, "v1_activity_search_enabled", False)
    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", True)
    assert manager_chat._hunt_live_state(None, None) == "no_credentials"

    monkeypatch.setattr(manager_chat.settings, "defender_tools_enabled", False)
    assert manager_chat._hunt_live_state(None, None) == "disabled_by_config"
