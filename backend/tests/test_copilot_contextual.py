"""Unit tests for AI Copilot pure prompt building (`llm/contextual.py`)."""

from __future__ import annotations

import pytest

from isoc_api.llm import contextual


def test_available_actions_shape():
    acts = contextual.available_actions()
    keys = {a["key"] for a in acts}
    assert {"summarize", "next_steps", "explain"} <= keys
    for a in acts:
        assert a["scope"] in {"incident", "general"}
        assert set(a) == {"key", "label", "scope"}  # no system prompt leaked to clients


def test_incident_context_is_egress_safe_and_curated():
    ctx = contextual.incident_context(
        case_number="CASE-000042",
        title="Suspicious PowerShell",
        severity="high",
        verdict="PENDING",
        report="## Alert Analysis\nthe body",
        proposed_actions=["isolate_host", "tag"],
        ti_band="high",
        mitre=["T1059.001"],
    )
    assert "CASE-000042" in ctx
    assert "PENDING means no analyst decision" in ctx
    assert "isolate_host" in ctx
    assert "T1059.001" in ctx
    assert "the body" in ctx


def test_incident_context_truncates_long_report():
    ctx = contextual.incident_context(
        case_number="C",
        title="t",
        severity="low",
        verdict="PENDING",
        report="x" * 10000,
        max_report_chars=100,
    )
    assert "…(truncated)" in ctx


def test_build_prompt_incident_action_includes_guardrail_and_context():
    system, user = contextual.build_prompt("summarize", incident_ctx="## Incident C: t")
    assert "read-only" in system.lower()
    assert "do not issue verdicts" in system.lower() or "do not issue" in system.lower()
    assert "## Incident C: t" in user


def test_build_prompt_incident_action_requires_context():
    with pytest.raises(ValueError):
        contextual.build_prompt("summarize", incident_ctx=None)


def test_build_prompt_general_requires_question():
    with pytest.raises(ValueError):
        contextual.build_prompt("explain", question=None)
    system, user = contextual.build_prompt("explain", question="what is T1110?")
    assert "what is T1110?" in user


def test_build_prompt_unknown_action_raises():
    with pytest.raises(ValueError):
        contextual.build_prompt("delete_everything", question="x")


def test_question_appended_to_incident_context():
    _, user = contextual.build_prompt(
        "next_steps", incident_ctx="## Incident C: t", question="check lateral movement?"
    )
    assert "## Incident C: t" in user
    assert "check lateral movement?" in user
