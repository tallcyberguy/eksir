"""Unit + regression tests for the LLM egress contract (F3).

Pure unit tests — no stack needed. The regression cases are the important ones:
they prove the *post-change* briefing (raw block removed) passes the Strict
contract, while a briefing that still carried a raw block would be blocked.
"""

from __future__ import annotations

import pytest

from isoc_api.llm import prompts
from isoc_api.llm.contract import (
    LLMContractViolation,
    classify_message,
    enforce_egress,
    validate_messages,
)
from isoc_api.pipeline import briefing

CAP = 60000


def _classify(text: str) -> str | None:
    return classify_message(text, max_chars=CAP)


# ── Blocks ────────────────────────────────────────────────────────────────


def test_blocks_openai_key():
    key = 'config api_key="sk-ABCDEF0123456789ABCDEF"'  # pragma: allowlist secret
    assert _classify(key) is not None


def test_blocks_pem_private_key():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIB...\n"  # pragma: allowlist secret
    assert _classify(pem) is not None


def test_blocks_oversize():
    assert classify_message("x" * (CAP + 1), max_chars=CAP) is not None


def test_blocks_sysmon_xml():
    xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">...'
    assert _classify(xml) is not None


def test_blocks_ocsf_json_object():
    assert _classify('{"class_uid": 1001, "activity_id": 1, "metadata": {}}') is not None


def test_blocks_event_batch_array():
    row = '{"EventID": 4624, "Channel": "Security", "Provider": "x", "RecordID": 1, "a": 1, "b": 2, "c": 3}'
    assert _classify(f"[{row},{row},{row}]") is not None


def test_blocks_splunk_envelope():
    assert (
        _classify('{"_raw": "Nov 1 host sshd: failed", "sourcetype": "linux_secure"}') is not None
    )


# ── Allows ────────────────────────────────────────────────────────────────


def test_allows_plain_markdown_report():
    md = "# SOC report\n\n## Verdict\n**true_positive** — credential access via T1110.\n"
    assert _classify(md) is None


def test_allows_mitre_and_iocs():
    assert _classify("Techniques: T1059.001, T1071. IOC: 8.8.8.8, evil.example.com") is None


@pytest.mark.parametrize(
    "system_prompt",
    [
        prompts.FAST_CLASSIFIER_SYSTEM,
        prompts.L2_SYSTEM,
        prompts.HUNT_SYSTEM,
        prompts.FORENSIC_SYSTEM,
        prompts.MANAGER_CHAT_SYSTEM,
    ],
)
def test_allows_persona_system_prompts(system_prompt):
    # If a persona system prompt itself tripped the contract, every synthesis
    # call would be blocked under enforce mode — so this must stay green.
    assert classify_message(str(system_prompt), max_chars=CAP) is None


# ── Regression: the briefing change is correct and necessary ──────────────


def _render_briefing(raw_value: str) -> str:
    """Render a minimal briefing whose normalized payload carries a log-ish
    `raw` value. After the F3 change, `raw` must NOT appear in the output."""
    normalized = {
        "source_product": "wazuh",
        "rule_name": "Multiple failed logins",
        "src_ip": "203.0.113.7",
        "username": "jdoe",
        "raw": raw_value,
    }
    return briefing.render(
        normalized=normalized,
        autoclose_pre=None,
        autoclose_post=None,
        exact_match=None,
        n_way=None,
        similar=[],
        kb_hits=[],
        triage_results=[],
        ip_enrichments=[],
    )


def test_post_change_briefing_passes_even_with_raw_logish_normalized():
    raw = '{"EventID": 4624, "Channel": "Security", "_raw": "raw evtx blob here"}'
    rendered = _render_briefing(raw)
    # The structured fields are present...
    assert "Multiple failed logins" in rendered
    # ...but the raw block is gone, so the contract passes.
    assert "### Raw" not in rendered
    assert _classify(rendered) is None


def test_briefing_with_raw_block_would_be_blocked():
    # Simulate the OLD briefing by appending the raw block back. This proves the
    # contract catches raw and that removing the block (§3.4) was required.
    raw = '{"EventID": 4624, "Channel": "Security", "_raw": "raw evtx blob"}'
    old_style = _render_briefing(raw) + "\n### Raw (truncated)\n```\n" + raw + "\n```\n"
    assert _classify(old_style) is not None


# ── Enforcement modes ─────────────────────────────────────────────────────

_SECRET_PROMPT = 'token="sk-LIVEKEY0123456789ABCD"'  # pragma: allowlist secret


def test_mode_off_never_blocks():
    assert enforce_egress(system="ok", user=_SECRET_PROMPT, mode="off") is None


def test_mode_report_logs_but_never_blocks():
    assert enforce_egress(system="ok", user=_SECRET_PROMPT, mode="report") is None


def test_mode_enforce_blocks_violation():
    reason = enforce_egress(system="ok", user=_SECRET_PROMPT, mode="enforce")
    assert reason is not None
    assert "user message" in reason


def test_mode_enforce_allows_clean():
    assert (
        enforce_egress(system="You are an analyst.", user="Summarize T1059.", mode="enforce")
        is None
    )


def test_enforce_checks_system_role_too():
    reason = enforce_egress(system=_SECRET_PROMPT, user="hello", mode="enforce")
    assert reason is not None
    assert "system message" in reason


# ── Reason strings never leak the secret ──────────────────────────────────


def test_secret_reason_does_not_leak_value():
    reason = _classify('password="hunter2hunter2hunter2"')  # pragma: allowlist secret
    assert reason is not None
    assert "hunter2" not in reason


# ── validate_messages raises ──────────────────────────────────────────────


def test_validate_messages_raises_on_violation():
    msgs = [
        {"role": "system", "content": "ok"},
        {
            "role": "user",
            "content": '{"class_uid": 1, "metadata": {"product": "x", "version": "1"}}',
        },
    ]
    with pytest.raises(LLMContractViolation):
        validate_messages(msgs, max_chars=CAP)


def test_validate_messages_passes_clean():
    validate_messages([{"role": "user", "content": "T1059 hunt please"}], max_chars=CAP)
