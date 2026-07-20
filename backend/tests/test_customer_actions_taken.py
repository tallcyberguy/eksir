"""Customer notification — 'Actions we took' wiring (executed gate actions →
customer brief). Pure tests for the prompt + parser layer."""

from __future__ import annotations

from isoc_api.llm import customer_prompt


def _v1_actions():
    # Shape written by routes/cases.py::_run_proposed_actions
    return [
        {
            "action": "blocklist_ioc",
            "payload": {"value": "1.2.3.4", "ioc_type": "ip", "status": "executed"},
        },
        {"action": "isolate_host", "payload": {"endpoint_name": "FIN-WS-07", "status": "executed"}},
        {
            "action": "blocklist_ioc",
            "payload": {"value": "9.9.9.9", "status": "failed"},
        },  # excluded
    ]


def test_format_actions_taken_executed_only():
    lines = customer_prompt._format_actions_taken(_v1_actions())
    assert lines == ["- Blocked indicator: 1.2.3.4", "- Isolated host: FIN-WS-07"]
    # the failed one is not claimed
    assert all("9.9.9.9" not in line for line in lines)


def test_format_actions_taken_empty():
    assert customer_prompt._format_actions_taken([]) == []
    assert (
        customer_prompt._format_actions_taken([{"action": "x", "payload": {"status": "pending"}}])
        == []
    )


def test_build_user_prompt_includes_actions_taken_section():
    prompt = customer_prompt.build_user_prompt(
        case_number="CC-1",
        incident_case_number="CASE-1",
        incident_title="Phishing",
        customer_name="Acme",
        normalized={"rule_name": "x"},
        enrichment={"v1_actions": _v1_actions()},
        analyst_report_markdown=None,
    )
    assert "Actions already taken by the SOC" in prompt
    assert "Blocked indicator: 1.2.3.4" in prompt
    assert "Isolated host: FIN-WS-07" in prompt


def test_build_user_prompt_no_section_when_no_actions():
    prompt = customer_prompt.build_user_prompt(
        case_number="CC-1",
        incident_case_number="CASE-1",
        incident_title="Phishing",
        customer_name="Acme",
        normalized={"rule_name": "x"},
        enrichment={"v1_actions": []},
        analyst_report_markdown=None,
    )
    assert "Actions already taken by the SOC" not in prompt


def test_parse_llm_json_actions_taken_is_a_capped_list():
    text = (
        '{"title":"t","attack_type_label":"a","incident_analysis":"i",'
        '"critical_impact_summary":"c",'
        '"actions_taken":["Blocked the IP.","Isolated the host."],'
        '"recommended_actions":["Reset passwords."],'
        '"attribution":"","prior_cases_note":""}'
    )
    out = customer_prompt.parse_llm_json(text)
    assert out["actions_taken"] == ["Blocked the IP.", "Isolated the host."]
    assert out["recommended_actions"] == ["Reset passwords."]


def test_parse_llm_json_actions_taken_defaults_empty():
    text = (
        '{"title":"t","attack_type_label":"a","incident_analysis":"i",'
        '"critical_impact_summary":"c","recommended_actions":[],'
        '"attribution":"","prior_cases_note":""}'
    )
    out = customer_prompt.parse_llm_json(text)
    assert out["actions_taken"] == []  # absent → empty list, never a string
