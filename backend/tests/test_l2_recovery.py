"""Regression tests for the two INC-001130 failures (2026-07-08).

1. A deep L2 report truncated before its ```json verdict block must still
   yield the report's verdict (not default to inconclusive).
2. The briefing must flag an asset_inventory KB hit that names a DIFFERENT host
   than the alert's resolved device (the CSV-03 vs CSV-Server conflation).
"""

from __future__ import annotations

from isoc_api.pipeline import contracts
from isoc_api.pipeline.briefing import render

# ── Fix #1: truncated L2 report -> verdict recovered from the markdown header ──
_TRUNCATED_REPORT = """## Alert Analysis — Possible OS Credential Dumping

**Recommendation: BENIGN** | Confidence: HIGH

### Summary
This alert triggered on CSV-03. A command like `& {write-host "x"}` ran, mapping
to T1003.001. The report keeps going and is then cut off before the json block
because the model ran out of output tokens...
"""


def test_truncated_report_recovers_verdict_not_inconclusive():
    # No fenced json block at all -> the strict parser finds nothing.
    assert contracts.parse_into(contracts.AnalysisVerdict, _TRUNCATED_REPORT) is None
    # …but parse_analysis_verdict recovers it from the markdown header.
    v = contracts.parse_analysis_verdict(_TRUNCATED_REPORT)
    assert v is not None
    assert v.verdict == "benign"
    assert v.confidence == "high"
    assert "T1003.001" in v.mitre_techniques  # pulled from the report body
    assert "recovered" in v.reasoning.lower()


def test_recovery_maps_all_recommendations():
    for header, expected in [
        ("**Recommendation: TRUE POSITIVE** | Confidence: MEDIUM", "true_positive"),
        ("**Recommendation: FALSE POSITIVE** | Confidence: LOW", "false_positive"),
        ("**Recommendation: BENIGN**", "benign"),
    ]:
        v = contracts.recover_analysis_verdict(f"## Alert Analysis\n\n{header}\n\n### Summary\nx")
        assert v is not None and v.verdict == expected


def test_full_json_block_still_preferred_over_markdown():
    text = (
        "## Alert Analysis\n\n**Recommendation: BENIGN** | Confidence: HIGH\n\n"
        '```json\n{"verdict": "true_positive", "confidence": "high"}\n```'
    )
    v = contracts.parse_analysis_verdict(text)
    assert v is not None and v.verdict == "true_positive"  # the JSON block wins


def test_no_verdict_anywhere_returns_none():
    assert contracts.parse_analysis_verdict("just some prose, no verdict") is None
    assert contracts.recover_analysis_verdict("") is None


# ── Fix #2: KB host-identity mismatch flag ────────────────────────────────────
_KB_ARGS = dict(
    autoclose_pre=None,
    autoclose_post=None,
    exact_match=None,
    n_way=None,
    similar=[],
    triage_results=[],
    ip_enrichments=[],
)


def test_kb_asset_for_different_host_is_flagged():
    out = render(
        normalized={"rule_name": "Possible OS Credential Dumping"},
        entities=[{"kind": "device", "value": "CSV-03", "role": None}],
        kb_hits=[
            {
                "title": "CSV-Server — authorized red-team endpoint",
                "type": "asset_inventory",
                "content": "CSV-Server is a SANCTIONED red-team host. Also seen as CSV-SERVER / csv-server. IP 192.168.10.4.",
                "tags": ["CSV-Server", "red-team", "allowlist"],
                "score": 1.0,
            }
        ],
        **_KB_ARGS,
    )
    assert "Host mismatch" in out
    assert "csv-03" in out.lower()


def test_kb_asset_naming_the_alert_host_is_not_flagged():
    out = render(
        normalized={"rule_name": "x"},
        entities=[{"kind": "device", "value": "CSV-03", "role": None}],
        kb_hits=[
            {
                "title": "CSV-03 — authorized red-team endpoint",
                "type": "asset_inventory",
                "content": "CSV-03 is a sanctioned red-team host.",
                "tags": ["CSV-03"],
                "score": 1.0,
            }
        ],
        **_KB_ARGS,
    )
    assert "Host mismatch" not in out


def test_non_asset_kb_and_no_entities_never_flag():
    out = render(
        normalized={"rule_name": "x"},
        entities=[{"kind": "device", "value": "CSV-03", "role": None}],
        kb_hits=[{"title": "Runbook", "type": "runbook", "content": "generic advice", "tags": []}],
        **_KB_ARGS,
    )
    assert "Host mismatch" not in out  # runbooks aren't host-scoped
