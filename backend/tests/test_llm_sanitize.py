"""Regression test for the INC-001131 whitespace-degeneration failure (2026-07-08).

A near-greedy deep call locked into emitting spaces while padding a markdown
table, filling its 8192-token budget with ~128 KB of whitespace. The stored
report then rendered as an empty/broken section on the UI. ``sanitize_llm_text``
collapses that runaway repetition before the text is ever stored.
"""

from __future__ import annotations

from isoc_api.llm.client import sanitize_llm_text

# The exact shape seen live: a clean report head, then a runaway space loop.
_HEAD = (
    "## Alert Analysis — Possible OS Credential Dumping\n\n"
    "**Recommendation: TRUE POSITIVE** | Confidence: MEDIUM\n\n"
    "### Threat Details & Indicators (IOC/IOA)\n| Field | Value"
)


def test_collapses_runaway_space_loop():
    degenerate = _HEAD + " " * 127_000
    clean, changed = sanitize_llm_text(degenerate)
    assert changed is True
    assert len(clean) < 500  # 128 KB of spaces gone
    assert clean.endswith("| Field | Value")  # real content preserved, tail trimmed
    assert "  " * 20 not in clean


def test_collapses_runaway_char_loop():
    clean, changed = sanitize_llm_text("report body\n" + "-" * 5000)
    assert changed is True
    assert "-" * 100 not in clean
    assert clean.startswith("report body")


def test_collapses_runaway_blank_lines():
    clean, changed = sanitize_llm_text("a" + "\n" * 200 + "b")
    assert changed is True
    assert "\n" * 50 not in clean


def test_healthy_report_untouched():
    # A normal report — including a compact table and modest cell padding —
    # must pass through byte-for-byte (no false positives).
    report = (
        "## Alert Analysis — X\n\n**Recommendation: BENIGN** | Confidence: HIGH\n\n"
        "| Field | Value |\n|---|---|\n| Host  | CSV-04 |\n| Verdict | benign |\n\n"
        "### Risk Score\nLOW — sanctioned red-team activity.\n"
    )
    clean, changed = sanitize_llm_text(report)
    assert changed is False
    assert clean == report.rstrip()


def test_empty_is_safe():
    assert sanitize_llm_text("") == ("", False)
