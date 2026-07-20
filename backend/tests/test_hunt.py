"""Unit tests for the Hunt NL→query translator pure core (`hunt/translate.py`)."""

from __future__ import annotations

from isoc_api.hunt import translate as t


def test_build_prompt_normalizes_time_range():
    system, user = t.build_translate_prompt("find powershell", "4h")
    assert "last 4h" in user
    assert "find powershell" in user
    assert "READ-ONLY" in system  # the safety rule is present
    # unknown range falls back to the default
    _, user2 = t.build_translate_prompt("x", "bogus")
    assert f"last {t.DEFAULT_TIME_RANGE}" in user2


def test_parse_translation_extracts_all_dialects():
    text = (
        "Here you go:\n```json\n"
        '{"s1ql": "EventType = \\"Process Creation\\"", "kql": "DeviceProcessEvents",'
        ' "sigma": "title: x", "explanation": "finds processes"}\n```'
    )
    out = t.parse_translation(text)
    assert out["s1ql"].startswith("EventType")
    assert out["kql"] == "DeviceProcessEvents"
    assert out["sigma"] == "title: x"
    assert out["explanation"] == "finds processes"


def test_parse_translation_tolerant_of_garbage():
    out = t.parse_translation("the model rambled with no json")
    assert out == {"s1ql": "", "kql": "", "sigma": "", "explanation": ""}
    assert t.parse_translation(None) == {"s1ql": "", "kql": "", "sigma": "", "explanation": ""}


def test_parse_translation_missing_dialect_is_empty_string():
    out = t.parse_translation('```json\n{"s1ql": "X", "explanation": "y"}\n```')
    assert out["s1ql"] == "X"
    assert out["kql"] == ""  # absent → empty string, never null
    assert out["sigma"] == ""


def test_has_any_query():
    assert t.has_any_query({"s1ql": "X", "kql": "", "sigma": ""}) is True
    assert t.has_any_query({"s1ql": "", "kql": "", "sigma": "", "explanation": "note"}) is False


def test_languages_and_ranges_are_known():
    assert t.LANGUAGES == ("s1ql", "kql", "sigma")
    assert t.DEFAULT_TIME_RANGE in t.TIME_RANGES
