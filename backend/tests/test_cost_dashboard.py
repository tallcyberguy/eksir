"""Cost Dashboard — pricing imputer + pure aggregation builder.

The DB-backed endpoint is validated on the stack; here we lock the pricing table
and the builder math (which is where the dashboard's correctness lives).
"""

from __future__ import annotations

from datetime import date

from isoc_api.llm import pricing
from isoc_api.routes.costs import build_dashboard

# ── pricing ───────────────────────────────────────────────────────────────


def test_rate_for_families():
    assert pricing.rate_for("claude-opus-4-8") == (15.0, 75.0)
    assert pricing.rate_for("anthropic/claude-sonnet-4-6") == (
        3.0,
        15.0,
    )  # provider prefix stripped
    assert pricing.rate_for("claude-haiku-4-5") == (0.80, 4.0)


def test_rate_for_ordering_mini_before_4o():
    assert pricing.rate_for("gpt-4o-mini") == (0.15, 0.60)
    assert pricing.rate_for("gpt-4o") == (2.50, 10.0)


def test_local_is_zero():
    assert pricing.rate_for("llama3.1:8b") == (0.0, 0.0)
    assert pricing.is_local("ollama/qwen2.5")
    assert not pricing.is_local("claude-opus-4-8")


def test_unknown_uses_default():
    assert pricing.rate_for("some-future-model-x") == (1.0, 3.0)


def test_isoc_virtual_tiers():
    assert pricing.rate_for("isoc-deep") == (3.0, 15.0)
    assert pricing.rate_for("isoc-fast") == (0.80, 4.0)


def test_impute_cost():
    # 1M input @ $15 + 1M output @ $75 = $90
    assert pricing.impute_cost_usd("claude-opus-4-8", 1_000_000, 1_000_000) == 90.0
    assert pricing.impute_cost_usd("llama3", 1_000_000, 1_000_000) == 0.0
    assert pricing.impute_cost_usd("claude-opus-4-8", None, None) == 0.0


def test_normalize_model():
    assert pricing.normalize_model("Anthropic/Claude-Opus") == "claude-opus"


# ── builder ─────────────────────────────────────────────────────────────


def _rows():
    return [
        {
            "day": date(2026, 6, 1),
            "model": "claude-opus-4-8",
            "input_tokens": 1_000_000,
            "output_tokens": 0,
            "calls": 2,
            "avg_latency_ms": 1000,
        },
        {
            "day": date(2026, 6, 1),
            "model": "llama3",
            "input_tokens": 1_000_000,
            "output_tokens": 1_000_000,
            "calls": 1,
            "avg_latency_ms": 500,
        },
        {
            "day": date(2026, 6, 2),
            "model": "claude-opus-4-8",
            "input_tokens": 0,
            "output_tokens": 1_000_000,
            "calls": 1,
            "avg_latency_ms": 2000,
        },
    ]


def _top():
    return [
        {
            "incident_id": "inc1",
            "model": "claude-opus-4-8",
            "input_tokens": 1_000_000,
            "output_tokens": 1_000_000,
            "calls": 3,
            "case_number": "CASE-1",
        },
        {
            "incident_id": "inc2",
            "model": "llama3",
            "input_tokens": 5_000_000,
            "output_tokens": 0,
            "calls": 2,
            "case_number": "CASE-2",
        },
    ]


def test_build_kpis():
    out = build_dashboard(_rows(), _top(), window_days=30)
    assert out["window_days"] == 30
    assert out["total_cost_usd"] == 90.0  # 15 + 0 + 75
    assert out["total_calls"] == 4
    assert out["total_input_tokens"] == 2_000_000
    assert out["total_output_tokens"] == 2_000_000
    assert out["total_tokens"] == 4_000_000
    assert out["avg_cost_per_call_usd"] == 22.5
    # local (llama) 1M in + 1M out priced at the sonnet reference (3/15) = 18
    assert out["byok_savings_usd"] == 18.0


def test_build_by_model_sorted_and_local_flag():
    out = build_dashboard(_rows(), _top(), window_days=30)
    by_model = out["by_model"]
    assert by_model[0]["model"] == "claude-opus-4-8"  # highest cost first
    assert by_model[0]["cost_usd"] == 90.0
    assert by_model[0]["calls"] == 3
    assert by_model[0]["is_local"] is False
    llama = next(m for m in by_model if m["model"] == "llama3")
    assert llama["cost_usd"] == 0.0 and llama["is_local"] is True


def test_build_by_day_sorted():
    out = build_dashboard(_rows(), _top(), window_days=30)
    days = out["by_day"]
    assert [d["day"] for d in days] == ["2026-06-01", "2026-06-02"]
    assert days[0]["cost_usd"] == 15.0 and days[0]["calls"] == 3
    assert days[1]["cost_usd"] == 75.0


def test_build_top_incidents():
    out = build_dashboard(_rows(), _top(), window_days=30)
    top = out["top_incidents"]
    assert top[0]["case_number"] == "CASE-1" and top[0]["cost_usd"] == 90.0
    assert top[1]["case_number"] == "CASE-2" and top[1]["cost_usd"] == 0.0


def test_build_empty():
    out = build_dashboard([], [], window_days=7)
    assert out["total_cost_usd"] == 0.0
    assert out["avg_cost_per_call_usd"] == 0.0
    assert out["by_model"] == [] and out["by_day"] == [] and out["top_incidents"] == []
