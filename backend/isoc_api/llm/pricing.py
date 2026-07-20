"""LLM cost imputation for the Cost Dashboard.

`LLMCall.cost_usd` is NOT populated when a call is recorded, so the dashboard
prices the recorded token counts at read time against a public list-price table.

These are **estimates** (provider list prices, not billing-grade invoices) and
are labelled as such in the UI. Self-hosted/local models price at $0 — that's
the BYOK-savings story. Edit `_RATES` as model pricing changes; matching is by
family substring so version suffixes (`-2026..`, `-latest`) still resolve.
"""

from __future__ import annotations

# USD per 1,000,000 tokens, as (input, output). Order matters: more specific
# needles first (gpt-4o-mini before gpt-4o before gpt-4).
_RATES: tuple[tuple[str, tuple[float, float]], ...] = (
    # Anthropic Claude
    ("opus", (15.0, 75.0)),
    ("sonnet", (3.0, 15.0)),
    ("haiku", (0.80, 4.0)),
    # isoc virtual tiers (deep routes to Claude; priced as sonnet/haiku-ish)
    ("isoc-deep", (3.0, 15.0)),
    ("isoc-fast", (0.80, 4.0)),
    # OpenAI
    ("gpt-4o-mini", (0.15, 0.60)),
    ("gpt-4o", (2.50, 10.0)),
    ("gpt-4.1-mini", (0.40, 1.60)),
    ("gpt-4.1", (2.0, 8.0)),
    ("gpt-4", (30.0, 60.0)),
    ("gpt-3.5", (0.50, 1.50)),
    ("o1-mini", (1.10, 4.40)),
    ("o1", (15.0, 60.0)),
)

# Self-hosted families resolve to $0 (no per-token cost).
_LOCAL_FAMILIES = ("ollama", "llama", "vllm", "mistral", "qwen", "gemma", "phi", "local")

# Fallback for an unrecognized model — a conservative non-zero estimate.
_DEFAULT_RATE: tuple[float, float] = (1.0, 3.0)


def normalize_model(model: str | None) -> str:
    """Lowercase + drop any `provider/` prefix (e.g. `anthropic/claude-...`)."""
    return (model or "").lower().split("/")[-1].strip()


def rate_for(model: str | None) -> tuple[float, float]:
    """(input_per_1M, output_per_1M) USD for a model. Local → (0,0); unknown → default."""
    m = normalize_model(model)
    if not m:
        return _DEFAULT_RATE
    for fam in _LOCAL_FAMILIES:
        if fam in m:
            return (0.0, 0.0)
    for needle, rate in _RATES:
        if needle in m:
            return rate
    return _DEFAULT_RATE


def impute_cost_usd(
    model: str | None, input_tokens: int | None, output_tokens: int | None
) -> float:
    """Imputed USD cost for one call's recorded token counts. Never negative."""
    in_rate, out_rate = rate_for(model)
    in_tok = max(0, int(input_tokens or 0))
    out_tok = max(0, int(output_tokens or 0))
    return (in_tok / 1_000_000.0) * in_rate + (out_tok / 1_000_000.0) * out_rate


def is_local(model: str | None) -> bool:
    """True when the model is self-hosted (priced at $0) — drives BYOK savings."""
    return rate_for(model) == (0.0, 0.0)
