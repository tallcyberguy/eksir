"""Hunt (3.13) — deterministic NL → threat-hunt-query translator.

v1 is TRANSLATE-ONLY: an analyst asks in plain English, we translate to the
dialects isoc's stack actually uses — **S1QL** (SentinelOne PowerQuery / Deep
Visibility), **KQL** (Microsoft Defender / Sentinel), and **Sigma** (portable
YAML). We do NOT execute the query (execution against SentinelOne is a deferred
fast-follow) and we NEVER write a verdict. The LLM call runs through
`llm.client.complete`, so the F3 egress contract applies.

Prompt building + the tolerant parse are pure + unit-tested; only `translate`
touches the LLM.
"""

from __future__ import annotations

from typing import Any

from ..pipeline.contracts import parse_json_block

LANGUAGES = ("s1ql", "kql", "sigma")
TIME_RANGES = ("1h", "4h", "24h", "7d", "30d")
DEFAULT_TIME_RANGE = "24h"

HUNT_SYSTEM = """You are a precise threat-hunting query translator for a SOC.
Translate the analyst's plain-English question into THREE read-only hunt queries:

- "s1ql":  SentinelOne PowerQuery (Deep Visibility) — the primary target.
- "kql":   Microsoft Defender / Sentinel KQL.
- "sigma": a portable Sigma detection rule (YAML).

Hard rules:
- READ-ONLY hunts only. Never emit a query that deletes, modifies, isolates, or
  takes any action — only searches/filters/aggregations.
- Respect the analyst's time range; default to the last 24 hours if unstated.
- Prefer specific field filters over broad wildcards; include a sensible result
  limit where the dialect supports it.
- If you cannot faithfully produce a dialect, return an empty string "" for it
  rather than guessing.
- "explanation": 1-3 sentences in plain English describing what the hunt looks
  for and any assumptions you made. Do not include raw log data.

Respond with ONE fenced ```json block and nothing else:
```json
{"s1ql": "...", "kql": "...", "sigma": "...", "explanation": "..."}
```"""


def build_translate_prompt(question: str, time_range: str | None) -> tuple[str, str]:
    """(system, user). Pure. `time_range` is normalized to a known window."""
    tr = time_range if time_range in TIME_RANGES else DEFAULT_TIME_RANGE
    user = f"Time range: last {tr}\n\nQuestion: {question.strip()}"
    return HUNT_SYSTEM, user


def parse_translation(text: str | None) -> dict[str, Any]:
    """Tolerant parse → always {s1ql, kql, sigma, explanation} as strings.
    Missing/garbage → empty strings (never raises)."""
    blob = parse_json_block(text) or {}
    out = {k: str(blob.get(k) or "").strip() for k in ("s1ql", "kql", "sigma", "explanation")}
    return out


def has_any_query(translated: dict[str, Any]) -> bool:
    return any(translated.get(k) for k in LANGUAGES)


async def translate(question: str, time_range: str | None = None) -> dict[str, Any]:
    """NL question → {s1ql, kql, sigma, explanation, time_range, status}. The only
    impure function — calls the LLM behind the F3 egress contract."""
    from ..llm.client import complete

    tr = time_range if time_range in TIME_RANGES else DEFAULT_TIME_RANGE
    system, user = build_translate_prompt(question, tr)
    result = await complete(system=system, user=user, max_tokens=900, temperature=0.0)

    if result.status != "ok":
        return {
            "s1ql": "",
            "kql": "",
            "sigma": "",
            "explanation": "",
            "time_range": tr,
            "status": result.status,
            "detail": "LLM unavailable or response blocked by the egress contract.",
        }
    parsed = parse_translation(result.text)
    parsed["time_range"] = tr
    parsed["status"] = "ok" if has_any_query(parsed) else "empty"
    parsed["model"] = result.model
    return parsed
