"""Customer-facing notification prompt.

Different audience from the analyst report:
  • Reader is the customer's IT lead / business stakeholder, not a SOC analyst.
  • No tactical jargon, no MITRE technique IDs, no hunt queries.
  • Action-oriented: what to do, in priority order.
  • Localised: written in the case's locale (en/tr/de/...).

The LLM returns strict JSON so the HTML template (Phase-CC3) renders
deterministically. We parse defensively because models occasionally wrap
JSON in markdown code fences.
"""

from __future__ import annotations

import json
import re
from typing import Any

# ISO language code → human name. The model writes the body in this language.
_LOCALE_NAMES = {
    "en": "English",
    "tr": "Turkish (Türkçe)",
    "de": "German (Deutsch)",
    "fr": "French (Français)",
    "es": "Spanish (Español)",
}


def system_prompt(locale: str) -> str:
    lang = _LOCALE_NAMES.get(locale, "English")
    return f"""\
You are the EKSIR SOC team writing a customer-facing security notification.

Audience: the customer's IT or security lead. NOT another SOC analyst. They
need to understand WHAT happened, WHY it matters, and WHAT to do — without
SOC jargon, MITRE technique IDs, hunt-query syntax, or vendor-specific terms
unless absolutely necessary.

Language: write the body content in **{lang}**. Section labels themselves
are added by the template — you only produce the content.

Hard rules:
- NEVER invent IOCs, hostnames, users, or timestamps not present in the briefing.
- Base `attribution` ONLY on the Vision One detection, confirmed threat-intel
  feed hits, or the analyst verdict in the briefing. If none names a known
  actor/family, return an EMPTY attribution — do NOT guess a group from the
  attack type.
- Only state an action as DONE if it appears in the "Actions already taken by the
  SOC" section of the briefing — those are confirmed, executed actions. For anything
  not in that section, recommend; NEVER assert an action that isn't listed there.
- Tone is professional, clear, and reassuring — the SOC has it under control;
  here is what we observed and what they should do.
- Be concise. Soft word targets are guidance, not padding to hit.
- If the data is thin (low-quality alert, short-circuited case), say so honestly
  and recommend "monitor and report any related activity" rather than padding.
- The Threat Intelligence table (IOC value, location, VT score, domain) is
  rendered by the template from enrichment data — you do NOT paraphrase those
  facts. You only produce the 1-line attribution + 1-line prior-cases note
  that sit BELOW the table.

Return ONE JSON object with EXACTLY these keys (no others, no commentary):

{{
  "title":                    "<short headline, 80 chars max>",
  "attack_type_label":        "<short category, e.g. 'Brute-force authentication attempt'>",
  "incident_analysis":        "<what happened, in customer language. 2-5 sentences.>",
  "critical_impact_summary":  "<worst-case if unaddressed — what they stand to lose. Around 40 words. Be punchy, not exhaustive.>",
  "actions_taken":            ["<what the SOC already DID — ONLY restate items from the 'Actions already taken by the SOC' section, past tense, customer language. Empty array if that section is absent.>"],
  "recommended_actions":      ["<bullet 1 — ≤120 chars, imperative>", "<bullet 2>", "..."],
  "attribution":              "<≤100 chars: who/what is this attacker? E.g. 'TrickBot infrastructure cluster active since Mar 2026'. Empty string if unknown.>",
  "prior_cases_note":         "<≤100 chars: any history with this IOC or pattern. E.g. '3 related incidents in last 30 days'. Empty string if no prior data.>"
}}

Actions-taken rules (strict):
- ONLY include actions that appear in the "Actions already taken by the SOC"
  section of the briefing. NEVER invent one.
- If that section is absent or empty, return an EMPTY array — do not guess.
- Each ≤120 chars, PAST tense, customer language ("Blocked the malicious sender
  IP at the perimeter.", "Isolated the affected host from the network.").

Recommended-actions rules (strict):
- AT MOST 5 actions. Cut the least-urgent if you have more.
- Each action ≤120 characters. One sentence, imperative ("Reset…", "Block…",
  "Review…"). No preamble like "We recommend that you…".
- Prefix the most urgent items with "URGENT: " (max 1-2 urgent ones).

Output MUST be valid JSON. No markdown code fences, no preamble, no
explanation. If you cannot fill a field meaningfully, use an empty string
(or empty array for recommended_actions).
"""


# Human phrasing for the executed response-action kinds (ground truth from the
# gate). Used to brief the LLM so it can restate them in customer language.
_ACTION_VERB = {
    "blocklist_ioc": "Blocked indicator",
    "isolate_host": "Isolated host",
    "collect_file": "Collected file from host",
}


def _format_actions_taken(v1_actions: list[dict]) -> list[str]:
    """Render the EXECUTED gate actions into briefing bullets. Only `executed`
    entries (failed/skipped ones are not claimed). Pure + unit-tested."""
    lines: list[str] = []
    for a in v1_actions or []:
        if not isinstance(a, dict):
            continue
        payload = a.get("payload") or {}
        if payload.get("status") != "executed":
            continue
        kind = a.get("action") or "action"
        verb = _ACTION_VERB.get(kind, kind.replace("_", " "))
        target = (
            payload.get("value") or payload.get("endpoint_name") or payload.get("file_path") or ""
        )
        lines.append(f"- {verb}{(': ' + str(target)) if target else ''}".rstrip())
    return lines


def build_user_prompt(
    *,
    case_number: str,
    incident_case_number: str,
    incident_title: str | None,
    customer_name: str | None,
    normalized: dict[str, Any] | None,
    enrichment: dict[str, Any] | None,
    analyst_report_markdown: str | None,
) -> str:
    """Assemble the briefing the customer-prompt LLM sees."""
    parts: list[str] = []

    parts.append(f"## Case to write\n")
    parts.append(f"- Customer case number: `{case_number}`")
    parts.append(f"- Source incident: `{incident_case_number}`")
    if customer_name:
        parts.append(f"- Customer (tenant): {customer_name}")
    if incident_title:
        parts.append(f"- Incident title (analyst-side): {incident_title}")
    parts.append("")

    # Normalized alert — the structured truth
    if normalized:
        parts.append("## Normalized alert fields\n")
        for k in (
            "rule_name",
            "source_product",
            "severity_label",
            "threat_category",
            "src_ip",
            "dst_ip",
            "dst_port",
            "hostname",
            "username",
            "url",
            "cve",
            "mitre_technique",
            "timestamp",
        ):
            v = normalized.get(k)
            if v:
                parts.append(f"- **{k}**: {v}")
        parts.append("")

    # Enrichment summary — surface only the high-signal bits
    if enrichment:
        triage = enrichment.get("triage") or []
        if triage:
            parts.append("## Threat-intel triage results\n")
            for t in triage[:6]:
                ioc = t.get("ioc") or t.get("query")
                summ = t.get("summary") or {}
                hits = []
                if summ.get("vt_malicious"):
                    hits.append(f"VT={summ['vt_malicious']}")
                if summ.get("abuseipdb"):
                    hits.append(f"AbuseIPDB={summ['abuseipdb']}")
                if summ.get("otx_pulses"):
                    hits.append(f"OTX={summ['otx_pulses']}")
                if summ.get("urlhaus_url_count"):
                    hits.append(f"URLhaus={summ['urlhaus_url_count']}")
                line = f"- `{ioc}`"
                if hits:
                    line += "  →  " + ", ".join(hits)
                parts.append(line)
            parts.append("")
        ipinfo = enrichment.get("ipinfo") or []
        if ipinfo:
            parts.append("## Source-IP geolocation\n")
            for r in ipinfo[:3]:
                parts.append(
                    f"- `{r.get('ip')}` — {r.get('country') or '?'} / {r.get('org') or '?'}"
                )
            parts.append("")

        # P3 — confirmed-malicious context so attribution/analysis are grounded,
        # not pattern-matched from the attack type.
        wb = (enrichment.get("v1") or {}).get("workbench") or {}
        if wb:
            parts.append("## Vision One detection (authoritative vendor verdict)\n")
            if wb.get("model"):
                parts.append(f"- Detection model: {wb['model']}")
            if wb.get("score") is not None:
                parts.append(f"- Score: {wb['score']} — severity: {wb.get('severity') or '?'}")
            if wb.get("description"):
                parts.append(f"- Description: {str(wb['description'])[:300]}")
            ents = (wb.get("impactScope") or {}).get("entities") or []
            if ents:
                shown = []
                for e in ents[:6]:
                    val = e.get("value")
                    if isinstance(val, dict):
                        val = val.get("name") or val.get("ips")
                    shown.append(f"{e.get('type')}={val}")
                parts.append("- Impacted: " + "; ".join(str(s) for s in shown))
            inds = wb.get("indicators") or []
            if inds:
                parts.append("- Indicators (real, from the detection):")
                for ind in inds[:8]:
                    parts.append(
                        f"  - {ind.get('field') or ind.get('type')}: {str(ind.get('value'))[:160]}"
                    )
            parts.append("")

        ti_matches = enrichment.get("threat_intel_matches") or []
        if ti_matches:
            parts.append("## Confirmed threat-intel feed hits\n")
            for m in ti_matches[:6]:
                src = ", ".join(m.get("sources") or []) or "feed"
                parts.append(f"- `{m.get('value')}` ({m.get('ioc_type')}) — {src}")
            parts.append("")

        l2 = (enrichment.get("stages") or {}).get("l2") or {}
        if l2:
            parts.append("## Senior-analyst (L2) verdict\n")
            parts.append(
                f"- Verdict: {l2.get('verdict', '?')} (confidence {l2.get('confidence', '?')})"
            )
            techs = l2.get("mitre_techniques") or []
            if techs:
                parts.append(f"- MITRE techniques: {', '.join(map(str, techs))[:200]}")
            for step in (l2.get("attack_chain") or [])[:6]:
                if isinstance(step, dict):
                    parts.append(
                        f"  {step.get('step', '')}. {step.get('technique', '')} — {step.get('evidence', '')}"[
                            :200
                        ]
                    )
            if l2.get("reasoning"):
                parts.append(f"- Reasoning: {str(l2['reasoning'])[:400]}")
            parts.append("")

        # Response actions the analyst ACTUALLY executed at the gate (ground
        # truth — only these may be stated as 'done' to the customer).
        taken = _format_actions_taken(enrichment.get("v1_actions") or [])
        if taken:
            parts.append("## Actions already taken by the SOC\n")
            parts.append(
                "These were executed on the customer's behalf — you MAY state them as done:"
            )
            parts.extend(taken)
            parts.append("")

    # The analyst-side report — gives the LLM the verdict + reasoning to
    # paraphrase from. Critical context.
    if analyst_report_markdown:
        # Trim to keep prompt under control
        report = analyst_report_markdown.strip()
        if len(report) > 6000:
            report = report[:6000] + "\n\n[... analyst report truncated for length ...]"
        parts.append("## Analyst-side report (for reference — DO NOT paste verbatim)\n")
        parts.append(report)
        parts.append("")

    return "\n".join(parts)


# ── Defensive JSON parsing ──────────────────────────────────────────────

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?|\n?```\s*$", re.MULTILINE)

# Fields we expect the LLM to return; everything else is dropped.
# `threat_intel_summary` retained for back-compat with older saved cases;
# new generations don't emit it (the template renders a structured table
# instead). `attribution` + `prior_cases_note` are the new 1-liners that
# sit below that table.
EXPECTED_KEYS: tuple[str, ...] = (
    "title",
    "attack_type_label",
    "incident_analysis",
    "critical_impact_summary",
    "actions_taken",
    "recommended_actions",
    "attribution",
    "prior_cases_note",
    "threat_intel_summary",  # legacy; LLM no longer asked to produce it
)

# List-valued output keys — coerced to list[str] + capped.
_LIST_KEYS = {"recommended_actions", "actions_taken"}


def parse_llm_json(text: str) -> dict[str, Any]:
    """Extract the JSON object from the LLM's response.

    Models occasionally wrap output in markdown fences or add a one-line
    explanation before the JSON. We strip fences and find the first
    balanced `{...}` block to parse.

    Raises ValueError if no usable JSON object is found.
    """
    s = text.strip()
    if not s:
        raise ValueError("empty LLM response")

    # Strip ```json ... ``` style fences if present
    s = _CODE_FENCE_RE.sub("", s).strip()

    # If the model added preamble, find the first '{' and last '}'
    if not s.startswith("{"):
        start = s.find("{")
        if start == -1:
            raise ValueError("no JSON object in response")
        s = s[start:]
    if not s.endswith("}"):
        end = s.rfind("}")
        if end == -1:
            raise ValueError("unterminated JSON object")
        s = s[: end + 1]

    try:
        obj = json.loads(s)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e

    if not isinstance(obj, dict):
        raise ValueError("JSON top level is not an object")

    # Keep only expected keys; coerce types defensively.
    out: dict[str, Any] = {}
    for k in EXPECTED_KEYS:
        v = obj.get(k)
        if k in _LIST_KEYS:
            if isinstance(v, list):
                items = [str(x).strip() for x in v if str(x).strip()]
                # Hard cap at 6 — even if the LLM ignored the prompt rule.
                out[k] = items[:6]
            else:
                out[k] = []
        else:
            out[k] = str(v).strip() if v is not None else ""
    return out
