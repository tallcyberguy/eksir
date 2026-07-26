"""Render the pre-LLM markdown briefing.

This is the *user prompt* sent to the LLM at synthesis. By doing all the
heavy formatting in Python (no LLM), we keep the LLM step focused on
synthesis + judgment, not parsing tool output.
"""

from __future__ import annotations

from typing import Any

# Hard caps on per-section item counts so a noisy multi-IOC alert can't balloon
# the prompt past a model's context window (an 8B/Ollama model with an 8k window
# silently drops the FRONT of the prompt — i.e. the system instructions — when
# overflowed) or run up token cost on a hosted model.
_MAX_KB_HITS = 8
_MAX_TRIAGE_BLOCKS = 20
_MAX_OAT_ROWS = 10


def _custom_note(ci: dict | None) -> str:
    """A compact note when an IOC is on the tenant's own custom allow/block list."""
    matches = (ci or {}).get("matches") or []
    if not matches:
        return ""
    actions = ",".join(sorted({str(m.get("action")) for m in matches if m.get("action")}))
    return f", custom-list={actions}" if actions else ", custom-list=listed"


def render(
    *,
    normalized: dict[str, Any],
    autoclose_pre: dict | None,
    autoclose_post: dict | None,
    exact_match: dict | None,
    n_way: dict | None,
    similar: list[dict],
    kb_hits: list[dict],
    triage_results: list[dict],
    ip_enrichments: list[dict],
    threat_intel_matches: list[dict] | None = None,
    excluded_iocs: list[dict] | None = None,
    fast_classifier: dict | None = None,
    temporal: dict | None = None,
    sensitive: dict | None = None,
    deobfuscation: dict | None = None,
    v1_enrichment: dict | None = None,
    entities: list[dict] | None = None,
    cluster: dict | None = None,
    ms_reputation: dict | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# Pre-synthesis briefing")
    lines.append("")
    lines.append("## Normalized alert")
    for k in (
        "source_product",
        "customer",
        "rule_name",
        "src_ip",
        "dst_ip",
        "dst_port",
        "username",
        "timestamp",
        "application",
        "url",
        "http_method",
        "http_status",
        "user_agent",
        "url_category",
        "src_zone",
        "dst_zone",
        "action",
    ):
        v = normalized.get(k)
        if v:
            lines.append(f"- **{k}**: {v}")
    lines.append("")

    # Resolved entities — deterministic OCSF-shaped device/user/network/file/
    # observable candidates from _step_entities. Gives the LLM the canonical
    # actors in this alert without re-parsing the normalized fields.
    if entities:
        lines.append("## Entities")
        for e in entities[:20]:
            role = e.get("role")
            suffix = f" ({role})" if role else ""
            # Prior entity risk = confirmed-TP history from EARLIER incidents,
            # decayed. Strong prior context for the verdict — surface it loudly.
            risk = e.get("risk")
            if risk is not None:
                suffix += f" — ⚠ prior entity risk **{risk}/100** (confirmed-TP history)"
            lines.append(f"- **{e.get('kind', '?')}**: `{e.get('value', '?')}`{suffix}")
        lines.append("")

    # Correlation — grouped with related same-tenant incidents sharing a strong
    # entity within the window (from _step_correlate). Signals a coordinated
    # multi-incident pattern (a campaign / one host spraying) worth weighing.
    if cluster and int(cluster.get("member_count") or 0) > 1:
        lines.append("## Correlation")
        lines.append(
            f"- Part of a **cluster of {cluster['member_count']} related incidents** (same "
            f"tenant, sharing a strong entity within the correlation window). A coordinated "
            f"multi-incident pattern; weigh it in the verdict and severity."
        )
        lines.append("")

    # NOTE (F3 egress contract, Strict policy): the raw alert excerpt that used
    # to be rendered here was REMOVED so no raw OCSF/log text reaches the LLM.
    # Personas now rely on the structured fields above; if a thinly-normalized
    # source needs more, enrich the normalizer — do NOT re-add raw here.

    # Temporal context — surfaced as its own section so the LLM weighs it.
    if temporal:
        emphasis = "🚩 " if not temporal.get("is_business_hours") else ""
        lines.append(f"## {emphasis}Temporal context")
        lines.append(f"- Local timestamp: `{temporal.get('local_iso')}`")
        lines.append(
            f"- Local hour: **{temporal.get('local_hour')}:00** ({temporal.get('weekday')})"
        )
        cat = temporal.get("category")
        if not temporal.get("is_business_hours"):
            lines.append(
                f"- **Outside business hours** (category: `{cat}`). "
                f"Authn / admin / privileged activity at this hour deserves extra scrutiny."
            )
        else:
            lines.append(f"- Within business hours (category: `{cat}`).")
        lines.append("")

    # Sensitive-rule flag — if matched, tell the LLM this is the must-analyse class.
    if sensitive and sensitive.get("matched"):
        lines.append("## 🚨 Sensitive rule pattern matched")
        lines.append(f"- Triggered keyword: `{sensitive.get('keyword')}`")
        lines.append("- This rule class has low FP/benign base rates. Auto-close /")
        lines.append("  fast-tier short-circuit is **disabled** for this incident — your")
        lines.append("  judgement is required regardless of how routine the surface details look.")
        lines.append("")

    # Auto-close
    if autoclose_pre or autoclose_post:
        lines.append("## Auto-close YAML")
        if autoclose_pre:
            lines.append(
                f"- Pre-enrichment match: `{autoclose_pre.get('rule_id')}` → {autoclose_pre.get('verdict')} — {autoclose_pre.get('reason')}"
            )
        if autoclose_post:
            lines.append(
                f"- Post-enrichment match: `{autoclose_post.get('rule_id')}` → {autoclose_post.get('verdict')} — {autoclose_post.get('reason')}"
            )
        lines.append("")

    # Exact match / N-way
    if exact_match:
        lines.append("## Exact-match (Vector DB)")
        lines.append(f"- alert_id: `{exact_match.get('alert_id')}`")
        lines.append(f"- cosine: {exact_match.get('score')}")
        lines.append(f"- prior verdict: **{exact_match.get('verdict')}**")
        reason = (exact_match.get("verdict_reason") or "")[:1500]
        lines.append(f"- reason: {reason}")
        lines.append("")

    if n_way:
        lines.append("## N-way agreement (Vector DB)")
        lines.append(f"- agreement: {n_way.get('agreement')} → **{n_way.get('verdict')}**")
        for m in (n_way.get("matches") or [])[:5]:
            sim = m.get("cosine")
            sim_str = f"{sim:.3f}" if isinstance(sim, (int, float)) else "?"
            lines.append(f"  - {m.get('alert_id')} (cosine {sim_str}, verdict {m.get('verdict')})")
        lines.append("")

    # Similar cases — up to 10 (full retrieval depth from Qdrant).
    # Skipped if exact_match already gave us a high-conviction prior.
    if similar and not exact_match:
        lines.append(f"## Similar cases (top {len(similar)})")
        for s in similar:
            sim = s.get("cosine")
            score_str = f"{sim:.3f}" if isinstance(sim, (int, float)) else "?"
            verified = " ✓verified" if s.get("human_verified") else ""
            lines.append(
                f"- `{s.get('alert_id')}` — verdict **{s.get('verdict')}**, "
                f"cosine {score_str}{verified}"
            )
            r = (s.get("verdict_reason") or "")[:400]
            if r:
                lines.append(f"  - {r}")
        lines.append("")

    # Local threat-intel feed match (severity has already been bumped one notch
    # by the pipeline; this section tells the LLM *which* IOCs matched).
    if threat_intel_matches:
        lines.append("## Local threat-intel feed match")
        # Strongest match drives the overall confidence band (corroboration across
        # feeds + recency + match kind — see threat_intel/scoring.py).
        top = max((m.get("score") or 0.0) for m in threat_intel_matches)
        top_band = next(
            (m.get("band") for m in threat_intel_matches if (m.get("score") or 0.0) == top), "low"
        )
        lines.append(
            f"_{len(threat_intel_matches)} extracted IOC(s) appear in the local feed DB — "
            f"**{top_band} confidence** (strongest score {top:.2f}). Weigh weak/stale single-feed "
            f"hits accordingly; do not treat every match as equally damning._"
        )
        for m in threat_intel_matches[:15]:
            sources = m.get("sources") or []
            src_count = len(sources)
            last_seen = (m.get("last_seen_at") or "")[:10]
            kind = m.get("match_kind") or "exact"
            band = m.get("band")
            score = m.get("score")
            badge = f" — _{band} {score:.2f}_" if band and score is not None else ""
            lines.append(
                f"- **{m.get('ioc_type', '?')}** `{m.get('value', '?')}` ({kind}) — "
                f"in {src_count} feed{'s' if src_count != 1 else ''}"
                f"{f', last seen {last_seen}' if last_seen else ''}{badge}"
            )
        lines.append("")

    # Deobfuscated payloads — decoded encoded blobs + heuristic obfuscation
    # score. Decoded IOCs are already merged into the triage set above; this
    # section shows the LLM the decoded content and which IOCs it surfaced so
    # the report can explain the payload and is allowed to cite those IOCs.
    if deobfuscation:
        obf = deobfuscation.get("obfuscation") or {}
        artifacts = deobfuscation.get("artifacts") or []
        decoded_iocs = deobfuscation.get("decoded_iocs") or []
        lines.append("## Deobfuscated payloads & signature analysis")
        lines.append(
            f"_Heuristic obfuscation score **{obf.get('score', 0)}** "
            f"(**{obf.get('band', 'n/a')}**) — symbol-density + marker + entropy blend, "
            f"not an ML verdict. {obf.get('encoded_layers', 0)} encoded layer(s) decoded._"
        )
        for a in artifacts[:10]:
            snippet = (a.get("snippet") or "").replace("`", "'").replace("\n", " ")
            lines.append(
                f"- **{a.get('encoding', '?')}** (layer {a.get('layer', '?')}, "
                f"{a.get('size', '?')} bytes, from `{a.get('source_field', '?')}`): "
                f"`{snippet}`"
            )
        new_iocs = [d for d in decoded_iocs if d.get("new")]
        if new_iocs:
            lines.append("")
            lines.append(f"_IOCs surfaced ONLY after decoding ({len(new_iocs)}):_")
            for d in new_iocs[:20]:
                lines.append(
                    f"- **{d.get('type', '?')}** `{d.get('value', '?')}` "
                    f"(from {d.get('encoding', '?')} payload)"
                )
        # YARA matches against decoded payloads (populated by the worker scan).
        yara = deobfuscation.get("yara_matches") or []
        if yara:
            lines.append("")
            lines.append(f"_YARA-Forge matches on decoded payloads ({len(yara)}):_")
            for y in yara[:20]:
                lines.append(f"- `{y.get('rule', '?')}` ({y.get('namespace', '?')})")
        lines.append("")

    # Vision One Workbench detail (+ optional OAT) — fetched read-only at enrich.
    # This is the rich evidence the alert email omits: real command lines, hashes,
    # impact scope, and MITRE techniques pulled straight from the V1 API.
    if v1_enrichment:
        wb = v1_enrichment.get("workbench") or {}
        lines.append("## Vision One Workbench detail")
        meta_bits = []
        if wb.get("model"):
            meta_bits.append(f"model **{wb['model']}**")
        if wb.get("score") is not None:
            meta_bits.append(f"score {wb['score']}")
        if wb.get("severity"):
            meta_bits.append(f"severity {wb['severity']}")
        if wb.get("status"):
            meta_bits.append(f"status {wb['status']} / {wb.get('investigationResult', '?')}")
        if meta_bits:
            lines.append("- " + " · ".join(meta_bits))
        if v1_enrichment.get("workbench_id"):
            lines.append(
                f"- workbench id: `{v1_enrichment['workbench_id']}` "
                f"(region {v1_enrichment.get('region', '?')})"
            )
        if wb.get("description"):
            lines.append(f"- {wb['description']}")
        mitre = wb.get("mitreTechniqueIds") or []
        if mitre:
            lines.append(f"- MITRE techniques: {', '.join(mitre)}")
        ents = (wb.get("impactScope") or {}).get("entities") or []
        if ents:
            lines.append("- Impact scope:")
            for e in ents[:10]:
                v = e.get("value")
                if isinstance(v, dict):
                    ips = ", ".join(v.get("ips") or [])
                    lines.append(
                        f"  - {e.get('type')}: {v.get('name')}{f' ({ips})' if ips else ''}"
                    )
                else:
                    lines.append(f"  - {e.get('type')}: {v}")
        inds = wb.get("indicators") or []
        if inds:
            lines.append("- Indicators (command lines / hashes / paths):")
            for ind in inds[:20]:
                field = ind.get("field") or ind.get("type") or "?"
                val = str(ind.get("value") or "").replace("\n", " ")
                lines.append(f"  - `{field}`: {val}")
        oat = v1_enrichment.get("oat") or []
        if oat:
            lines.append(f"### Observed Attack Techniques (top {min(len(oat), _MAX_OAT_ROWS)})")
            for o in oat[:_MAX_OAT_ROWS]:
                techs = ", ".join(o.get("mitreTechniqueIds") or [])
                lines.append(
                    f"- **{o.get('name', '?')}** ({o.get('riskLevel', '?')})"
                    f"{f' — {techs}' if techs else ''}"
                )
                for h in (o.get("highlighted") or [])[:2]:
                    hv = str(h.get("value") or "").replace("\n", " ")
                    lines.append(f"    - {h.get('field')}: {hv}")
        elif v1_enrichment.get("oat_error"):
            lines.append(f"- _OAT fetch failed: {v1_enrichment['oat_error']}_")
        lines.append("")

    # Excluded IOCs — the analyst-curated allowlist filtered these from triage.
    # The LLM is told explicitly so it doesn't go hunting for IOCs it can't see.
    if excluded_iocs:
        lines.append("## Excluded IOCs (allowlisted)")
        lines.append(
            "_These were extracted but skipped per the exclusion DB. "
            "Treat as known-good unless other evidence contradicts._"
        )
        for e in excluded_iocs[:20]:
            reason = e.get("reason") or "exclusion rule"
            lines.append(f"- **{e.get('ioc_type', '?')}** `{e.get('value', '?')}` — _{reason}_")
        lines.append("")

    # KB hits — show content snippet, not just title (was a black box before).
    if kb_hits:
        # Short host names of THIS alert's resolved device entities — used to
        # catch asset-record conflation (a semantically-similar KB asset like
        # "CSV-Server" being applied to a different host "CSV-03").
        alert_hosts = [
            str(e.get("value", "")).strip().lower()
            for e in (entities or [])
            if e.get("kind") == "device" and e.get("value")
        ]
        shown_kb = kb_hits[:_MAX_KB_HITS]
        suffix = (
            f" (showing {_MAX_KB_HITS} of {len(kb_hits)})" if len(kb_hits) > _MAX_KB_HITS else ""
        )
        lines.append(f"## Knowledge Base hits{suffix}")
        for k in shown_kb:
            title = k.get("title") or "(untitled)"
            kb_type = k.get("type") or k.get("entry_type") or "?"
            score = k.get("score")
            score_str = f" (score {score:.3f})" if isinstance(score, (int, float)) else ""
            lines.append(f"### {title} — *{kb_type}*{score_str}")
            content = (k.get("content") or "").strip()
            tags = k.get("tags") or []
            if content:
                snippet = content[:400].replace("\n", " ")
                if len(content) > 400:
                    snippet += "…"
                lines.append(f"  {snippet}")
            if tags:
                lines.append(f"  _tags: {', '.join(str(t) for t in tags[:8])}_")
            # Host-identity guard: an asset_inventory record applies to ONE host.
            # If it names none of this alert's resolved hosts, it's a different
            # machine — the LLM must not inherit its authorization/allowlist.
            if kb_type == "asset_inventory" and alert_hosts:
                haystack = f"{title} {content} {' '.join(str(t) for t in tags)}".lower()
                if not any(h in haystack for h in alert_hosts):
                    lines.append(
                        f"  ⚠ **Host mismatch:** this asset record does NOT name the alert host "
                        f"(`{'`, `'.join(alert_hosts)}`) — it describes a DIFFERENT machine. Do "
                        f"NOT apply its authorized/allowlisted status to this alert."
                    )
        lines.append("")

    # Fast-classifier verdict (only set when the two-tier LLM ran and didn't
    # short-circuit). Deep model sees this as prior reasoning to validate or refute.
    if fast_classifier:
        lines.append("## Prior fast-tier classification")
        lines.append(f"- verdict: **{fast_classifier.get('verdict', '?')}**")
        lines.append(f"- confidence: **{fast_classifier.get('confidence', '?')}**")
        reason = (fast_classifier.get("reason") or "").strip()
        if reason:
            lines.append(f"- reasoning: {reason}")
        lines.append("")

    # Triage TI
    if triage_results:
        shown_triage = triage_results[:_MAX_TRIAGE_BLOCKS]
        suffix = (
            f" (showing {_MAX_TRIAGE_BLOCKS} of {len(triage_results)})"
            if len(triage_results) > _MAX_TRIAGE_BLOCKS
            else ""
        )
        lines.append(f"## Threat Intelligence (triage){suffix}")
        for r in shown_triage:
            if not isinstance(r, dict):
                continue
            # `query` may be a string (the IOC value) or a dict {ioc, type}.
            q = r.get("query")
            ioc_value = q.get("ioc") if isinstance(q, dict) else (q or "?")
            ioc_type = (q.get("type") if isinstance(q, dict) else None) or r.get("type") or "?"
            lines.append(f"### {ioc_type}: `{ioc_value}`")

            verdict = r.get("verdict", "?")
            conf = r.get("confidence", "?")
            lines.append(f"- verdict: **{verdict}** (confidence: {conf})")

            summary = r.get("summary")
            if isinstance(summary, dict):
                for k, v in summary.items():
                    if isinstance(v, (list, tuple)):
                        v = ", ".join(str(x) for x in v[:8])
                    lines.append(f"- {k}: {v}")

            hostnames = r.get("hostnames") or []
            if isinstance(hostnames, list) and hostnames:
                lines.append("- hostnames:")
                for h in hostnames[:8]:
                    if isinstance(h, dict):
                        name = h.get("hostname") or h.get("name") or ""
                    else:
                        name = str(h)
                    if name:
                        lines.append(f"  - {name}")

            # behaviour_summary lives inside the VirusTotal source, not at top level.
            sources = r.get("sources") if isinstance(r.get("sources"), list) else []
            beh = None
            for s in sources:
                if (
                    isinstance(s, dict)
                    and s.get("source") == "virustotal"
                    and s.get("behaviour_summary")
                ):
                    beh = s["behaviour_summary"]
                    break
            if isinstance(beh, dict):
                lines.append("- VT behaviour (sandboxed):")
                for key in (
                    "dns_lookups",
                    "ip_traffic",
                    "http_conversations",
                    "files_written",
                    "processes_created",
                ):
                    items = beh.get(key) or []
                    if isinstance(items, list) and items:
                        lines.append(f"  - {key}: {len(items)}")
            lines.append("")

    # ipinfo
    if ip_enrichments:
        lines.append("## IP enrichment (ipinfo + rDNS)")
        for e in ip_enrichments:
            lines.append(
                f"- `{e.get('ip')}` — rDNS: {e.get('rdns')}, "
                f"ISP: {e.get('org')}, {e.get('city')}/{e.get('country')}"
            )
        lines.append("")

    # Microsoft Defender reputation (ADR-0009 PR-1 pre-L2 enrichment)
    if ms_reputation and any(ms_reputation.get(k) for k in ("files", "domains", "ips")):
        lines.append("## Microsoft Defender reputation")
        for f in ms_reputation.get("files") or []:
            info = f.get("info") or {}
            stats = f.get("stats") or {}
            det = info.get("determinationValue") or info.get("determinationType")
            lines.append(
                f"- file `{f.get('value')}`: determination={det or '?'}, "
                f"signer={info.get('signer') or '?'}, "
                f"valid_cert={info.get('isValidCertificate')}, "
                f"org_prevalence={stats.get('organizationPrevalence', '?')}"
                f"{_custom_note(f.get('custom_indicator'))}"
            )
        for d in ms_reputation.get("domains") or []:
            stats = d.get("stats") or {}
            lines.append(
                f"- domain `{d.get('value')}`: "
                f"org_prevalence={stats.get('organizationPrevalence', '?')}, "
                f"first_seen={stats.get('orgFirstSeen', '?')}"
                f"{_custom_note(d.get('custom_indicator'))}"
            )
        for ip in ms_reputation.get("ips") or []:
            stats = ip.get("stats") or {}
            lines.append(
                f"- ip `{ip.get('value')}`: "
                f"org_prevalence={stats.get('organizationPrevalence', '?')}"
                f"{_custom_note(ip.get('custom_indicator'))}"
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Write the SOC analyst report in the canonical format. "
        "Do not invent fields not present above."
    )
    return "\n".join(lines)
