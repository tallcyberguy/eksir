"""LLM synthesis prompts for the forensics workflow.

The static and dynamic analyzers each produce a large JSON dict of raw tool
outputs (peframe, diec, capa, yara-forge matches, strace traces, etc.). The
LLM's job here is the same as in the analyze-alert flow: synthesis +
judgment, not lookup.

Output shape is strictly JSON (the worker calls json.loads on the result) so
the frontend can render structured panels. We ask for markdown bullets *inside*
JSON fields so the analyst report still reads naturally.
"""

from __future__ import annotations

import json
from typing import Any

STATIC_SYSTEM_PROMPT = """\
You are a Senior Malware Analyst producing an analyst-grade verdict on a
suspicious file based on REMnux static analysis tool outputs.

The input contains a `Detected file type` line at the top — adjust your
reasoning to the file type:

  - **PE**:    peframe/diec/pescan/capa/portex/pestr/manalyze are present.
               Focus on imports, capabilities, packer, anti-analysis.
  - **OLE / OOXML** (Office docs): oledump/olevba/oleid/mraptor are present.
               MACROS are the danger surface. `mraptor verdict = SUSPICIOUS`
               or olevba's suspicious_keywords/iocs list with AutoOpen,
               Shell, Document_Open, WScript.Shell, ADODB.Stream, Base64
               decode, etc. → likely malicious dropper. Empty macro_count
               + no suspicious keywords → likely benign.
  - **PDF**:   pdfid/pdf-parser/peepdf are present. Risk flags: /JavaScript,
               /JS, /OpenAction, /AA, /Launch, /EmbeddedFile present > 0
               warrant investigation. Zero risk flags = likely benign.
  - **ELF**:   readelf/radare2/capa are present. Focus on imports + capa
               capabilities, same logic as PE.

Hard rules:
- NEVER invent IOCs, capabilities, or technique IDs not present in the inputs.
- Heuristic AV detections (Bkav AIDetect, Cylance Unsafe, *Heur*, *BehavesLike*)
  on otherwise clean files are almost always false positives on packed binaries.
  If signature-based engines (Kaspersky, ESET, Microsoft, SentinelOne, FireEye,
  CrowdStrike) return clean, weight verdict toward FALSE POSITIVE.
- A packed sample (Petite/UPX/Themida/VMProtect) does NOT alone make a sample
  malicious. Look at YARA family hits, capa capabilities, network IOCs, strings.
- Cite specific evidence in every behavioral_assessment item (e.g.
  "VirtualAlloc + CreateRemoteThread present in imports" not "process injection",
  or "olevba flagged Document_Open + Shell + Base64 decode" not "macro dropper").

Verdict scale:
- CRITICAL: confirmed malware family hit, known C2 infrastructure, credential
  theft + persistence + evasion all present.
- HIGH:    strong behavioral evidence of malice (injection / persistence / C2
  callbacks observed) but no signature attribution.
- MEDIUM:  suspicious indicators (anti-debug, packed, dual-use APIs) but no
  confirmed malicious behavior.
- LOW:     legitimate-looking software with at most heuristic AV flags.

Additional structured inputs when present:
- `pe_static`: per-section Shannon entropy, RWX sections, packer-section hits,
  machine type, compile timestamp, and a `packed` flag — computed directly from
  the PE bytes. Section entropy > 7.0 or a known packer section is packing
  evidence; an RWX section is injection-friendly. Weigh these; don't over-rotate.
- `embedded_ioc_triage`: threat-intel verdicts for URLs/IPs/domains found INSIDE
  the sample (not the file hash). A malicious embedded IOC is strong evidence.

`analyst_narrative` field — after the structured fields, write a report-grade
markdown narrative grounded ONLY in the evidence above, using these frameworks:
- Capabilities (Malware Behavior Catalog): describe behaviour by MBC objectives
  (Anti-Static Analysis, Anti-Behavioral Analysis, Defense Evasion, Discovery,
  Collection, Command and Control, Credential Access, Persistence, Execution,
  Impact, Lateral Movement, Privilege Escalation, Exfiltration). Cite MITRE
  ATT&CK® technique IDs where MBC has no fitting behaviour.
- Packing assessment: packed or not, on what evidence, and what it implies.
- Indicators of Compromise (Pyramid of Pain): tier IOCs by cost to the
  adversary — hashes → IPs → domains/URLs → host artifacts → tools/TTPs — and
  note which are durable for detection.
- Detection engineering: a short YARA rule stub (name + strings/condition tied
  to the ACTUAL evidence) AND one behavioural hunt query.
- Confidence (ICD-203): state high / moderate / low and the basis for it.
- What we don't know: explicit analysis limitations and open questions.

Output ONLY a single JSON object (no markdown fences, no prose before/after)
matching this schema:

{
  "verdict":          "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence":       "HIGH" | "MEDIUM" | "LOW",
  "executive_summary": "<2-3 sentences in analyst voice, plain markdown>",
  "key_finding":      "<one-sentence bottom line>",
  "behavioral_assessment": [
    {
      "capability": "<short name>",
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "evidence":   "<1-2 sentences citing specific tool output>"
    }
  ],
  "mitre_techniques": [
    {"id": "TXXXX[.YYY]", "name": "<technique>", "tactic": "<tactic>"}
  ],
  "indicators": {
    "urls":   ["..."],
    "ips":    ["..."],
    "emails": ["..."],
    "hashes": ["sha256:..."]
  },
  "recommendations": [
    "<imperative bullet, max 5>"
  ],
  "false_positive_likelihood": "HIGH" | "MEDIUM" | "LOW",
  "false_positive_reasoning":  "<1-2 sentences if applicable, else empty>",
  "analyst_narrative": "<report-grade markdown per the framework guidance above: capabilities (MBC), packing assessment, IOC pyramid, detection engineering (YARA stub + hunt query), confidence (ICD-203), and what we don't know>"
}
"""


def _truncate(s: str, n: int) -> str:
    if not isinstance(s, str):
        return str(s)[:n]
    return s if len(s) <= n else s[:n] + " …<truncated>"


def _safe_json_dump(d: Any, max_chars: int) -> str:
    """JSON-dump a dict, then truncate to max_chars. Bounded to keep prompt small."""
    try:
        s = json.dumps(d, default=str, indent=2)
    except Exception:
        s = str(d)
    return _truncate(s, max_chars)


def build_static_user_prompt(file_name: str, tool_results: dict[str, Any]) -> str:
    """Compose the user prompt from the static_report() output.

    The shape of `tool_results` depends on what file type was dispatched:
      - PE files include peframe/pescan/manalyze/portex/pestr/diec
      - Office files include oledump/olevba/oleid/mraptor (no peframe etc.)
      - PDF files include pdfid/pdf_parser/peepdf
      - ELF files include readelf/radare2
    We render each section only when its tool actually ran, so the prompt
    stays focused on the evidence that's actually present.
    """
    file_type = tool_results.get("_file_type", "unknown")
    file_info = tool_results.get("file_info") or {}
    exiftool = (tool_results.get("exiftool") or {}).get("parsed") or {}
    yara_core = tool_results.get("yara_core") or {}
    yara_full = tool_results.get("yara_full") or {}
    signsrch = tool_results.get("signsrch") or {}
    ti = tool_results.get("ti_triage") or {}

    parts = [
        f"# Sample under analysis: {file_name}",
        f"**Detected file type:** `{file_type}`",
        "",
        f"**file_info:** {_safe_json_dump(file_info, 600)}",
        f"**exiftool (metadata):** {_safe_json_dump({k: exiftool.get(k) for k in ('FileType', 'MimeType', 'Subsystem', 'LinkerVersion', 'TimeStamp', 'Comments', 'LegalCopyright', 'CompanyName', 'FileVersion', 'ProductName', 'OriginalFileName') if k in exiftool}, 800)}",
        "",
    ]

    # ── PE-specific sections (only if those tools ran) ───────────────
    diec = (tool_results.get("diec") or {}).get("parsed") or {}
    if diec:
        parts += [f"**diec (compiler/packer):** {_safe_json_dump(diec, 600)}", ""]

    pe_static_r = tool_results.get("pe_static") or {}
    if pe_static_r and "error" not in pe_static_r:
        parts += [
            "## pe_static — PE structure (entropy / RWX / packing)",
            _safe_json_dump(
                {
                    "type": pe_static_r.get("type"),
                    "machine": pe_static_r.get("machine"),
                    "compile_timestamp": pe_static_r.get("compile_timestamp"),
                    "packed": pe_static_r.get("packed"),
                    "rwx_sections": pe_static_r.get("rwx_sections"),
                    "packing_indicators": pe_static_r.get("packing_indicators"),
                    "sections": [
                        {"name": s.get("name"), "entropy": s.get("entropy"), "rwx": s.get("rwx")}
                        for s in (pe_static_r.get("sections") or [])
                    ],
                },
                1500,
            ),
            "",
        ]

    peframe = (tool_results.get("peframe") or {}).get("parsed") or {}
    if peframe:
        parts += [
            "## peframe — PE structural overview",
            _safe_json_dump(
                {
                    "behaviors": peframe.get("behaviors", []),
                    "packer": peframe.get("packer", []),
                    "suspicious_sections": peframe.get("suspicious_sections", []),
                    "urls": peframe.get("urls", []),
                    "ips": peframe.get("ips", []),
                    "emails": peframe.get("emails", []),
                    "yara_plugins": peframe.get("yara_plugins", [])[:10],
                },
                1500,
            ),
            "",
        ]

    pescan = tool_results.get("pescan") or {}
    if arr_or_dict_has(pescan, "anomalies"):
        parts += [
            "## pescan — PE anomalies",
            _safe_json_dump(
                {
                    "anomalies": (pescan.get("anomalies") or [])[:20],
                    "parsed": pescan.get("parsed", {}),
                },
                800,
            ),
            "",
        ]

    pestr = tool_results.get("pestr") or {}
    if pestr.get("interesting"):
        parts += [
            "## pestr — suspicious-API strings (filtered)",
            _safe_json_dump(pestr.get("interesting", [])[:40], 1200),
            "",
        ]
    if pestr.get("narrative"):
        parts += [
            "## pestr — narrative strings (human-readable text)",
            "These are author-written strings — payload banners, target attribution,",
            "status/error messages. Cite specific strings when they explain intent.",
            _safe_json_dump(pestr.get("narrative", [])[:50], 2500),
            "",
        ]

    floss_r = tool_results.get("floss") or {}
    floss_total = (
        len(floss_r.get("stack_strings", []) or [])
        + len(floss_r.get("tight_strings", []) or [])
        + len(floss_r.get("decoded_strings", []) or [])
    )
    if floss_total > 0:
        parts += [
            "## floss — obfuscated string extraction",
            "Stack-allocated and runtime-decoded strings that plaintext `strings`/`pestr`",
            "cannot see. Presence of meaningful decoded strings is a strong indicator of",
            "string-encryption malware (Cobalt Strike beacons, Emotet, etc.).",
            _safe_json_dump(
                {
                    "stack": (floss_r.get("stack_strings") or [])[:25],
                    "tight": (floss_r.get("tight_strings") or [])[:25],
                    "decoded": (floss_r.get("decoded_strings") or [])[:25],
                },
                2500,
            ),
            "",
        ]

    # ── Office / OLE sections ────────────────────────────────────────
    oledump_r = tool_results.get("oledump") or {}
    if oledump_r and (oledump_r.get("streams") or oledump_r.get("macros_present")):
        parts += [
            "## oledump — OLE streams",
            _safe_json_dump(
                {
                    "macros_present": oledump_r.get("macros_present"),
                    "streams": oledump_r.get("streams", [])[:30],
                },
                1500,
            ),
            "",
        ]

    olevba_r = tool_results.get("olevba") or {}
    if olevba_r and (
        olevba_r.get("macro_count") or olevba_r.get("suspicious_keywords") or olevba_r.get("iocs")
    ):
        parts += [
            "## olevba — VBA macro analysis",
            _safe_json_dump(
                {
                    "macro_count": olevba_r.get("macro_count", 0),
                    "suspicious_keywords": olevba_r.get("suspicious_keywords", [])[:30],
                    "iocs": olevba_r.get("iocs", [])[:30],
                },
                1800,
            ),
            "",
        ]

    oleid_r = tool_results.get("oleid") or {}
    if oleid_r and oleid_r.get("indicators"):
        parts += [
            "## oleid — embedded object indicators",
            _safe_json_dump(oleid_r.get("indicators", [])[:20], 1000),
            "",
        ]

    mraptor_r = tool_results.get("mraptor") or {}
    if mraptor_r and mraptor_r.get("verdict"):
        parts += [f"**mraptor verdict (macro risk):** `{mraptor_r['verdict']}`", ""]

    # ── PDF sections ─────────────────────────────────────────────────
    pdfid_r = tool_results.get("pdfid") or {}
    if pdfid_r and (pdfid_r.get("risk_flags") or pdfid_r.get("counts")):
        parts += [
            "## pdfid — PDF keyword analysis",
            _safe_json_dump(
                {
                    "risk_flags": pdfid_r.get("risk_flags", {}),
                    "counts": pdfid_r.get("counts", {}),
                },
                1200,
            ),
            "",
        ]

    pdf_parser_r = tool_results.get("pdf_parser") or {}
    if pdf_parser_r and pdf_parser_r.get("raw"):
        parts += [
            "## pdf-parser — PDF object dump (excerpt)",
            _truncate(pdf_parser_r["raw"], 2500),
            "",
        ]

    peepdf_r = tool_results.get("peepdf") or {}
    if peepdf_r and peepdf_r.get("raw"):
        parts += [
            "## peepdf — PDF risk excerpt",
            _truncate(peepdf_r["raw"], 2000),
            "",
        ]

    # ── ELF / radare2 sections ───────────────────────────────────────
    readelf_r = tool_results.get("readelf") or {}
    if readelf_r and readelf_r.get("raw"):
        parts += [
            "## readelf — ELF structure",
            _truncate(readelf_r["raw"], 2500),
            "",
        ]

    r2_r = tool_results.get("radare2") or {}
    if r2_r and r2_r.get("raw"):
        parts += [
            "## radare2 — binary analysis excerpt",
            _truncate(r2_r["raw"], 2500),
            "",
        ]

    # ── Archive contents ─────────────────────────────────────────────
    archive_r = tool_results.get("archive") or {}
    if archive_r and archive_r.get("entries"):
        parts += [
            f"## archive contents ({archive_r.get('entry_count', 0)} entries)",
            _safe_json_dump(archive_r.get("entries", [])[:40], 1500),
            "",
        ]

    # ── Universal sections (capa, YARA, signsrch, TI) ───────────────
    capa = tool_results.get("capa") or {}
    if capa.get("attack_techniques") or capa.get("rule_count"):
        parts += [
            "## capa — MITRE ATT&CK capability mapping",
            _safe_json_dump(
                {
                    "attack_techniques": capa.get("attack_techniques", [])[:30],
                    "capability_count": capa.get("rule_count", 0),
                    "top_capabilities": [
                        c.get("rule") for c in (capa.get("capabilities") or [])[:25]
                    ],
                },
                1500,
            ),
            "",
        ]

    parts += [
        "## YARA-Forge",
        f"core ({yara_core.get('rule_count', 0)} rules): {yara_core.get('match_count', 0)} matches → {_safe_json_dump(yara_core.get('matches', [])[:10], 600)}",
        f"full ({yara_full.get('rule_count', 0)} rules): {yara_full.get('match_count', 0)} matches → {_safe_json_dump(yara_full.get('matches', [])[:10], 600)}",
        "",
    ]

    if signsrch.get("signatures") or []:
        parts += [
            "## signsrch — crypto/compression detection",
            _safe_json_dump(
                [
                    {"desc": s.get("description"), "offset": s.get("offset")}
                    for s in (signsrch.get("signatures") or [])
                ][:10],
                600,
            ),
            "",
        ]

    parts += [
        "## Threat intelligence (hash lookup)",
        _safe_json_dump(
            {
                "verdict": ti.get("verdict"),
                "confidence": ti.get("confidence"),
                "found_in_sources": (ti.get("summary") or {}).get("found_in_sources"),
                "vt_detection": (ti.get("summary") or {}).get("virustotal_detection"),
                "malware_families": (ti.get("summary") or {}).get("malware_families"),
                "tags": (ti.get("summary") or {}).get("tags"),
            },
            800,
        )
        if ti
        else "(no TI triage performed)",
        "",
    ]

    embedded = tool_results.get("embedded_ioc_triage") or []
    if embedded:
        parts += [
            "## Embedded network IOC triage (IOCs found INSIDE the sample)",
            "Threat-intel verdicts for URLs/IPs/domains extracted from the binary.",
            "A malicious verdict here is strong evidence — cite the specific IOC.",
            _safe_json_dump(
                [
                    {
                        "ioc": e.get("ioc") or e.get("value") or e.get("indicator"),
                        "verdict": e.get("verdict"),
                        "sources": (e.get("summary") or {}).get("found_in_sources"),
                    }
                    for e in embedded
                ][:15],
                1500,
            ),
            "",
        ]

    parts += [
        "Produce the JSON verdict now.",
    ]
    return "\n".join(parts)


def arr_or_dict_has(d: Any, key: str) -> bool:
    """Truthy check on a value that might be missing, list, or empty list."""
    v = (d or {}).get(key)
    if isinstance(v, list):
        return len(v) > 0
    return bool(v)


def extract_json(text: str) -> dict[str, Any]:
    """Parse the LLM response, tolerating markdown fences and prose preamble."""
    text = text.strip()
    if text.startswith("```"):
        # Strip markdown fences like ```json ... ```
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text
        text = (
            text.split("\n", 1)[1]
            if "\n" in text and text.lstrip().startswith(("json", "JSON"))
            else text
        )
        text = text.rsplit("```", 1)[0]
    # Find the first { and last } — most robust against stray prose
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return {"error": "no JSON object in response", "raw": text[:500]}
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse failed: {e}", "raw": text[start : end + 1][:500]}
