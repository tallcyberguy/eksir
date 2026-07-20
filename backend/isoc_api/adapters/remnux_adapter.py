"""REMnux integration via `docker exec` into the network-isolated container.

REMnux is treated as a tool toolbox, not a service. This adapter exposes one
high-level entrypoint — `static_report()` — that fans out to the individual
REMnux CLI tools in parallel via asyncio.gather.

**Static-only by design.** Dynamic sandboxing (real PE/script execution under
strace/wine/qiling) was removed because shared-container detonation is unsafe
for any sample worth analyzing: ransomware/wipers can encrypt other queued
samples in the shared workspace volume, leftover wine processes contaminate
the next sample's trace, and the kernel boundary is too thin for high-assurance
work. For dynamic analysis, integrate Hybrid Analysis / any.run / Triage via
their APIs instead — they run real VMs with snapshot/restore per sample. See
README "Why no dynamic analysis here" for the full rationale.

File-type awareness:
  static_report() detects (or accepts a hint for) the file type and dispatches
  to a type-specific tool wave instead of always running the PE toolchain.
  See FILE_TYPE_WAVES + detect_file_type() below.

  Common-to-all baseline: file_info, exiftool, signsrch, yara_forge core/full,
  strings_analysis. Then type-specific tools layered on top.

Each tool wrapper does three things:
  1. Run the tool via `_exec()` (docker exec into the isolated container)
  2. Parse the output into structured JSON where the tool supports it
  3. Always also return the raw stdout for analyst eyes-on review
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from typing import Any

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.adapter.remnux")


async def _exec(args: list[str], timeout: int | None = None) -> tuple[int, str, str]:
    """Run a command inside the REMnux container via `docker exec`."""
    cmd = ["docker", "exec", settings.remnux_container_name, *args]
    logger.info("remnux.exec", cmd=" ".join(shlex.quote(a) for a in cmd[:6]))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout or settings.remnux_default_timeout_seconds,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "", "timeout"
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


# ── Basic file info ────────────────────────────────────────────────────
async def file_info(path: str) -> dict[str, Any]:
    """Run `file` + sha256 + sha1 + md5 + size — the basics before deeper tools.

    Surfaces an `error` key when the docker exec itself fails (e.g. socket not
    mounted, container not running). Previously these failures returned all-null
    silently which made the LLM hallucinate "corrupted sample" on infra issues.
    """
    rc1, file_out, err1 = await _exec(["file", path])
    rc2, sha_out, err2 = await _exec(["sha256sum", path])
    rc3, sha1_out, _ = await _exec(["sha1sum", path])
    rc4, md5_out, _ = await _exec(["md5sum", path])
    rc5, stat_out, _ = await _exec(["stat", "-c", "%s", path])

    # If the very first `file` call failed AND so did `sha256sum`, the docker
    # exec layer is broken — surface the underlying stderr so the worker can
    # short-circuit instead of feeding empty data to the LLM.
    infra_error: str | None = None
    if rc1 != 0 and rc2 != 0:
        infra_error = (err1 or err2 or "docker exec failed").strip()[:400]

    out: dict[str, Any] = {
        "file_type": file_out.strip().split(":", 1)[-1].strip() if rc1 == 0 else None,
        "sha256": sha_out.split()[0] if rc2 == 0 and sha_out else None,
        "sha1": sha1_out.split()[0] if rc3 == 0 and sha1_out else None,
        "md5": md5_out.split()[0] if rc4 == 0 and md5_out else None,
        "size": int(stat_out.strip()) if rc5 == 0 and stat_out.strip().isdigit() else None,
    }
    if infra_error:
        out["error"] = infra_error
    return out


# ── Strings (raw + PE-aware) ───────────────────────────────────────────
async def strings_analysis(path: str, min_len: int = 8) -> dict[str, Any]:
    rc, out, err = await _exec(["strings", f"-n{min_len}", path], timeout=120)
    if rc != 0:
        return {"error": err[:500], "count": 0, "sample": []}
    lines = [l for l in out.splitlines() if l]
    return {"count": len(lines), "sample": lines[:200]}


# Strings that look human-readable but are actually MSVC runtime / DOS stub /
# section-name noise. They show up in *every* PE and crowd out real intel.
_NARRATIVE_NOISE_PREFIXES = (
    ".text",
    ".rdata",
    ".data",
    ".bss",
    ".CRT$",
    ".idata$",
    ".rtc$",
    ".xdata$",
    ".fptable",
    ".pdata",
    "operator",
    "`vftable",
    "`vbtable",
    "`vector",
    "`local ",
    "`omni",
    "`managed",
    "`copy",
    "`udt",
    "`scalar",
    "`anonymous",
    "`placement",
    "`vbase",
    "`dynamic",
    "`eh ",
    "`virtual",
    "`string'",
    "`RTTI",
    "__cdecl",
    "__stdcall",
    "__thiscall",
    "__fastcall",
    "__vectorcall",
    "__preserve",
    "__clrcall",
    "__based",
    "__swift",
    "__ptr",
    "__restrict",
    "__unaligned",
    "restrict(",
    " new",
    " delete[",
)
_NARRATIVE_NOISE_EXACT = frozenset(
    {
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
        "MM/dd/yy",
        "dddd, MMMM dd, yyyy",
        "HH:mm:ss",
        "Unknown exception",
        "bad exception",
        "(null)",
        "CorExitProcess",
        "NAN(SNAN)",
        "nan(snan)",
        "NAN(IND)",
        "nan(ind)",
        "e+000",
        "AreFileApisANSI",
        "CompareStringEx",
        "LCMapStringEx",
        "LocaleNameToLCID",
        "AppPolicyGetProcessTerminationMethod",
        "1#INF",
        "1#QNAN",
        "1#SNAN",
        "1#IND",
        "FlsAlloc",
        "FlsFree",
        "FlsGetValue",
        "FlsSetValue",
        "FlsGetValue2",
        "InitializeCriticalSectionEx",
        "RaiseException",
        "EncodePointer",
        "DecodePointer",
        "!This program cannot be run in DOS mode.",
    }
)


def _looks_narrative(s: str) -> bool:
    """Heuristic: does this string look like human-readable text rather than
    opcode / runtime noise / hex dump? Designed to catch payload banners,
    target names, error messages, status strings — the things a malware
    author actually wrote that explain intent.
    """
    if len(s) < 10:
        return False
    if s in _NARRATIVE_NOISE_EXACT:
        return False
    if any(s.startswith(p) for p in _NARRATIVE_NOISE_PREFIXES):
        return False
    letters = sum(1 for c in s if c.isalpha())
    if letters * 2 < len(s):  # less than 50% letters → opcode-ish
        return False
    # Positive signal: at least one of these structural markers
    return (
        " " in s
        or "://" in s
        or s.lower().endswith((".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js"))
        or s.startswith(("C:\\", "D:\\", "\\\\", "/"))
    )


async def pestr(path: str) -> dict[str, Any]:
    """PE-aware string extraction (ASCII + Unicode) with API + narrative buckets.

    - `interesting`: hardcoded suspicious-API keyword matches (LoadLibrary,
      CreateRemoteThread, VirtualAllocEx, etc.) — fast triage signal.
    - `narrative`:   human-readable text strings filtered by `_looks_narrative`
      — captures payload banners, target attribution, status messages. This
      is the bucket that lets the LLM see strings like "Hedef:
      SentinelAgentWorker.exe v25.1.3.334" instead of just opcode noise.
    """
    rc, out, err = await _exec(["pestr", path], timeout=120)
    if rc != 0:
        return {"error": err[:500], "count": 0, "sample": [], "interesting": [], "narrative": []}
    lines = [l for l in out.splitlines() if l]

    api_keys = (
        "http://",
        "https://",
        "ftp://",
        "\\\\",
        "C:\\",
        "cmd.exe",
        "powershell",
        "regsvr32",
        "rundll32",
        "wmic",
        "schtasks",
        "VirtualAlloc",
        "WriteProcess",
        "CreateRemoteThread",
        "LoadLibrary",
        "GetProcAddress",
    )
    interesting = [l for l in lines if any(k in l for k in api_keys)][:60]

    # Dedupe narrative — the same string often shows up in multiple PE sections.
    narrative_set: set[str] = set()
    narrative: list[str] = []
    for l in lines:
        if l in narrative_set or not _looks_narrative(l):
            continue
        narrative_set.add(l)
        narrative.append(l)
        if len(narrative) >= 60:
            break

    return {
        "count": len(lines),
        "sample": lines[:120],
        "interesting": interesting,
        "narrative": narrative,
    }


# ── capa — MITRE ATT&CK capability mapping (existing) ─────────────────
async def capa(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["capa", "-j", path], timeout=300)
    if rc != 0:
        return {"error": err[:500] or "capa failed"}
    try:
        parsed = json.loads(out)
        # Compact the capa output — the full file is huge. Extract just
        # the capability names + ATT&CK technique IDs that we care about.
        rules = parsed.get("rules", {})
        capabilities: list[dict[str, Any]] = []
        attack: dict[str, dict[str, Any]] = {}
        for rule_name, rule in rules.items():
            meta = rule.get("meta", {})
            scope = meta.get("scopes", {}).get("static", "") or meta.get("scope", "")
            capabilities.append(
                {
                    "rule": rule_name,
                    "namespace": meta.get("namespace", ""),
                    "scope": scope,
                }
            )
            for att in meta.get("attack", []):
                tech_id = att.get("id", "")
                if tech_id and tech_id not in attack:
                    attack[tech_id] = {
                        "id": tech_id,
                        "tactic": att.get("tactic", ""),
                        "technique": att.get("technique", ""),
                        "subtechnique": att.get("subtechnique", ""),
                    }
        return {
            "capabilities": capabilities[:60],
            "attack_techniques": list(attack.values()),
            "rule_count": len(rules),
        }
    except Exception as e:
        return {"error": f"capa output not JSON: {e}", "raw": out[:1000]}


# ── yara-forge core (5,078 rules) ──────────────────────────────────────
async def yara_forge(path: str) -> dict[str, Any]:
    """Match against the YARA-Forge core ruleset (5,078 rules)."""
    rc, out, err = await _exec(["yara-forge", path], timeout=120)
    matches = _parse_yara(out)
    return {
        "ruleset": "core",
        "rule_count": 5078,
        "match_count": len(matches),
        "matches": matches,
        "error": err[:500] if (rc != 0 and not matches) else None,
    }


async def yara_forge_full(path: str) -> dict[str, Any]:
    """Match against the YARA-Forge full ruleset (11,679 rules from 45+ sources)."""
    rc, out, err = await _exec(["yara-forge-full", path], timeout=240)
    matches = _parse_yara(out)
    return {
        "ruleset": "full",
        "rule_count": 11679,
        "match_count": len(matches),
        "matches": matches,
        "error": err[:500] if (rc != 0 and not matches) else None,
    }


async def yara_scan_bytes(content: bytes, *, full: bool = False) -> dict[str, Any]:
    """Write a content blob to the shared workspace and YARA-scan it.

    Used to scan DECODED payloads / raw script-command fields from the alert
    pipeline (not an uploaded file). Returns the same shape as ``yara_forge()``.
    The temp file lives under ``<workspace>/deob`` (shared with the REMnux
    container, same mount the forensics flow uses) and is always cleaned up.
    """
    import hashlib
    import uuid as _uuid

    digest = hashlib.sha256(content).hexdigest()
    target_dir = settings.workspace_path / "deob"
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / f"{digest}-{_uuid.uuid4().hex}.bin"
        target_path.write_bytes(content)
    except OSError as e:
        return {
            "ruleset": "full" if full else "core",
            "match_count": 0,
            "matches": [],
            "error": str(e)[:200],
        }
    try:
        return await (yara_forge_full(str(target_path)) if full else yara_forge(str(target_path)))
    finally:
        try:
            target_path.unlink()
        except OSError:
            pass


def _parse_yara(out: str) -> list[dict[str, str]]:
    """Parse `rule_name /path/to/sample` lines from yara stdout."""
    matches: list[dict[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("warning:") or line.startswith("error:"):
            continue
        # yara emits "rulename path" (or "namespace:rulename path" with -e)
        parts = line.split(maxsplit=1)
        if not parts:
            continue
        rule = parts[0]
        if ":" in rule:
            namespace, rule = rule.split(":", 1)
        else:
            namespace = ""
        matches.append({"rule": rule, "namespace": namespace})
    return matches


# ── diec — compiler/packer/protector detection ────────────────────────
async def diec(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["diec", path], timeout=60)
    if rc != 0:
        return {"error": err[:500] or "diec failed", "raw": out[:500]}
    # diec output is ANSI-coloured key:value text, e.g.:
    #   Linker: Turbo Linker(2.25*,Delphi)[GUI32]
    #   Compiler: Borland Delphi
    #   Packer: Petite(2.2)
    clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
    parsed: dict[str, str] = {}
    for line in clean.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("["):
            k, v = line.split(":", 1)
            parsed[k.strip().lower()] = v.strip()
    return {"parsed": parsed, "raw": clean[:2000]}


# ── exiftool — file metadata ──────────────────────────────────────────
async def exiftool(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["exiftool", "-json", "-fast", path], timeout=60)
    if rc != 0:
        return {"error": err[:500] or "exiftool failed"}
    try:
        data = json.loads(out)
        if isinstance(data, list) and data:
            return {"parsed": data[0]}
        return {"parsed": {}}
    except Exception as e:
        return {"error": f"exiftool output not JSON: {e}", "raw": out[:1000]}


# ── peframe — overview + behaviors + IPs/URLs/emails ──────────────────
async def peframe(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["peframe", "--json", path], timeout=300)
    if rc == 0 and out.strip().startswith("{"):
        try:
            return {"parsed": json.loads(out)}
        except Exception:
            pass
    # Fall back to text mode + structured parse.
    rc2, text_out, _ = await _exec(["peframe", path], timeout=300)
    if rc2 != 0:
        return {"error": err[:500] or "peframe failed"}
    return {"parsed": _parse_peframe_text(text_out), "raw": text_out[:5000]}


def _parse_peframe_text(text: str) -> dict[str, Any]:
    """Light parser for peframe's text output — sections, behaviors, urls, ips."""
    sections = {
        "behaviors": [],
        "packer": [],
        "suspicious_sections": [],
        "imports": [],
        "urls": [],
        "ips": [],
        "emails": [],
        "yara_plugins": [],
    }
    current: str | None = None
    section_map = {
        "Behavior": "behaviors",
        "Packer": "packer",
        "Sections Suspicious": "suspicious_sections",
        "Import function": "imports",
        "Url": "urls",
        "Ip Address": "ips",
        "Email": "emails",
        "Yara Plugins": "yara_plugins",
    }
    for line in text.splitlines():
        if line.startswith("---"):
            # Heading line; the heading name is on the same line surrounded by dashes
            stripped = line.replace("-", "").strip()
            current = section_map.get(stripped)
            continue
        if not line.strip():
            continue
        if current and current in sections:
            value = line.strip()
            # imports look like "kernel32.dll  8"
            if current == "imports" and "  " in value:
                value = value.split("  ", 1)[0].strip()
            sections[current].append(value)
    # Truncate long arrays
    for k in sections:
        sections[k] = sections[k][:40]
    return sections


# ── pescan — PE anomaly check ─────────────────────────────────────────
async def pescan(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["pescan", path], timeout=60)
    if rc != 0:
        return {"error": err[:500] or "pescan failed", "raw": out[:500]}
    anomalies: list[str] = []
    parsed: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            parsed[k.lower()] = v
            if any(
                flag in v.lower()
                for flag in (
                    "suspicious",
                    "self-modifying",
                    "anomal",
                    "too old",
                    "small length",
                    "zero length",
                )
            ):
                anomalies.append(f"{k}: {v}")
    return {"parsed": parsed, "anomalies": anomalies, "raw": out[:3000]}


# ── manalyze — alternative PE analyzer ────────────────────────────────
async def manalyze(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["manalyze", "--output=json", "--plugins=all", path], timeout=120)
    if rc == 0 and out.strip().startswith("{"):
        try:
            return {"parsed": json.loads(out)}
        except Exception:
            pass
    # Text fallback
    rc2, text_out, _ = await _exec(["manalyze", path], timeout=120)
    if rc2 != 0:
        return {"error": err[:500] or "manalyze failed"}
    return {"raw": text_out[:3000]}


# ── signsrch — crypto/compression algorithm detection ────────────────
async def signsrch(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["signsrch", path], timeout=60)
    if rc != 0:
        return {"error": err[:500] or "signsrch failed", "signatures": []}
    sigs: list[dict[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        # signsrch lines look like:  "007ab5d1 2875 libavcodec ff_mjpeg... [..162]"
        m = re.match(r"^([0-9a-fA-F]+)\s+(\d+)\s+(.+?)\s*\[([^\]]+)\]\s*$", line)
        if m:
            sigs.append(
                {
                    "offset": m.group(1),
                    "num": m.group(2),
                    "description": m.group(3),
                    "size_info": m.group(4),
                }
            )
    return {"signatures": sigs, "count": len(sigs)}


# ── portex — full PE structure ────────────────────────────────────────
async def portex(path: str) -> dict[str, Any]:
    rc, out, err = await _exec(["portex", path], timeout=120)
    if rc != 0:
        return {"error": err[:500] or "portex failed", "raw": out[:500]}
    # Capture section table summary if present
    in_sections = False
    section_lines: list[str] = []
    for line in out.splitlines():
        if "Section Table" in line:
            in_sections = True
            continue
        if in_sections and line.startswith("MSDOS Header"):
            break
        if in_sections:
            section_lines.append(line)
    return {"section_table_excerpt": "\n".join(section_lines)[:3000], "raw": out[:5000]}


# ── floss — deobfuscated string extraction (stack + tight + decoded) ─
async def floss(path: str) -> dict[str, Any]:
    """Extract obfuscated strings that plaintext `strings` can't see:
    stack-allocated strings, tight-loop decoders, runtime XOR decoders.

    Tuned for the analysis pipeline (not interactive use) against the actual
    floss 3.x CLI surface:
      --no static          : skip static strings (we already have those via pestr).
                             `--no` is nargs='+'; argparse stops consuming on the
                             next `-`-prefixed flag, so order matters.
      -n 8                 : minimum string length 8 (drops short opcode noise)
      --disable-progress   : suppress the TTY progress bars on stderr/stdout
      -j                   : emit JSON (NOT `--format json` — `--format` selects
                             the file format auto|pe|sc32|sc64, not output)

    Floss 3.x does NOT expose `--max-instruction-count` — that flag was removed
    when the vivisect backend changed. Runtime is now bounded only by our 300s
    docker-exec timeout.

    Floss results are normalised to flat string lists so the prompt builder
    and UI don't have to know about floss's nested {"string": "...", "offset":
    ...} shape.
    """
    rc, out, err = await _exec(
        ["floss", "--no", "static", "-n", "8", "--disable-progress", "-j", path],
        timeout=300,
    )
    if rc != 0:
        return {
            "error": err[:500] or "floss failed",
            "stack_strings": [],
            "tight_strings": [],
            "decoded_strings": [],
        }
    try:
        parsed = json.loads(out)
        s = parsed.get("strings", {}) or {}

        def _flatten(items: list) -> list[str]:
            # floss emits either bare strings or {"string": "...", "offset": ...}
            out_list: list[str] = []
            for it in items or []:
                if isinstance(it, str):
                    out_list.append(it)
                elif isinstance(it, dict) and isinstance(it.get("string"), str):
                    out_list.append(it["string"])
            return out_list

        return {
            "stack_strings": _flatten(s.get("stack_strings"))[:40],
            "tight_strings": _flatten(s.get("tight_strings"))[:40],
            "decoded_strings": _flatten(s.get("decoded_strings"))[:40],
        }
    except Exception as e:
        return {
            "error": f"floss output not JSON: {e}",
            "stack_strings": [],
            "tight_strings": [],
            "decoded_strings": [],
        }


# ── File-type detection + dispatcher ───────────────────────────────────
# Normalized file-type categories. Keep this list short — each entry maps
# to a tool wave in FILE_TYPE_WAVES. Detection is via the `file` command's
# magic-based output, with regex matches in priority order.
FILE_TYPES = (
    "pe",
    "elf",
    "macho",
    "ole",
    "ooxml",
    "pdf",
    "rtf",
    "script_ps1",
    "script_js",
    "script_vbs",
    "script_sh",
    "script_py",
    "archive",
    "unknown",
)


def detect_file_type(file_cmd_output: str, filename: str = "") -> str:
    """Map `file` command output (and filename extension as a tiebreaker) to
    a normalized file-type enum. Pure function — easy to unit-test.
    """
    s = (file_cmd_output or "").lower()
    name = (filename or "").lower()

    # Strong signals first (binary magic)
    if "pe32" in s or "ms-dos executable" in s or "pe executable" in s:
        return "pe"
    if "elf " in s or "elf 32-bit" in s or "elf 64-bit" in s:
        return "elf"
    if "mach-o" in s:
        return "macho"

    # Office formats. OLE (legacy) is "Composite Document File"; OOXML
    # (modern) is a ZIP archive but with content-type hints from `file`.
    if "composite document file" in s or "cdfv2" in s:
        return "ole"
    if (
        "microsoft office word" in s
        or "microsoft word 2007+" in s
        or "microsoft excel 2007+" in s
        or "microsoft powerpoint 2007+" in s
        or "microsoft ooxml" in s
    ):
        return "ooxml"

    if "rich text format" in s or name.endswith(".rtf"):
        return "rtf"

    if "pdf document" in s or name.endswith(".pdf"):
        return "pdf"

    # Script formats — filename takes priority since `file` often reports
    # "ASCII text" for scripts.
    if name.endswith((".ps1", ".psm1")) or "powershell" in s:
        return "script_ps1"
    if name.endswith(".vbs"):
        return "script_vbs"
    if name.endswith((".js", ".jse")):
        return "script_js"
    if name.endswith((".sh", ".bash")) or "shell script" in s:
        return "script_sh"
    if name.endswith(".py") or "python script" in s:
        return "script_py"

    # OOXML also matches as Zip; this branch catches non-Office zips.
    if (
        "zip archive" in s
        or "rar archive" in s
        or "7-zip archive" in s
        or "gzip compressed" in s
        or "tar archive" in s
    ):
        # OOXML extensions take precedence over generic ZIP.
        if name.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
            return "ooxml"
        return "archive"

    return "unknown"


# Maps each detected/hinted file type → list of *adapter function names* to
# run. The dispatcher resolves names to functions and calls each with `path`.
# Functions are defined later in this module.
FILE_TYPE_WAVES: dict[str, list[str]] = {
    # Common baseline that every wave includes. Kept here for clarity; the
    # dispatcher merges it with the type-specific list.
    "_common": [
        "file_info",
        "exiftool",
        "signsrch",
        "yara_forge",
        "yara_forge_full",
        "strings_analysis",
        "ssdeep",
    ],
    "pe": [
        "diec",
        "peframe",
        "pescan",
        "manalyze",
        "capa",
        "portex",
        "pestr",
        "floss",
        "dotnet_info",
        "cs_config",
    ],
    "elf": ["readelf", "radare2_info", "capa", "floss"],
    "macho": ["radare2_info", "capa"],
    "ole": ["oledump", "olevba", "oleid", "mraptor", "xlmdeobfuscator"],
    "ooxml": ["oledump", "olevba", "oleid", "mraptor", "archive_list", "xlmdeobfuscator"],
    "pdf": ["pdfid", "pdf_parser_stats", "peepdf_info"],
    "rtf": ["rtfobj", "rtfdump"],
    "script_ps1": [],
    "script_js": ["js_deobfuscate"],
    "script_vbs": [],
    "script_sh": [],
    "script_py": [],
    "archive": ["archive_list"],
    "unknown": [],
}


# ── Convenience: full static report ────────────────────────────────────
async def static_report(path: str, file_type_hint: str | None = None) -> dict[str, Any]:
    """Run the type-appropriate static tool wave in parallel and aggregate.

    Type detection priority:
      1. file_type_hint (analyst override from the UI)
      2. Auto-detection from `file` command output
      3. "unknown" → runs only the common baseline

    Each tool runs concurrently. One failing tool does NOT abort the others —
    its slot in the result will contain an `error` key. The dispatched file
    type is recorded in result["_file_type"] so the LLM prompt + UI can show
    it.
    """
    # Validate hint; reject anything outside the enum so we never trust
    # raw user input as a dispatcher key.
    file_type: str | None = None
    if file_type_hint and file_type_hint in FILE_TYPES:
        file_type = file_type_hint

    # If no hint, detect via `file` output.
    if file_type is None:
        rc, file_out, _ = await _exec(["file", path])
        file_cmd_output = file_out if rc == 0 else ""
        import os as _os

        file_type = detect_file_type(file_cmd_output, _os.path.basename(path))

    # Build the wave: common baseline + type-specific extras.
    tool_names = list(FILE_TYPE_WAVES["_common"]) + list(FILE_TYPE_WAVES.get(file_type, []))
    # Resolve names to functions defined in this module.
    tool_fns = []
    for name in tool_names:
        fn = globals().get(name)
        if not callable(fn):
            tool_fns.append((name, _missing_tool(name)))
        else:
            tool_fns.append((name, fn(path)))

    results = await asyncio.gather(*[coro for _, coro in tool_fns], return_exceptions=True)

    out: dict[str, Any] = {"_file_type": file_type, "_tools_run": tool_names}
    for (name, _), r in zip(tool_fns, results, strict=False):
        key = _adapter_key(name)
        out[key] = r if isinstance(r, dict) else {"error": str(r)[:500]}

    # Conditional follow-up: if diec flagged a UPX-packed PE, unpack and re-scan
    # the unpacked binary so capabilities/strings hidden behind packing surface.
    if file_type == "pe":
        diec_out = out.get("diec") or {}
        diec_blob = f"{diec_out.get('parsed')} {diec_out.get('raw')}".lower()
        if "upx" in diec_blob:
            try:
                unpacked = await _try_upx_unpack(path)
                if unpacked:
                    out["unpacked"] = unpacked
            except Exception as e:
                out["unpacked"] = {"error": str(e)[:300]}
    return out


async def _try_upx_unpack(path: str) -> dict[str, Any] | None:
    """`upx -d` the sample to a sibling path (container-visible) and re-run a
    small PE structural sub-wave on the unpacked output. Fail-soft."""
    target = f"{path}.unpacked"
    rc, _out, err = await _exec(["upx", "-d", "-o", target, path], timeout=120)
    if rc != 0:
        return {"unpacked": False, "error": (err[:300] or "upx -d failed")}
    sub_wave = ["diec", "pescan", "capa", "pestr"]
    coros = [(n, globals()[n](target)) for n in sub_wave if callable(globals().get(n))]
    res = await asyncio.gather(*[c for _, c in coros], return_exceptions=True)
    rescan: dict[str, Any] = {"unpacked": True, "output_path": target}
    for (n, _), r in zip(coros, res, strict=False):
        rescan[_adapter_key(n)] = r if isinstance(r, dict) else {"error": str(r)[:300]}
    return rescan


def _adapter_key(adapter_name: str) -> str:
    """Map adapter function name → result-dict key.

    Most are 1:1, but a few historical keys differ (yara_forge → yara_core,
    yara_forge_full → yara_full, strings_analysis → strings) for backwards
    compatibility with the renderer.
    """
    mapping = {
        "yara_forge": "yara_core",
        "yara_forge_full": "yara_full",
        "strings_analysis": "strings",
        "pdf_parser_stats": "pdf_parser",
        "peepdf_info": "peepdf",
        "radare2_info": "radare2",
        "archive_list": "archive",
    }
    return mapping.get(adapter_name, adapter_name)


async def _missing_tool(name: str) -> dict[str, Any]:
    return {"error": f"adapter '{name}' is referenced in FILE_TYPE_WAVES but not implemented"}


# ── Extended catalog (parity with the malware-analysis skill) ───────────
# All static (no execution): fuzzy hashing, RTF/XLM/JS deobfuscation, .NET
# metadata, Cobalt Strike beacon-config extraction. Each is fail-soft.
async def ssdeep(path: str) -> dict[str, Any]:
    """Context-triggered piecewise (fuzzy) hash — for similarity clustering."""
    rc, out, err = await _exec(["ssdeep", "-b", path], timeout=30)
    if rc != 0 and not out:
        return {"error": err[:300] or "ssdeep failed"}
    fuzzy = None
    for line in out.splitlines():
        line = line.strip()
        if line and not line.lower().startswith("ssdeep"):
            fuzzy = line.split(",")[0]
    return {"fuzzy_hash": fuzzy, "raw": out[:400]}


async def rtfobj(path: str) -> dict[str, Any]:
    """Extract embedded objects from RTF (oletools rtfobj) — exploit/dropper surface."""
    rc, out, err = await _exec(["rtfobj", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:500] or "rtfobj failed"}
    objects = [
        ln.strip()
        for ln in out.splitlines()
        if "object" in ln.lower() and ("0x" in ln or "ole" in ln.lower())
    ]
    suspicious = any(
        k in out.lower() for k in ("ole2link", "equation", "packager", "exploit", "cve-")
    )
    return {"objects": objects[:30], "suspicious": suspicious, "raw": out[:3000]}


async def rtfdump(path: str) -> dict[str, Any]:
    """Dump RTF structure (Didier Stevens rtfdump)."""
    rc, out, err = await _exec(["rtfdump.py", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:500] or "rtfdump failed"}
    return {"raw": out[:3000]}


async def xlmdeobfuscator(path: str) -> dict[str, Any]:
    """Deobfuscate Excel 4.0 (XLM) macros. No-op error on non-Excel inputs."""
    rc, out, err = await _exec(["xlmdeobfuscator", "-f", path], timeout=120)
    if rc != 0 and not out:
        return {"error": (err[:400] or "no XLM macros / not an Excel file")}
    has_macros = "CELL:" in out or "FORMULA" in out.upper() or "auto_open" in out.lower()
    return {"xlm_macros_found": has_macros, "raw": out[:4000]}


async def js_deobfuscate(path: str) -> dict[str, Any]:
    """Static JS beautification for readability (no execution — stays static-only)."""
    rc, out, err = await _exec(["js-beautify", path], timeout=45)
    if rc != 0 and not out:
        return {"error": err[:300] or "js-beautify failed"}
    return {"beautified": out[:6000]}


async def dotnet_info(path: str) -> dict[str, Any]:
    """.NET assembly metadata (dotnetfile_dump). Returns not-a-.NET error on native PEs."""
    rc, out, err = await _exec(["dotnetfile_dump.py", "-f", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:300] or "not a .NET assembly"}
    return {"is_dotnet": ("Assembly" in out or "#Strings" in out), "raw": out[:4000]}


async def cs_config(path: str) -> dict[str, Any]:
    """Scan for an embedded Cobalt Strike beacon config (Didier Stevens 1768.py)."""
    rc, out, err = await _exec(["1768.py", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:300] or "no Cobalt Strike config found"}
    found = any(k in out.lower() for k in ("config found", "sleeptime", "0x0001", "c2server"))
    return {
        "cobalt_strike_config_found": found,
        "raw": out[:3000] if found else out[:500],
    }


# ── Office / OLE adapters ──────────────────────────────────────────────
async def oledump(path: str) -> dict[str, Any]:
    """List OLE streams. Lines look like '  1:        96 \\x03ObjInfo'."""
    rc, out, err = await _exec(["oledump.py", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:500] or "oledump failed"}
    streams: list[dict[str, Any]] = []
    macros_present = False
    for line in out.splitlines():
        line = line.strip()
        if not line or "indicators" in line.lower():
            continue
        # "  3: M    7536 'Macros/VBA/ThisDocument'"   →  index, type, size, name
        m = re.match(r"^\s*(\d+):\s*([A-Za-z]*)\s+(\d+)\s+'?([^']+)'?", line)
        if m:
            stype = m.group(2)
            if stype in ("M", "m"):
                macros_present = True
            streams.append(
                {
                    "index": int(m.group(1)),
                    "type": stype,
                    "size": int(m.group(3)),
                    "name": m.group(4).strip(),
                }
            )
    return {"streams": streams[:60], "macros_present": macros_present, "raw": out[:3000]}


async def olevba(path: str) -> dict[str, Any]:
    """Extract VBA macros + auto-classify suspicious calls."""
    rc, out, err = await _exec(["olevba", "--no-deobf", "--decode", path], timeout=180)
    # olevba returns non-zero on no-VBA-found AND on real errors. Trust output.
    text = out or err
    # Key sections: suspicious keywords table, IOC table, VBA source.
    suspicious: list[str] = []
    iocs: list[str] = []
    macro_count = 0
    if text:
        # The keyword analysis is in a table marked "| Type ... | Keyword ... | Description ..."
        in_table = False
        for line in text.splitlines():
            if line.startswith("+--"):
                in_table = True
                continue
            if in_table:
                if line.startswith("+--"):
                    in_table = False
                    continue
                m = re.match(r"^\|\s*Suspicious\s*\|\s*([^|]+?)\s*\|", line)
                if m:
                    suspicious.append(m.group(1).strip())
                m2 = re.match(r"^\|\s*IOC\s*\|\s*([^|]+?)\s*\|", line)
                if m2:
                    iocs.append(m2.group(1).strip())
            if "VBA MACRO" in line:
                macro_count += 1
    return {
        "macro_count": macro_count,
        "suspicious_keywords": suspicious[:40],
        "iocs": iocs[:40],
        "raw_excerpt": text[:4000],
    }


async def oleid(path: str) -> dict[str, Any]:
    """Identify embedded objects, encryption, and macro presence."""
    rc, out, err = await _exec(["oleid", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:500] or "oleid failed"}
    indicators: list[dict[str, str]] = []
    # oleid output format: lines with indicator name, value, severity
    for line in out.splitlines():
        line = line.strip()
        # Crude parse — look for "name: value" colon-separated lines with risk markers
        if (":" in line) and any(
            tok in line.lower()
            for tok in ("macro", "encrypt", "ole", "external", "object", "flash", "auto")
        ):
            indicators.append({"line": line[:200]})
    return {"indicators": indicators[:30], "raw": out[:2500]}


async def mraptor(path: str) -> dict[str, Any]:
    """Macro risk classifier (oletools/mraptor). Outputs SUSPICIOUS/UNKNOWN/etc."""
    rc, out, err = await _exec(["mraptor", path], timeout=60)
    verdict = None
    text = out or err
    for token in ("SUSPICIOUS", "UNKNOWN", "NOT SUSPICIOUS"):
        if token in (text or ""):
            verdict = token
            break
    return {"verdict": verdict, "raw": (text or "")[:1500]}


# ── PDF adapters ───────────────────────────────────────────────────────
async def pdfid(path: str) -> dict[str, Any]:
    """Identify PDF keyword counts (/JavaScript, /JS, /OpenAction, etc.)."""
    rc, out, err = await _exec(["pdfid.py", path], timeout=60)
    if rc != 0 and not out:
        return {"error": err[:500] or "pdfid failed"}
    counts: dict[str, int] = {}
    # Format:  "/JavaScript                  3"
    for line in out.splitlines():
        m = re.match(r"^\s*(/\w+)\s+(\d+)", line)
        if m:
            counts[m.group(1)] = int(m.group(2))
    # Risk flags: any of these > 0 is worth surfacing.
    risk_keys = (
        "/JavaScript",
        "/JS",
        "/AA",
        "/OpenAction",
        "/AcroForm",
        "/JBIG2Decode",
        "/RichMedia",
        "/Launch",
        "/EmbeddedFile",
        "/XFA",
    )
    risk_flags = {k: counts[k] for k in risk_keys if counts.get(k, 0) > 0}
    return {"counts": counts, "risk_flags": risk_flags, "raw": out[:2500]}


async def pdf_parser_stats(path: str) -> dict[str, Any]:
    """High-level stats from pdf-parser (object counts, stream contents)."""
    rc, out, err = await _exec(["pdf-parser.py", "-a", path], timeout=120)
    if rc != 0 and not out:
        return {"error": err[:500] or "pdf-parser failed"}
    return {"raw": out[:5000]}


async def peepdf_info(path: str) -> dict[str, Any]:
    """Quick info from peepdf (older but still useful for triage)."""
    rc, out, err = await _exec(["peepdf", "-f", path], timeout=120)
    if rc != 0 and not out:
        return {"error": err[:500] or "peepdf failed"}
    return {"raw": out[:4000]}


# ── ELF / Mach-O adapters ──────────────────────────────────────────────
async def readelf(path: str) -> dict[str, Any]:
    """ELF header + section headers (high-level structure)."""
    rc, out, err = await _exec(["readelf", "-h", "-S", path], timeout=60)
    if rc != 0:
        return {"error": err[:500] or "readelf failed"}
    return {"raw": out[:5000]}


async def radare2_info(path: str) -> dict[str, Any]:
    """Brief radare2 analysis: imports, exports, strings, security flags."""
    # `r2 -e bin.cache=true -A -qc 'iI;ii;iS;iz~?' file`
    # iI = info, ii = imports, iS = sections, iz = strings (~? = count)
    rc, out, err = await _exec(
        [
            "r2",
            "-e",
            "bin.cache=true",
            "-2",
            "-A",
            "-qc",
            "iI ; echo === IMPORTS === ; ii ; echo === SECTIONS === ; iSq",
            path,
        ],
        timeout=180,
    )
    if rc != 0 and not out:
        return {"error": err[:500] or "radare2 failed"}
    return {"raw": out[:6000]}


# ── Archive adapter ────────────────────────────────────────────────────
async def archive_list(path: str) -> dict[str, Any]:
    """List archive contents (zip / 7z / tar / rar)."""
    rc, out, err = await _exec(
        [
            "bash",
            "-c",
            f"unzip -l {shlex.quote(path)} 2>/dev/null || 7z l {shlex.quote(path)} 2>/dev/null",
        ],
        timeout=60,
    )
    if rc != 0 and not out:
        return {"error": err[:500] or "archive list failed"}
    # Extract just the file names — different listers have different formats.
    entries: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        # zip: "      163  2024-01-01 ...  filename.txt"
        m_zip = re.match(r"^\s*\d+\s+\d{4}-\d{2}-\d{2}\s+\S+\s+(.+)$", line)
        if m_zip:
            entries.append(m_zip.group(1))
            continue
        # 7z:  "2024-01-01 ... <size> <packed> filename"
        m_7z = re.match(r"^\d{4}-\d{2}-\d{2}\s+\S+\s+\S+\s+\d+\s+\d+\s+(.+)$", line)
        if m_7z:
            entries.append(m_7z.group(1))
    return {"entries": entries[:80], "entry_count": len(entries), "raw": out[:3000]}
