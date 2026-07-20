"""YARA-Forge scanning of alert *content* (decoded payloads + script/command
fields), as opposed to uploaded forensics files.

Design constraints (the user opted to scan every alert that carries a script/
command field, so this runs hot):

  * **Core ruleset only** (5,078 rules, ~120 s cap) — the 11.6k full ruleset is
    reserved for deliberate forensics file uploads. Content scanning must stay
    cheap.
  * **In-process SHA256 cache** — SOC alert streams are extremely repetitive;
    identical command lines hit the cache instead of re-invoking REMnux. The
    cache is shared across the worker's concurrent pipeline jobs (one process,
    ``max_jobs`` coroutines).
  * **Bounded concurrency** — a semaphore caps simultaneous REMnux execs.
  * **Total time budget + fail-soft** — the whole step is wrapped so a slow or
    unreachable REMnux degrades to "no matches" and NEVER stalls or fails the
    pipeline. YARA is a bonus signal, not a gate.

Results feed the briefing (so the LLM sees them) and the UI panel.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections import OrderedDict

from ..adapters import remnux_adapter
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.pipeline.yara")

# Fields that may carry attacker-controlled script/command content.
_SCAN_FIELDS = (
    "command_line",
    "commandline",
    "process_command_line",
    "command",
    "script",
    "script_block",
    "powershell",
    "payload",
    "parent_command_line",
)

MIN_BLOB_BYTES = 16  # skip trivially short content
MAX_BLOBS = 8  # cap REMnux execs per alert
MAX_CONCURRENCY = 3
TOTAL_BUDGET_SECONDS = 90  # hard ceiling for the whole content-scan step
_CACHE_MAX = 2048

# sha256 -> list[match dict]. Bounded LRU, process-local.
_cache: "OrderedDict[str, list[dict[str, str]]]" = OrderedDict()
_sem = asyncio.Semaphore(MAX_CONCURRENCY)


def _cache_get(digest: str) -> list[dict[str, str]] | None:
    if digest in _cache:
        _cache.move_to_end(digest)
        return _cache[digest]
    return None


def _cache_put(digest: str, matches: list[dict[str, str]]) -> None:
    _cache[digest] = matches
    _cache.move_to_end(digest)
    while len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)


def _gather_blobs(normalized: dict, deob: dict | None) -> list[tuple[str, bytes]]:
    """(label, bytes) blobs to scan: script/command fields + decoded artifacts.
    Deduplicated by sha256, capped at MAX_BLOBS."""
    seen: set[str] = set()
    out: list[tuple[str, bytes]] = []

    def add(label: str, text: str) -> None:
        if not text:
            return
        data = text.encode("utf-8", errors="replace")
        if len(data) < MIN_BLOB_BYTES:
            return
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            return
        seen.add(digest)
        out.append((label, data))

    for f in _SCAN_FIELDS:
        v = normalized.get(f)
        if isinstance(v, str):
            add(f, v)

    for art in (deob or {}).get("artifacts", []) or []:
        add(
            f"decoded:{art.get('encoding', '?')}:L{art.get('layer', '?')}",
            art.get("decoded_text") or "",
        )

    return out[:MAX_BLOBS]


async def _scan_one(label: str, data: bytes) -> list[dict[str, str]]:
    digest = hashlib.sha256(data).hexdigest()
    cached = _cache_get(digest)
    if cached is not None:
        return [{**m, "source": label} for m in cached]
    async with _sem:
        result = await remnux_adapter.yara_scan_bytes(data, full=False)
    matches = result.get("matches") or []
    # Only cache clean infra results (don't cache a transient REMnux error as "no matches").
    if not result.get("error"):
        _cache_put(digest, matches)
    return [{**m, "source": label} for m in matches]


async def scan_alert_content(normalized: dict | None, deob: dict | None) -> list[dict[str, str]]:
    """Scan decoded payloads + script/command fields with YARA-Forge core.

    Returns a deduplicated list of ``{rule, namespace, source}`` matches.
    Fully fail-soft: returns ``[]`` on any error, timeout, or unreachable REMnux.
    """
    if not getattr(settings, "remnux_container_name", None):
        return []
    blobs = _gather_blobs(normalized or {}, deob)
    if not blobs:
        return []
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*[_scan_one(lbl, data) for lbl, data in blobs], return_exceptions=True),
            timeout=TOTAL_BUDGET_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("yara.content_scan.timeout", blob_count=len(blobs))
        return []

    merged: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for r in results:
        if isinstance(r, BaseException):
            logger.warning("yara.content_scan.blob_failed", error=str(r))
            continue
        for m in r:
            key = (m.get("rule", ""), m.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            merged.append(m)
    return merged
