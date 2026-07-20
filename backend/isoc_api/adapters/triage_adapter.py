"""Adapter for `malware-analysis/scripts/triage.py`.

Invoked as a subprocess so we get full isolation, the existing ThreadPoolExecutor
parallelism, and the in-process TTL cache benefits per worker.
We always request JSON output (`-f json`) and parse stdout.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.adapter.triage")


def _env() -> dict[str, str]:
    """Build the env dict passed to triage.py.

    Variable names mirror exactly what triage.py reads via os.environ.get(...)
    — see scripts/triage.py:163 (CANONICAL_KEY_NAMES). Notable: the abuse.ch
    services (MalwareBazaar + ThreatFox + URLhaus auth) all share a single
    auth key, exposed to triage.py as ABUSECH_AUTH_KEY (not MALWAREBAZAAR_*).
    """
    env = os.environ.copy()
    if settings.virustotal_api_key:
        env["VIRUSTOTAL_API_KEY"] = settings.virustotal_api_key.get_secret_value()
    if settings.abuseipdb_api_key:
        env["ABUSEIPDB_API_KEY"] = settings.abuseipdb_api_key.get_secret_value()
    if settings.otx_api_key:
        env["OTX_API_KEY"] = settings.otx_api_key.get_secret_value()
    if settings.abusech_auth_key:
        env["ABUSECH_AUTH_KEY"] = settings.abusech_auth_key.get_secret_value()
    if settings.ipinfo_token:
        env["IPINFO_TOKEN"] = settings.ipinfo_token.get_secret_value()
    return env


async def triage(
    ioc: str,
    ioc_type: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run triage.py against a single IOC. Returns the full JSON report."""
    cmd = ["python3", str(settings.triage_script_path), ioc, "-f", "json"]
    if ioc_type:
        cmd.extend(["-t", ioc_type])

    logger.info("triage.start", ioc=ioc, type=ioc_type, cmd=cmd[:3] + ["…"])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error("triage.timeout", ioc=ioc, timeout=timeout)
        return {"query": {"ioc": ioc, "type": ioc_type}, "error": "timeout", "sources": []}

    if proc.returncode != 0:
        logger.error(
            "triage.failed", ioc=ioc, returncode=proc.returncode, stderr=stderr.decode()[:500]
        )
        return {
            "query": {"ioc": ioc, "type": ioc_type},
            "error": stderr.decode()[:500],
            "sources": [],
        }

    try:
        return json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        logger.error(
            "triage.invalid_json",
            ioc=ioc,
            error=str(e),
            preview=stdout[:200].decode("utf-8", "replace"),
        )
        return {"query": {"ioc": ioc, "type": ioc_type}, "error": "invalid_json", "sources": []}


async def triage_many(
    iocs: list[tuple[str, str | None]], timeout: int = 90
) -> list[dict[str, Any]]:
    """Run triage on multiple IOCs in parallel (bounded concurrency)."""
    sem = asyncio.Semaphore(4)

    async def _one(ioc: str, ioc_type: str | None):
        async with sem:
            return await triage(ioc, ioc_type, timeout=timeout)

    return await asyncio.gather(*[_one(i, t) for i, t in iocs])
