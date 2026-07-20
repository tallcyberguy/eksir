"""ipinfo.io + rDNS lookups. Used when an alert has a public IP but triage misses it."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import httpx

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.adapter.ipinfo")


async def reverse_dns(ip: str) -> str | None:
    try:
        return await asyncio.to_thread(lambda: socket.gethostbyaddr(ip)[0])
    except Exception:
        return None


async def ipinfo(ip: str, timeout: float = 5.0) -> dict[str, Any] | None:
    headers = {}
    token = settings.ipinfo_token
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url = f"https://ipinfo.io/{ip}?token={token.get_secret_value()}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers=headers)
        if r.status_code == 200:
            return r.json()
        logger.warning("ipinfo.bad_status", ip=ip, status=r.status_code)
        return None
    except Exception as e:
        logger.warning("ipinfo.failed", ip=ip, error=str(e))
        return None


async def enrich_ip(ip: str) -> dict[str, Any]:
    rdns_task = asyncio.create_task(reverse_dns(ip))
    info_task = asyncio.create_task(ipinfo(ip))
    rdns, info = await asyncio.gather(rdns_task, info_task)
    return {
        "ip": ip,
        "rdns": rdns,
        "org": (info or {}).get("org"),
        "city": (info or {}).get("city"),
        "country": (info or {}).get("country"),
        "hostname": (info or {}).get("hostname"),
        "raw": info,
    }
