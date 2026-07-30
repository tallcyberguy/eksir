"""Container performance / health (admin): read through a docker-socket-proxy.

The internet-facing backend deliberately does NOT mount the raw Docker socket
(see deploy/docker-compose.yml). Instead it reads a GET/HEAD-only slice of the
Docker Engine API via a `tecnativa/docker-socket-proxy` (POST=0). This endpoint:

- is admin-only,
- fails SOFT: if the proxy is unconfigured/unreachable it returns
  `docker_ok=false` + an empty list so the tab shows a clean "unavailable" state,
- returns a fixed WHITELIST of fields (container inspect exposes env/secrets
  like JWT_SECRET + API keys, which must never reach the browser).
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends

from ..auth.deps import require_admin
from ..db.models import User
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.performance")
router = APIRouter()

_TIMEOUT = httpx.Timeout(5.0)


def _cpu_pct(stats: dict) -> float | None:
    """Container CPU% from the Docker stats deltas (cpu vs precpu)."""
    try:
        cpu = stats["cpu_stats"]
        pre = stats["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or []) or 1
        if sys_delta > 0 and cpu_delta >= 0:
            return round((cpu_delta / sys_delta) * ncpu * 100.0, 1)
    except (KeyError, TypeError, ZeroDivisionError):
        return None
    return None


def _mem(stats: dict) -> tuple[float | None, float | None]:
    """(used_mb, limit_mb). `used` excludes inactive_file, matching `docker stats`."""
    try:
        mem = stats["memory_stats"]
        used = mem["usage"] - (mem.get("stats", {}).get("inactive_file", 0) or 0)
        limit = mem.get("limit")
        return (round(used / 1048576, 1), round(limit / 1048576, 1) if limit else None)
    except (KeyError, TypeError):
        return (None, None)


async def _container_row(client: httpx.AsyncClient, c: dict) -> dict[str, Any]:
    cid = c.get("Id", "")
    name = (c.get("Names") or ["?"])[0].lstrip("/")
    row: dict[str, Any] = {
        "name": name,
        "image": c.get("Image"),
        "state": c.get("State"),  # running | exited | ...
        "status": c.get("Status"),  # e.g. "Up 3 hours (healthy)"
        "health": None,
        "restarts": None,
        "cpu_pct": None,
        "mem_used_mb": None,
        "mem_limit_mb": None,
    }
    # Inspect → health status + restart count (fail-soft per container).
    try:
        ins = (await client.get(f"/containers/{cid}/json")).json()
        st = ins.get("State") or {}
        row["health"] = (st.get("Health") or {}).get("Status")
        row["restarts"] = ins.get("RestartCount")
    except Exception:  # pragma: no cover - best-effort enrichment
        pass
    # One-shot stats for running containers only.
    if c.get("State") == "running":
        try:
            s = (await client.get(f"/containers/{cid}/stats", params={"stream": "false"})).json()
            row["cpu_pct"] = _cpu_pct(s)
            row["mem_used_mb"], row["mem_limit_mb"] = _mem(s)
        except Exception:  # pragma: no cover - best-effort enrichment
            pass
    return row


@router.get("/overview")
async def overview(_admin: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    base = (settings.isoc_docker_proxy_url or "").rstrip("/")
    if not base:
        return {"docker_ok": False, "reason": "monitoring not configured", "containers": []}
    try:
        async with httpx.AsyncClient(base_url=base, timeout=_TIMEOUT) as client:
            resp = await client.get("/containers/json", params={"all": "1"})
            resp.raise_for_status()
            containers = resp.json()
            rows = await asyncio.gather(*(_container_row(client, c) for c in containers))
    except Exception as e:
        logger.warning("performance.docker_unreachable", error=str(e))
        return {"docker_ok": False, "reason": "docker proxy unreachable", "containers": []}
    rows.sort(key=lambda r: r["name"])
    return {"docker_ok": True, "containers": rows}
