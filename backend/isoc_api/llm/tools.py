"""Read-only LLM tools for the deep-synthesis tier.

Each tool is (1) an OpenAI-format function schema advertised to the model and
(2) an async dispatch entry that executes it. Everything here is READ-ONLY and
safe to auto-execute. Write / irreversible actions (V1 isolate, blocklist,
customer-case send) are deliberately NOT exposed — those stay analyst-approved.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from ..adapters import defender_adapter, store_adapter, v1_adapter

LOOKUP_IOC_HISTORY_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "lookup_ioc_history",
        "description": (
            "Prior track record for ONE indicator — a public IP, SHA-256/SHA-1 "
            "file hash, or domain — across previously analyst-verified alerts: how "
            "many times it was seen and the verdict breakdown (TP/FP/benign). Call "
            "this when an indicator in the alert looks suspicious and its history "
            "would change the verdict. URLs, email addresses and ports are NOT "
            "tracked — do not call it for those."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "Exact IP, file hash, or domain value to look up.",
                },
            },
            "required": ["indicator"],
        },
    },
}

# name → async callable(parsed_args) -> JSON-serialisable result
DISPATCH: dict[str, Callable[[dict[str, Any]], Awaitable[Any]]] = {
    "lookup_ioc_history": lambda args: store_adapter.lookup_ioc_history(args.get("indicator", "")),
}

# The set advertised to the deep tier. Read-only; safe to auto-execute.
DEEP_TIER_TOOLS: list[dict[str, Any]] = [LOOKUP_IOC_HISTORY_TOOL]


# ── Threat-hunter live search (analyst-triggered only — NOT auto-exec) ────────
# Read-only, but hits the live V1 API per call, so it is deliberately kept OUT of
# DEEP_TIER_TOOLS. It's handed to the hunt persona only on a human-triggered hunt
# re-task (manager chat), behind settings.v1_activity_search_enabled, with a
# dispatch handler bound to the incident's resolved V1 credentials + time window.

GET_ENDPOINT_ACTIVITY_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_endpoint_activity",
        "description": (
            "Search Trend Vision One Endpoint Activity Data (read-only endpoint "
            "telemetry) to check whether a confirmed threat has spread. Pivot on an "
            "indicator — file hash, endpoint host/IP, process, or command line — "
            "across a bounded time window. Returns matching activity records "
            "(capped). Call at most a few times with focused filters."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "TMV1-Query filter. Field:value with and/or/not and ( ). "
                        "e.g. objectFileHashSha256:<sha256> · endpointHostName:HOST · "
                        "src:1.2.3.4 · processCmd:powershell"
                    ),
                },
                "start": {
                    "type": "string",
                    "description": "ISO-8601 start, e.g. 2026-07-01T00:00:00Z. Defaults to the alert window.",
                },
                "end": {
                    "type": "string",
                    "description": "ISO-8601 end. Defaults to the alert window.",
                },
                "top": {
                    "type": "integer",
                    "description": "Records per page (50/100/500/1000/5000). Default 50.",
                },
                "select": {
                    "type": "string",
                    "description": (
                        "Optional comma-separated fields to return, e.g. "
                        "endpointHostName,objectFilePath,processCmd."
                    ),
                },
            },
            "required": ["query"],
        },
    },
}

_ACTIVITY_FIELD_TRUNC = 500


def _slim_activity(rec: dict[str, Any]) -> dict[str, Any]:
    """Truncate oversized string fields (objectRawDataStr etc.) to protect the
    model's context. Non-string values pass through untouched."""
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if isinstance(v, str) and len(v) > _ACTIVITY_FIELD_TRUNC:
            out[k] = v[:_ACTIVITY_FIELD_TRUNC] + "…"
        else:
            out[k] = v
    return out


def make_endpoint_activity_handler(
    creds: Any,
    *,
    start: str | None = None,
    end: str | None = None,
    max_records: int = 200,
    collector: list[dict[str, Any]] | None = None,
) -> Callable[[dict[str, Any]], Awaitable[Any]]:
    """Build the `get_endpoint_activity` dispatch handler bound to one incident's
    resolved V1 credentials + default time window. Model-supplied start/end/top
    override the defaults per call. When `collector` is given, each call's
    `{query, count, records}` is appended for downstream persistence (the
    downloadable evidence log)."""

    async def _handler(args: dict[str, Any]) -> Any:
        query = (args.get("query") or "").strip()
        if not query:
            return {"error": "query (TMV1-Query filter) is required"}
        try:
            top = int(args.get("top") or 50)
        except (TypeError, ValueError):
            top = 50
        records = await v1_adapter.get_endpoint_activity(
            query,
            start=args.get("start") or start,
            end=args.get("end") or end,
            top=top,
            select=args.get("select"),
            region=creds.region,
            api_key=creds.api_key,
            max_records=max_records,
        )
        slimmed = [_slim_activity(r) for r in records]
        if collector is not None:
            collector.append({"query": query, "count": len(slimmed), "records": slimmed})
        return {"count": len(slimmed), "records": slimmed}

    return _handler


# ── Microsoft Defender live read tools (analyst/flag-gated — NOT auto-exec) ────
# Like the V1 activity search above: read-only but each hits the live Microsoft
# API with per-tenant creds, so they are kept OUT of DEEP_TIER_TOOLS and handed to
# the persona only via `make_defender_handlers(creds)`, behind a flag + creds check
# assembled by the caller (mirrors `_hunt_activity_tool`).

DEFENDER_RUN_HUNT_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "defender_run_hunt",
        "description": (
            "Run a Microsoft Defender advanced-hunting KQL query (read-only) to check "
            "whether a threat has spread — pivot on a process, file, IP, or host across "
            "DeviceProcessEvents / DeviceNetworkEvents / DeviceFileEvents / DeviceLogonEvents. "
            "Returns matching rows (capped). Prefer a specific filter and a limit."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kql": {
                    "type": "string",
                    "description": "Advanced-hunting KQL, e.g. DeviceNetworkEvents | where RemoteIP == '1.2.3.4' | limit 50",
                },
            },
            "required": ["kql"],
        },
    },
}

DEFENDER_GET_MACHINE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "defender_get_machine",
        "description": (
            "Microsoft Defender machine (endpoint) details by device id: risk & exposure "
            "score, business value, OS, health, last seen, and IP addresses. Use to weigh how "
            "critical or exposed the impacted host is. (Live isolation state is NOT in this "
            "call — it lives in machineActions history.)"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "machine_id": {
                    "type": "string",
                    "description": "Defender device id (from the alert's device evidence).",
                },
            },
            "required": ["machine_id"],
        },
    },
}

DEFENDER_FILE_STATS_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "defender_file_stats",
        "description": (
            "Organisation prevalence plus global first/last-seen for a file, keyed by SHA-1. "
            "Low org prevalence + recent first-seen is a rarity signal; ubiquitous long-lived "
            "files are usually benign."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "sha1": {"type": "string", "description": "File SHA-1 hash."},
            },
            "required": ["sha1"],
        },
    },
}

DEFENDER_IP_STATS_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "defender_ip_stats",
        "description": (
            "Organisation-level sighting stats for an IP address in Microsoft Defender "
            "(how much this IP is seen across the tenant)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4/IPv6 address."},
            },
            "required": ["ip"],
        },
    },
}

# The read tools advertised together when Defender live tools are enabled.
DEFENDER_TOOLS: list[dict[str, Any]] = [
    DEFENDER_RUN_HUNT_TOOL,
    DEFENDER_GET_MACHINE_TOOL,
    DEFENDER_FILE_STATS_TOOL,
    DEFENDER_IP_STATS_TOOL,
]

# Cap hunt rows handed back to the model to protect context (rows can be wide).
_DEFENDER_HUNT_MAX = 50


def make_defender_handlers(
    creds: Any,
) -> dict[str, Callable[[dict[str, Any]], Awaitable[Any]]]:
    """Build the Defender read-tool dispatch bound to one tenant's OAuth creds.

    ``creds`` carries ``oauth_tenant_id`` / ``client_id`` / ``client_secret`` (the
    microsoft_defender Integration store row). Handlers validate the required arg
    and return ``{"error": ...}`` when it is missing; adapter exceptions propagate
    and are reported back to the model by ``complete_with_tools``.
    """
    kw = {
        "tenant_id": getattr(creds, "oauth_tenant_id", None),
        "client_id": getattr(creds, "client_id", None),
        "client_secret": getattr(creds, "client_secret", None),
    }

    async def _run_hunt(args: dict[str, Any]) -> Any:
        kql = (args.get("kql") or "").strip()
        if not kql:
            return {"error": "kql (advanced-hunting query) is required"}
        rows = await defender_adapter.run_hunting_query(kql, max_records=_DEFENDER_HUNT_MAX, **kw)
        # Keep every column; truncate only oversized string values (long command
        # lines etc.) so a wide hunt can't blow the model's context — same as V1.
        slimmed = [_slim_activity(r) for r in rows]
        return {"count": len(slimmed), "results": slimmed}

    async def _get_machine(args: dict[str, Any]) -> Any:
        machine_id = (args.get("machine_id") or "").strip()
        if not machine_id:
            return {"error": "machine_id is required"}
        return await defender_adapter.get_machine(machine_id, **kw)

    async def _file_stats(args: dict[str, Any]) -> Any:
        sha1 = (args.get("sha1") or "").strip()
        if not sha1:
            return {"error": "sha1 is required"}
        return await defender_adapter.get_file_stats(sha1, **kw)

    async def _ip_stats(args: dict[str, Any]) -> Any:
        ip = (args.get("ip") or "").strip()
        if not ip:
            return {"error": "ip is required"}
        return await defender_adapter.get_ip_stats(ip, **kw)

    return {
        "defender_run_hunt": _run_hunt,
        "defender_get_machine": _get_machine,
        "defender_file_stats": _file_stats,
        "defender_ip_stats": _ip_stats,
    }
