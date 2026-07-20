#!/usr/bin/env python3
"""
Alert Memory MCP Server

Tools:
  - index_alert        : Parse + embed + store an alert
  - search_similar     : Find semantically similar past alerts
  - search_ioc         : Check if an IP/hash was seen before (cross-customer)
  - save_verdict       : Record analyst decision (TP/FP/benign)
  - get_stats          : Collection statistics

Run:
  python3 server.py

Claude Code config (~/.claude/settings.json):
  {
    "mcpServers": {
      "alert-memory": {
        "type": "stdio",
        "command": "python3",
        "args": ["/path/to/alert-memory-mcp/server.py"]
      }
    }
  }
"""

import sys
import os
import json

# Ensure local modules are importable regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

import parsers
import embedder
from store import AlertStore
from normalizer import NormalizedAlert

app = Server("alert-memory")
store: AlertStore = None  # lazy-init after startup checks


def get_store() -> AlertStore:
    global store
    if store is None:
        store = AlertStore()
    return store


# ──────────────────────────────────────────────
# Tool definitions
# ──────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="index_alert",
            description=(
                "Parse, normalize and index a security alert into the vector database. "
                "Supports QRadar email format and Wazuh JSON format (auto-detected). "
                "Call this after analyzing an alert to build up the memory."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "raw_alert": {
                        "type": "string",
                        "description": "Full alert text (QRadar email) or JSON string (Wazuh)"
                    },
                    "customer": {
                        "type": "string",
                        "description": "Customer identifier for multi-tenant isolation (e.g. 'contoso', 'fabrikam')"
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["TP", "FP", "benign"],
                        "description": "Optional: analyst verdict if already known"
                    },
                    "verdict_reason": {
                        "type": "string",
                        "description": "Optional: short reason for the verdict"
                    }
                },
                "required": ["raw_alert", "customer"]
            }
        ),

        types.Tool(
            name="search_similar",
            description=(
                "Search the alert memory for past alerts semantically similar to a given alert. "
                "Returns top matches with their verdicts. Use this at the START of analyzing "
                "a new alert to check if a similar case was handled before."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_text": {
                        "type": "string",
                        "description": "Description or embed_text of the alert to search for"
                    },
                    "customer": {
                        "type": "string",
                        "description": "Restrict search to this customer. Omit for cross-customer search."
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return (default: 3)",
                        "default": 3
                    }
                },
                "required": ["alert_text"]
            }
        ),

        types.Tool(
            name="search_ioc",
            description=(
                "Check if an IP address or file hash has been seen in past alerts "
                "across all customers. Useful for cross-customer IOC correlation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "IP address or file hash (SHA256/SHA1) to look up"
                    }
                },
                "required": ["indicator"]
            }
        ),

        types.Tool(
            name="save_verdict",
            description=(
                "Save analyst verdict (TP/FP/benign) for a previously indexed alert. "
                "The verdict is embedded into the vector so future similarity searches "
                "will surface it as context."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "UUID of the alert (returned by index_alert)"
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["TP", "FP", "benign"],
                        "description": "Analyst decision"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Short explanation (e.g. 'Expired password, mapped drive retry')"
                    },
                    "analyst": {
                        "type": "string",
                        "description": "Analyst identifier"
                    }
                },
                "required": ["alert_id", "verdict", "reason"]
            }
        ),

        types.Tool(
            name="get_stats",
            description="Return statistics about the alert memory collection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "customer": {
                        "type": "string",
                        "description": "Optional: filter stats by customer"
                    }
                }
            }
        ),
    ]


# ──────────────────────────────────────────────
# Tool handlers
# ──────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    if name == "index_alert":
        return await _index_alert(arguments)
    elif name == "search_similar":
        return await _search_similar(arguments)
    elif name == "search_ioc":
        return await _search_ioc(arguments)
    elif name == "save_verdict":
        return await _save_verdict(arguments)
    elif name == "get_stats":
        return await _get_stats(arguments)
    else:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


async def _index_alert(args: dict) -> list[types.TextContent]:
    raw = args["raw_alert"]
    customer = args.get("customer")
    verdict = args.get("verdict")
    verdict_reason = args.get("verdict_reason")

    try:
        # Auto-detect format and parse
        try:
            parsed_raw = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            parsed_raw = raw

        alert = parsers.parse(parsed_raw, customer=customer)

        if verdict:
            alert.verdict = verdict
            alert.verdict_reason = verdict_reason
            alert = alert.finalize()

        alert_id = get_store().index_alert(alert)

        result = {
            "alert_id": alert_id,
            "source_product": alert.source_product,
            "customer": alert.customer,
            "rule_name": alert.rule_name,
            "threat_category": alert.threat_category,
            "severity": f"{alert.severity} ({alert.severity_label})",
            "src_ip": alert.src_ip,
            "mitre_technique": alert.mitre_technique,
            "cve": alert.cve,
            "verdict": alert.verdict,
            "embed_text": alert.embed_text,
            "status": "indexed"
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        return [types.TextContent(type="text", text=f"Error indexing alert: {e}")]


async def _search_similar(args: dict) -> list[types.TextContent]:
    alert_text = args["alert_text"]
    customer = args.get("customer")
    top_k = int(args.get("top_k", 3))

    try:
        # Build a minimal NormalizedAlert just for embedding
        query = NormalizedAlert(
            rule_name=alert_text,
            embed_text=alert_text,
        )

        results = get_store().search_similar(query, customer=customer, top_k=top_k)

        if not results:
            return [types.TextContent(type="text", text="No similar alerts found in memory.")]

        lines = [f"Found {len(results)} similar alert(s):\n"]
        for i, r in enumerate(results, 1):
            verdict_str = f"{r['verdict']} — {r['verdict_reason']}" if r['verdict'] else "no verdict yet"
            lines.append(
                f"{i}. [score={r['score']}] {r['rule_name']}\n"
                f"   customer={r['customer']} | category={r['threat_category']}\n"
                f"   src_ip={r['src_ip']} | timestamp={r['timestamp']}\n"
                f"   verdict: {verdict_str}\n"
                f"   alert_id: {r['alert_id']}\n"
            )

        return [types.TextContent(type="text", text="\n".join(lines))]

    except Exception as e:
        return [types.TextContent(type="text", text=f"Error searching: {e}")]


async def _search_ioc(args: dict) -> list[types.TextContent]:
    indicator = args["indicator"]

    try:
        results = get_store().search_ioc(indicator)

        if not results:
            return [types.TextContent(
                type="text",
                text=f"IOC '{indicator}' not found in alert memory."
            )]

        lines = [f"IOC '{indicator}' found in {len(results)} past alert(s):\n"]
        for r in results:
            lines.append(
                f"- customer={r['customer']} | rule={r['rule_name']}\n"
                f"  timestamp={r['timestamp']} | verdict={r.get('verdict', 'none')}\n"
                f"  alert_id={r['alert_id']}\n"
            )

        return [types.TextContent(type="text", text="\n".join(lines))]

    except Exception as e:
        return [types.TextContent(type="text", text=f"Error searching IOC: {e}")]


async def _save_verdict(args: dict) -> list[types.TextContent]:
    alert_id = args["alert_id"]
    verdict = args["verdict"]
    reason = args["reason"]
    analyst = args.get("analyst", "claude")

    try:
        ok = get_store().save_verdict(alert_id, verdict, reason, analyst)
        if ok:
            return [types.TextContent(
                type="text",
                text=f"Verdict saved: alert_id={alert_id} verdict={verdict} reason='{reason}'"
            )]
        else:
            return [types.TextContent(
                type="text",
                text=f"Alert ID not found: {alert_id}"
            )]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error saving verdict: {e}")]


async def _get_stats(args: dict) -> list[types.TextContent]:
    customer = args.get("customer")
    try:
        stats = get_store().stats(customer=customer)
        return [types.TextContent(type="text", text=json.dumps(stats, indent=2))]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error getting stats: {e}")]


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

async def main():
    # Pre-flight checks
    print("[alert-memory] Checking Ollama...", file=sys.stderr)
    try:
        embedder.check_or_raise()
        print("[alert-memory] Ollama OK", file=sys.stderr)
    except Exception as e:
        print(f"[alert-memory] WARNING: {e}", file=sys.stderr)

    print("[alert-memory] Connecting to Qdrant...", file=sys.stderr)
    try:
        get_store()
        print("[alert-memory] Qdrant OK", file=sys.stderr)
    except Exception as e:
        print(f"[alert-memory] WARNING: {e}", file=sys.stderr)

    print("[alert-memory] Server ready", file=sys.stderr)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
