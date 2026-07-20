"""Connectors framework — test-connection dispatcher.

Validates that stored credentials actually authenticate, by delegating to the connector's own
``Connector.test_connection`` (ADR-0006 — the metadata + runtime surface live on one class). A
connector with no live adapter returns a clear ``no_adapter`` status (credentials are stored, but
live testing arrives with the adapter). Read-only — test-connection never mutates the remote system.
"""

from __future__ import annotations

from typing import Any

from . import registry


async def test_connection(provider: str, creds: Any) -> dict:
    """`{ok: bool|None, status: str, detail: str}`. ok=None means 'stored but not
    live-testable yet' (not a failure)."""
    spec = registry.get_spec(provider)
    if spec is None:
        return {
            "ok": False,
            "status": "unknown_provider",
            "detail": f"No connector named {provider!r}.",
        }
    if spec.adapter_status != "live":
        return {
            "ok": None,
            "status": "no_adapter",
            "detail": f"Credentials stored. Live connection testing for {spec.label} "
            "arrives when its adapter ships.",
        }
    conn = registry.get_connector(provider)
    if conn is None:
        return {"ok": None, "status": "no_adapter", "detail": "No tester wired for this connector."}
    try:
        return await conn.test_connection(creds)
    except Exception as exc:  # a connector tester should catch its own errors; this is the backstop
        return {"ok": False, "status": "error", "detail": str(exc)[:200]}
