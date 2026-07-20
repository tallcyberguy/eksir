"""Tests for the Vision One collectFile request body.

V1 identifies the target endpoint by `agentGuid` (preferred / FedRAMP-required)
or `endpointName` — exactly one per entry. These pin the body-building + the
fail-fast validation without touching the network (the HTTP client is faked).
"""

from __future__ import annotations

import httpx
import pytest

from isoc_api.adapters import v1_adapter


class _FakeClient:
    """Captures the POST body instead of hitting the API."""

    def __init__(self, capture: dict):
        self._capture = capture

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *_a) -> bool:
        return False

    async def post(self, url, json=None, headers=None):  # noqa: A002 - mirror httpx
        self._capture.update(url=url, json=json, headers=headers)
        return httpx.Response(200, json={"id": "task-123"})


def _patch_client(monkeypatch) -> dict:
    capture: dict = {}
    monkeypatch.setattr(v1_adapter, "_client", lambda **_kw: _FakeClient(capture))
    return capture


async def test_collect_file_prefers_agent_guid(monkeypatch):
    cap = _patch_client(monkeypatch)
    out = await v1_adapter.collect_file(
        "DESKTOP-ABC", "C:/tmp/x.exe", "why", agent_guid="11111111-1111-1111-1111-111111111111"
    )
    assert out == {"id": "task-123"}
    assert cap["url"] == "v3.0/response/endpoints/collectFile"
    entry = cap["json"][0]
    # agentGuid wins; endpointName must NOT be sent alongside it.
    assert entry["agentGuid"] == "11111111-1111-1111-1111-111111111111"
    assert "endpointName" not in entry
    assert entry["filePath"] == "C:/tmp/x.exe"
    assert entry["description"] == "why"


async def test_collect_file_falls_back_to_endpoint_name(monkeypatch):
    cap = _patch_client(monkeypatch)
    await v1_adapter.collect_file("DESKTOP-ABC", "C:/tmp/x.exe")
    entry = cap["json"][0]
    assert entry["endpointName"] == "DESKTOP-ABC"
    assert "agentGuid" not in entry
    # empty description is omitted, not sent as ""
    assert "description" not in entry


async def test_collect_file_requires_a_target(monkeypatch):
    _patch_client(monkeypatch)
    with pytest.raises(v1_adapter.VisionOneError, match="agent_guid or endpoint_name"):
        await v1_adapter.collect_file(file_path="C:/tmp/x.exe")


async def test_collect_file_requires_file_path(monkeypatch):
    _patch_client(monkeypatch)
    with pytest.raises(v1_adapter.VisionOneError, match="file_path"):
        await v1_adapter.collect_file(endpoint_name="DESKTOP-ABC")


async def test_collect_file_rejects_slash_only_path(monkeypatch):
    _patch_client(monkeypatch)
    for junk in ("\\", "  ", "//"):
        with pytest.raises(v1_adapter.VisionOneError, match="real file_path"):
            await v1_adapter.collect_file(endpoint_name="H", file_path=junk)


# ── 207 Multi-Status interpretation ──────────────────────────────────────────


def test_parse_response_task_success_extracts_task_id():
    body = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://api.eu.xdr.trendmicro.com/v3.0/response/tasks/00000012",
                }
            ],
        }
    ]
    p = v1_adapter.parse_response_task(body)
    assert p["ok"] is True
    assert p["item_status"] == 202
    assert p["task_id"] == "00000012"
    assert p["task_url"].endswith("/00000012")


def test_parse_response_task_item_failure():
    body = [{"status": 400, "body": {"error": {"code": "BadRequest", "message": "invalid path"}}}]
    p = v1_adapter.parse_response_task(body)
    assert p["ok"] is False
    assert p["item_status"] == 400
    assert p["error"] == "invalid path"
    assert p["task_id"] is None


def test_parse_response_task_unknown_shape_defaults_ok():
    # No parseable per-item status → don't invent a failure (status-quo success).
    assert v1_adapter.parse_response_task({})["ok"] is True
    assert v1_adapter.parse_response_task([])["ok"] is True
    assert v1_adapter.parse_response_task(None)["ok"] is True
