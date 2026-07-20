"""BYOK — per-tenant LLM override resolution + provider rules.

The endpoint CRUD and DB-backed `resolve_tenant_llm` are validated on the stack;
here we lock the precedence in `_resolve_call` (tenant BYOK → admin global → env)
and the provider requirement helpers.
"""

from __future__ import annotations

import uuid

from isoc_api.llm import byok_store
from isoc_api.llm import client as llm_client
from isoc_api.llm.byok_store import TenantLLM
from isoc_api.llm.config_store import LLMDynConfig

DYN = LLMDynConfig(
    endpoint_url="http://admin-llm:9000",
    api_key="admin-key",  # pragma: allowlist secret
    model_name="admin-model",
    temperature=0.2,
    max_tokens=4096,
)


def _mock(monkeypatch, *, dyn, tenant):
    async def fake_get_cfg():
        return dyn

    async def fake_resolve(_tid):
        return tenant

    monkeypatch.setattr("isoc_api.llm.config_store.get_llm_config", fake_get_cfg)
    monkeypatch.setattr("isoc_api.llm.byok_store.resolve_tenant_llm", fake_resolve)


async def test_no_tenant_uses_global_admin(monkeypatch):
    _mock(monkeypatch, dyn=DYN, tenant=None)  # request_tenant defaults to None
    client, model, _mt, _t = await llm_client._resolve_call(None, None, None)
    assert model == "admin-model"
    assert "admin-llm" in str(client.base_url)


async def test_tenant_byok_wins_over_global(monkeypatch):
    _mock(
        monkeypatch,
        dyn=DYN,
        tenant=TenantLLM(
            provider="ollama", base_url="http://ollama:11434", model="llama3", api_key=""
        ),
    )
    tok = llm_client.request_tenant.set(uuid.uuid4())
    try:
        client, model, _mt, _t = await llm_client._resolve_call(None, None, None)
    finally:
        llm_client.request_tenant.reset(tok)
    assert model == "llama3"
    assert "ollama:11434" in str(client.base_url)
    assert str(client.base_url).rstrip("/").endswith("/v1")


async def test_tenant_model_none_falls_back_to_admin_model(monkeypatch):
    _mock(
        monkeypatch,
        dyn=DYN,
        tenant=TenantLLM(
            provider="anthropic",
            base_url="https://api.anthropic.com",
            model=None,
            api_key="ant-key",  # pragma: allowlist secret
        ),
    )
    tok = llm_client.request_tenant.set(uuid.uuid4())
    try:
        client, model, _mt, _t = await llm_client._resolve_call(None, None, None)
    finally:
        llm_client.request_tenant.reset(tok)
    assert model == "admin-model"  # tenant has no model → global model
    assert "api.anthropic.com" in str(client.base_url)


async def test_tenant_with_no_byok_row_falls_back(monkeypatch):
    _mock(monkeypatch, dyn=DYN, tenant=None)  # tenant set but no enabled row
    tok = llm_client.request_tenant.set(uuid.uuid4())
    try:
        _client, model, _mt, _t = await llm_client._resolve_call(None, None, None)
    finally:
        llm_client.request_tenant.reset(tok)
    assert model == "admin-model"


async def test_caller_kwargs_win_over_byok_for_gen_params(monkeypatch):
    _mock(
        monkeypatch,
        dyn=DYN,
        tenant=TenantLLM(
            provider="ollama", base_url="http://ollama:11434", model="llama3", api_key=""
        ),
    )
    tok = llm_client.request_tenant.set(uuid.uuid4())
    try:
        _client, _model, mt, temp = await llm_client._resolve_call(None, 256, 0.9)
    finally:
        llm_client.request_tenant.reset(tok)
    assert mt == 256 and temp == 0.9


def test_provider_requirements():
    assert byok_store.provider_requires_api_key("openai")
    assert not byok_store.provider_requires_api_key("ollama")
    assert byok_store.provider_requires_base_url("ollama")
    assert byok_store.provider_requires_base_url("azure_openai")  # needs explicit resource endpoint
    assert not byok_store.provider_requires_base_url("openai")


def test_byok_providers_list():
    for p in ("openai", "anthropic", "azure_openai", "ollama", "vllm", "litellm", "custom"):
        assert p in byok_store.BYOK_PROVIDERS


def test_coerce_uuid():
    u = uuid.uuid4()
    assert byok_store._coerce_uuid(u) == u
    assert byok_store._coerce_uuid(str(u)) == u
    assert byok_store._coerce_uuid("not-a-uuid") is None
    assert byok_store._coerce_uuid(None) is None
