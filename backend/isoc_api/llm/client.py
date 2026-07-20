"""LLM client — talks to the LiteLLM proxy via the OpenAI-compatible API.

Backend only ever references virtual model names from settings
(`isoc_model_deep`, `isoc_model_fast`). The mapping to a real provider
(Anthropic, vLLM, OpenAI) lives in config/litellm.config.yaml.

Dynamic config
--------------
Admins can override the endpoint, API key, model and generation parameters via
the UI.  On every `complete()` call the config store is consulted (60-second
in-process cache); if a DB config exists it takes precedence over env vars.
The module-level ``_default_client`` is kept as a fallback for when the table
is empty (first boot, no admin config yet).
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import re
import time
from dataclasses import dataclass

import tiktoken
from openai import AsyncOpenAI

from ..logging_config import get_logger
from ..settings import settings
from .contract import enforce_egress

logger = get_logger("isoc.llm")

# BYOK — the tenant whose per-tenant LLM override (if any) applies to the calls
# made in the current async context. Set by the pipeline (run_pipeline) from
# incident.tenant_id; default None means "no tenant binding → global/env config".
request_tenant: contextvars.ContextVar = contextvars.ContextVar("isoc_request_tenant", default=None)

# Env-var based client — used when admin has not yet configured an override.
_default_client = AsyncOpenAI(
    base_url=f"{settings.litellm_base_url}/v1",
    api_key=settings.litellm_master_key.get_secret_value(),
    timeout=settings.pipeline_max_llm_seconds,
    max_retries=2,
)

try:
    _tokenizer = tiktoken.get_encoding("cl100k_base")
except Exception:
    _tokenizer = None


def count_tokens(text: str) -> int:
    if _tokenizer is None:
        # Conservative fallback: 4 chars per token
        return max(1, len(text) // 4)
    return len(_tokenizer.encode(text))


# A degenerating model (near-greedy decoding on a repetitive template) can lock
# into emitting the SAME character forever — INC-001131 filled its whole 8192-
# token budget with ~128 KB of spaces while trying to pad a markdown table.
# The stored report then renders as an empty/broken section on the UI. These
# thresholds are far above anything a real SOC report needs (a padded table cell
# is well under 40 chars), so collapsing longer runs only ever fires on the
# pathology — it never touches legitimate output.
_RUNAWAY_HSPACE = re.compile(r"[^\S\n]{40,}")  # 40+ spaces/tabs (no newline)
_RUNAWAY_BLANKS = re.compile(r"\n{10,}")  # 10+ consecutive newlines
_RUNAWAY_CHAR = re.compile(r"(\S)\1{59,}")  # 60+ of the same non-space char


def sanitize_llm_text(text: str) -> tuple[str, bool]:
    """Collapse runaway character repetition from a degenerated completion.

    Returns ``(clean_text, changed)``. ``changed`` is True when a pathological
    run was collapsed — the caller logs it so silent degeneration is visible.
    """
    if not text:
        return text, False
    cleaned = _RUNAWAY_HSPACE.sub(" ", text)
    cleaned = _RUNAWAY_BLANKS.sub("\n\n", cleaned)
    cleaned = _RUNAWAY_CHAR.sub(lambda m: m.group(1) * 3, cleaned)
    # `changed` reflects a real runaway collapse only — a trailing-newline trim
    # (below) is normal cleanup and must not flag a healthy report as degenerate.
    changed = cleaned != text
    return cleaned.rstrip(), changed


@dataclass(slots=True)
class LLMResult:
    text: str
    model: str
    provider: str | None
    input_tokens: int
    output_tokens: int
    latency_ms: int
    prompt_hash: str
    status: str  # 'ok' | 'timeout' | 'error' | 'blocked'
    error: str | None = None
    # Full inputs — populated unconditionally; persistence is the caller's call.
    # Keeping them here lets one persistence path apply across every call site
    # without each having to reconstruct what was sent.
    system_prompt: str = ""
    user_prompt: str = ""


async def _resolve_call(
    model: str | None,
    max_tokens: int | None,
    temperature: float | None,
) -> tuple[AsyncOpenAI, str, int, float]:
    """Resolve (client, model, max_tokens, temperature) honouring admin DB config.

    Endpoint / key / model precedence:
      - If the llm_config table has a row (admin configured): use its endpoint,
        key and MODEL. The caller's `model` kwarg is IGNORED because it is a
        LiteLLM virtual name (isoc-fast/isoc-deep) that won't resolve on a direct
        endpoint such as Ollama.
      - Otherwise: env-var defaults (litellm_base_url / litellm_master_key) and
        the caller's `model` (or isoc_model_deep) routed through LiteLLM.

    max_tokens / temperature precedence (both paths):
      caller kwarg → DB config value → hard default (4096 / 0.2).
    """
    from .config_store import get_llm_config

    dyn = await get_llm_config()

    # BYOK: an enabled per-tenant override wins over the global admin config and
    # env defaults. The tenant is bound for the current run via `request_tenant`
    # (set in run_pipeline); absent it, behaviour is unchanged.
    eff_tenant = request_tenant.get()
    if eff_tenant is not None:
        from .byok_store import resolve_tenant_llm

        tenant_cfg = await resolve_tenant_llm(eff_tenant)
        if tenant_cfg is not None and tenant_cfg.base_url:
            _t_base = tenant_cfg.base_url.rstrip("/")
            if not _t_base.endswith("/v1"):
                _t_base = f"{_t_base}/v1"
            return (
                AsyncOpenAI(
                    base_url=_t_base,
                    api_key=tenant_cfg.api_key
                    or (dyn.api_key if dyn else None)
                    or "sk-placeholder",
                    timeout=settings.pipeline_max_llm_seconds,
                    max_retries=2,
                ),
                tenant_cfg.model
                or (dyn.model_name if dyn else (model or settings.isoc_model_deep)),
                max_tokens if max_tokens is not None else (dyn.max_tokens if dyn else 4096),
                temperature if temperature is not None else (dyn.temperature if dyn else 0.2),
            )

    if dyn is not None:
        effective_model = dyn.model_name
        effective_max_tokens = max_tokens if max_tokens is not None else dyn.max_tokens
        effective_temperature = temperature if temperature is not None else dyn.temperature
        # Normalise to always end with /v1 so the OpenAI SDK constructs the full
        # path correctly regardless of what the admin typed.
        _base = dyn.endpoint_url.rstrip("/")
        if not _base.endswith("/v1"):
            _base = f"{_base}/v1"
        client = AsyncOpenAI(
            base_url=_base,
            api_key=dyn.api_key or "sk-placeholder",
            timeout=settings.pipeline_max_llm_seconds,
            max_retries=2,
        )
    else:
        effective_model = model or settings.isoc_model_deep
        effective_max_tokens = max_tokens if max_tokens is not None else 4096
        effective_temperature = temperature if temperature is not None else 0.2
        client = _default_client

    return client, effective_model, effective_max_tokens, effective_temperature


def _blocked_result(
    *, system: str, user: str, model_name: str, prompt: str, prompt_hash: str, reason: str
) -> LLMResult:
    """Build the LLMResult for a call the egress contract refused to send."""
    logger.error("llm.blocked", model=model_name, reason=reason)
    return LLMResult(
        text="",
        model=model_name,
        provider=None,
        input_tokens=count_tokens(prompt),
        output_tokens=0,
        latency_ms=0,
        prompt_hash=prompt_hash,
        status="blocked",
        error=reason,
        system_prompt=system,
        user_prompt=user,
    )


async def complete(
    *,
    system: str,
    user: str,
    model: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> LLMResult:
    """Single-turn completion. Logs to caller's incident_id externally.

    Endpoint / key / model and max_tokens / temperature precedence are resolved
    by ``_resolve_call`` (admin DB config overrides env-var defaults).
    """
    client, model_name, effective_max_tokens, effective_temperature = await _resolve_call(
        model, max_tokens, temperature
    )

    prompt = f"{system}\n\n---\n\n{user}"
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    blocked = enforce_egress(system=system, user=user)
    if blocked:
        return _blocked_result(
            system=system,
            user=user,
            model_name=model_name,
            prompt=prompt,
            prompt_hash=prompt_hash,
            reason=blocked,
        )

    started = time.perf_counter()

    try:
        resp = await client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=effective_max_tokens,
            temperature=effective_temperature,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        choice = resp.choices[0]
        usage = resp.usage
        text = choice.message.content or ""
        text, degenerated = sanitize_llm_text(text)
        finish_reason = getattr(choice, "finish_reason", None)
        if degenerated or finish_reason == "length":
            logger.warning(
                "llm.output_degenerated",
                model=model_name,
                finish_reason=finish_reason,
                collapsed_repetition=degenerated,
                output_tokens=(usage.completion_tokens if usage else None),
            )
        provider = (resp.model or "").split("/", 1)[0] if "/" in (resp.model or "") else None

        return LLMResult(
            text=text,
            model=model_name,
            provider=provider,
            input_tokens=(usage.prompt_tokens if usage else count_tokens(prompt)),
            output_tokens=(usage.completion_tokens if usage else count_tokens(text)),
            latency_ms=latency_ms,
            prompt_hash=prompt_hash,
            status="ok",
            system_prompt=system,
            user_prompt=user,
        )
    except TimeoutError as e:
        latency_ms = int((time.perf_counter() - started) * 1000)
        logger.error("llm.timeout", model=model_name, error=str(e))
        return LLMResult(
            text="",
            model=model_name,
            provider=None,
            input_tokens=count_tokens(prompt),
            output_tokens=0,
            latency_ms=latency_ms,
            prompt_hash=prompt_hash,
            status="timeout",
            error=str(e),
            system_prompt=system,
            user_prompt=user,
        )
    except Exception as e:
        latency_ms = int((time.perf_counter() - started) * 1000)
        logger.error("llm.error", model=model_name, error=str(e))
        return LLMResult(
            text="",
            model=model_name,
            provider=None,
            input_tokens=count_tokens(prompt),
            output_tokens=0,
            latency_ms=latency_ms,
            prompt_hash=prompt_hash,
            status="error",
            error=str(e),
            system_prompt=system,
            user_prompt=user,
        )


async def complete_with_tools(
    *,
    system: str,
    user: str,
    tools: list[dict],
    dispatch: dict,
    model: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    max_rounds: int = 4,
    gated: bool = True,
) -> LLMResult:
    """Multi-turn completion that lets the model call tools.

    ``gated`` (default True): respect ``settings.isoc_enable_llm_tools`` — when the
    flag is off this is identical to ``complete()`` (no tools), so the automatic
    pipeline can adopt it unconditionally and flip the flag to turn tool use on.
    Pass ``gated=False`` for analyst-invoked flows (e.g. the manager chat) that
    must always have their tools regardless of the flag.

    ``dispatch`` maps a tool name to an async callable taking the parsed-args
    dict. Tools may mutate session state in analyst-invoked flows; in the gated
    automatic path they must be read-only. Token usage is summed across rounds;
    a tool that raises is reported back to the model as an error result.
    """
    if gated and not settings.isoc_enable_llm_tools:
        return await complete(
            system=system,
            user=user,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    client, model_name, eff_max_tokens, eff_temp = await _resolve_call(
        model, max_tokens, temperature
    )

    prompt = f"{system}\n\n---\n\n{user}"
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    blocked = enforce_egress(system=system, user=user)
    if blocked:
        return _blocked_result(
            system=system,
            user=user,
            model_name=model_name,
            prompt=prompt,
            prompt_hash=prompt_hash,
            reason=blocked,
        )

    messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    input_tokens = 0
    output_tokens = 0
    started = time.perf_counter()

    def _provider(resp_model: str | None) -> str | None:
        rm = resp_model or ""
        return rm.split("/", 1)[0] if "/" in rm else None

    try:
        for _round in range(max_rounds):
            resp = await client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_tokens=eff_max_tokens,
                temperature=eff_temp,
                tools=tools,
            )
            usage = resp.usage
            if usage:
                input_tokens += usage.prompt_tokens or 0
                output_tokens += usage.completion_tokens or 0

            msg = resp.choices[0].message
            tool_calls = msg.tool_calls or []
            if not tool_calls:
                text, degenerated = sanitize_llm_text(msg.content or "")
                if degenerated:
                    logger.warning("llm.output_degenerated", model=model_name, tool_path=True)
                return LLMResult(
                    text=text,
                    model=model_name,
                    provider=_provider(resp.model),
                    input_tokens=input_tokens or count_tokens(prompt),
                    output_tokens=output_tokens,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    prompt_hash=prompt_hash,
                    status="ok",
                    system_prompt=system,
                    user_prompt=user,
                )

            # Echo the assistant turn (carrying tool_calls), then each result.
            messages.append(msg.model_dump(exclude_none=True))
            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                handler = dispatch.get(name)
                if handler is None:
                    result = {"error": f"unknown tool: {name}"}
                else:
                    try:
                        result = await handler(args)
                    except Exception as e:  # a tool failure must not kill synthesis
                        logger.warning("llm.tool_failed", tool=name, error=str(e))
                        result = {"error": str(e)}
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result, default=str),
                    }
                )

        # Round budget exhausted — one final call WITHOUT tools to force an answer.
        resp = await client.chat.completions.create(
            model=model_name,
            messages=messages,
            max_tokens=eff_max_tokens,
            temperature=eff_temp,
        )
        usage = resp.usage
        if usage:
            input_tokens += usage.prompt_tokens or 0
            output_tokens += usage.completion_tokens or 0
        text, degenerated = sanitize_llm_text(resp.choices[0].message.content or "")
        if degenerated:
            logger.warning("llm.output_degenerated", model=model_name, tool_path=True)
        return LLMResult(
            text=text,
            model=model_name,
            provider=_provider(resp.model),
            input_tokens=input_tokens or count_tokens(prompt),
            output_tokens=output_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
            prompt_hash=prompt_hash,
            status="ok",
            system_prompt=system,
            user_prompt=user,
        )
    except TimeoutError as e:
        logger.error("llm.timeout", model=model_name, error=str(e))
        return LLMResult(
            text="",
            model=model_name,
            provider=None,
            input_tokens=input_tokens or count_tokens(prompt),
            output_tokens=output_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
            prompt_hash=prompt_hash,
            status="timeout",
            error=str(e),
            system_prompt=system,
            user_prompt=user,
        )
    except Exception as e:
        logger.error("llm.error", model=model_name, error=str(e))
        return LLMResult(
            text="",
            model=model_name,
            provider=None,
            input_tokens=input_tokens or count_tokens(prompt),
            output_tokens=output_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
            prompt_hash=prompt_hash,
            status="error",
            error=str(e),
            system_prompt=system,
            user_prompt=user,
        )
