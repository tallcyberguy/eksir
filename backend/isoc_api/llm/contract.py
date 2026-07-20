"""LLM egress contract (F3) — fail-closed validator for every outbound prompt.

isoc routes its deep tier to Claude (a third party) via LiteLLM. This module is
the single choke point that inspects every prompt *before* it leaves
``llm/client.py`` and refuses to send content that shouldn't reach an external
model.

Policy: **Strict.** Forbidden inputs (any one aborts the call):

* raw OCSF JSON (``class_uid`` / ``activity_id`` / ``metadata.product`` blocks …),
* raw vendor log lines (Splunk ``_raw``/``sourcetype`` envelopes, Sysmon/Windows
  XML, EDR/Sentinel event arrays …),
* secret-shaped values (api keys, bearer tokens, passwords, PEM private keys),
* oversize messages (a single prompt over the char cap).

Allowed: the curated ``briefing.render()`` markdown (after the raw block was
removed — see ``pipeline/briefing.py``), persona system prompts, MITRE IDs,
scores, IOC values, RAG/KB snippets, prior-verdict reasons.

The validator is intentionally heuristic — a false positive (a blocked call) is
far cheaper than a false negative (a leak). Operators control enforcement with
``settings.isoc_llm_contract_mode`` (``off`` / ``report`` / ``enforce``); the
default is ``report`` so violations are logged but never block until the
heuristics are proven clean against live traffic.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.llm.contract")


# Dict keys that betray a raw OCSF event.
_OCSF_KEYS = frozenset(
    {
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "metadata",
        "time_dt",
        "observables",
        "raw_data",
    }
)
# Dict keys that betray a raw vendor/Windows log record.
_LOG_KEYS = frozenset(
    {
        "Event",
        "EventData",
        "Sysmon",
        "RecordID",
        "EventRecordID",
        "Channel",
        "Provider",
        "_raw",
        "_time",
        "punct",
    }
)

# Raw-log signatures caught even when the payload is a string, not a dict.
_LOG_SHAPE_PATTERNS = (
    re.compile(r'"class_uid"\s*:\s*\d+'),
    re.compile(r'"activity_id"\s*:\s*\d+'),
    re.compile(r'"EventID"\s*:\s*\d+'),
    re.compile(r'"EventRecordID"\s*:\s*\d+'),
    re.compile(r'<Event xmlns="http://schemas\.microsoft\.com/win/'),
    re.compile(r'"_raw"\s*:\s*"'),
    re.compile(r'"sourcetype"\s*:\s*"'),
)

# Loose secret signatures — belt-and-braces. The reason string deliberately
# NEVER includes the matched value, so a violation log can't itself leak the
# secret. Each entry is (label, pattern).
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "credential-keyword",
        re.compile(
            r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
    ),
    ("pem-private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

_MAX_JSON_LINE_KEYS = 6  # "looks like a log line" key-count threshold


class LLMContractViolation(RuntimeError):
    """Raised when a prompt about to be sent to an LLM violates the contract."""

    def __init__(self, reason: str, *, role: str | None = None, index: int | None = None) -> None:
        msg = f"[LLMEgressContract] {reason}"
        if role:
            msg += f" (role={role})"
        super().__init__(msg)
        self.reason = reason
        self.role = role
        self.index = index


# ── Heuristic classifier ──────────────────────────────────────────────────


def _looks_like_ocsf(payload: dict[str, Any]) -> str | None:
    matched = _OCSF_KEYS & set(payload.keys())
    if matched:
        return f"OCSF keys present: {sorted(matched)}"
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and {"product", "version"} <= set(metadata.keys()):
        return "OCSF-style metadata.product/version block"
    return None


def _looks_like_raw_log(payload: dict[str, Any]) -> str | None:
    matched = _LOG_KEYS & set(payload.keys())
    if matched:
        return f"raw-log keys present: {sorted(matched)}"
    if isinstance(payload.get("EventID"), int) and "Channel" in payload:
        return "Windows event-log shape (EventID + Channel)"
    return None


def _looks_like_log_string(text: str) -> str | None:
    # Scan the full (already size-capped) message — a raw block buried deep in a
    # long prompt must still be caught under the Strict policy.
    for pattern in _LOG_SHAPE_PATTERNS:
        m = pattern.search(text)
        if m:
            return f"raw-log signature matched: {m.group(0)[:80]}"
    return None


def _looks_like_secret(text: str) -> str | None:
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            # NB: value intentionally omitted so the log can't leak the secret.
            return f"secret-shaped value detected (pattern: {label})"
    return None


def _try_load_json(text: str) -> Any | None:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None


def classify_message(content: str, *, max_chars: int) -> str | None:
    """Return a violation reason if ``content`` breaches the contract, else None."""
    if not isinstance(content, str):
        return f"non-string message content (type={type(content).__name__})"

    if len(content) > max_chars:
        return f"message exceeds size cap ({len(content)} > {max_chars} chars)"

    # 1) Substring scan — fastest path, catches shapes embedded in prose.
    log_hit = _looks_like_log_string(content)
    if log_hit:
        return log_hit

    secret_hit = _looks_like_secret(content)
    if secret_hit:
        return secret_hit

    # 2) JSON inspection — only when the message *looks* like JSON.
    parsed = _try_load_json(content)
    if isinstance(parsed, dict):
        ocsf = _looks_like_ocsf(parsed)
        if ocsf:
            return ocsf
        log = _looks_like_raw_log(parsed)
        if log:
            return log
    elif isinstance(parsed, list) and parsed:
        head = parsed[0]
        if isinstance(head, dict):
            if len(head) > _MAX_JSON_LINE_KEYS and (
                _looks_like_ocsf(head) or _looks_like_raw_log(head)
            ):
                return "raw event array detected (looks like log batch)"

    return None


# ── Public API ────────────────────────────────────────────────────────────


def _coerce(msg: Any) -> tuple[str, str]:
    """Best-effort (role, content) from a chat-message-shaped object."""
    if isinstance(msg, dict):
        role = str(msg.get("role") or "user")
        content = msg.get("content")
        return role, content if isinstance(content, str) else json.dumps(content, default=str)
    if isinstance(msg, tuple) and len(msg) == 2:
        role, content = msg
        return str(role), content if isinstance(content, str) else json.dumps(content, default=str)
    return "user", str(msg)


def validate_messages(messages: Iterable[Any], *, max_chars: int | None = None) -> None:
    """Raise :class:`LLMContractViolation` on the first message that breaches the
    contract. Pure check — does not consult the enforcement mode."""
    cap = settings.isoc_llm_contract_max_chars if max_chars is None else max_chars
    for idx, msg in enumerate(messages):
        role, content = _coerce(msg)
        reason = classify_message(content, max_chars=cap)
        if reason:
            raise LLMContractViolation(
                f"message[{idx}] failed contract: {reason}", role=role, index=idx
            )


def enforce_egress(
    *,
    system: str,
    user: str,
    mode: str | None = None,
    max_chars: int | None = None,
) -> str | None:
    """Inspect a ``(system, user)`` prompt pair against the contract.

    Honors the enforcement mode (``settings.isoc_llm_contract_mode`` unless
    overridden):

    * ``off``     → no inspection, returns ``None``.
    * ``report``  → inspect; on violation log a warning; always returns ``None``
      (never blocks).
    * ``enforce`` → inspect; on violation log a warning and **return the reason
      string** so the caller can abort the LLM call.

    The reason string never contains a matched secret value (see
    ``_looks_like_secret``), so it is safe to log and to store on
    ``LLMResult.error``.
    """
    effective_mode = (mode or settings.isoc_llm_contract_mode or "report").lower()
    if effective_mode == "off":
        return None

    cap = settings.isoc_llm_contract_max_chars if max_chars is None else max_chars
    for role, content in (("system", system), ("user", user)):
        reason = classify_message(content, max_chars=cap)
        if not reason:
            continue
        logger.warning(
            "llm.contract.violation",
            mode=effective_mode,
            role=role,
            reason=reason,
            content_chars=len(content) if isinstance(content, str) else None,
        )
        if effective_mode == "enforce":
            return f"egress blocked — {role} message: {reason}"
        # report mode: keep scanning so all violations get logged, but never block.
    return None
