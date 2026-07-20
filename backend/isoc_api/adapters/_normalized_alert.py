"""Helper: safely instantiate alert-memory-mcp's NormalizedAlert from a dict.

The upstream dataclass has a closed set of fields and TypeErrors on extras.
We filter the input dict to the constructor's accepted parameters.

Phase-RAG-A: `rule_name` is cleaned before construction. SIEM rule names
typically carry boilerplate (customer prefix, MITRE bracket codes, vendor
tags) that pollutes the embed_text and creates false-positive retrieval
matches between unrelated alerts that share scaffolding. We strip those
locally so the embedder sees the semantic core of the rule name. The
original rule_name still lives on `incident.rule_name` (route layer) —
this only affects what goes into Qdrant.
"""

from __future__ import annotations

import importlib
import re
from functools import lru_cache
from typing import Any

# Bracket codes like [DE.CM.1], [TA0007], [T1003.001], [Web Logs].
# Strips the entire bracketed token, including brackets.
_BRACKET_TOKEN_RE = re.compile(r"\s*\[[^\]]*\]")
# Collapse runs of whitespace produced by removal.
_WS_COLLAPSE_RE = re.compile(r"\s+")


@lru_cache(maxsize=1)
def _normalizer():
    return importlib.import_module("normalizer")


@lru_cache(maxsize=1)
def _accepted_keys() -> frozenset[str]:
    import inspect

    sig = inspect.signature(_normalizer().NormalizedAlert.__init__)
    return frozenset(name for name in sig.parameters if name not in ("self",))


def _clean_rule_name(rule_name: str | None, customer: str | None) -> str | None:
    """Strip customer prefix + bracket codes + collapse whitespace.

    Examples:
      ("CONTOSO: Exploit: Possible SQL Discovery [DE.CM.1] [TA0007]", "CONTOSO")
        → "Exploit: Possible SQL Discovery"
      ("Sysmon EID 1: encoded powershell", None)
        → "Sysmon EID 1: encoded powershell"     (no prefix to strip)

    Conservative: only strips the customer prefix when it's the literal
    "{CUSTOMER}: " at the start of the string. Bracket stripping is
    unconditional — any `[...]` token (and surrounding whitespace) is removed.
    """
    if not rule_name or not isinstance(rule_name, str):
        return rule_name

    cleaned = rule_name

    # Strip the customer prefix if present at the very start, case-insensitive.
    if customer and isinstance(customer, str):
        cust = customer.strip()
        if cust:
            head = cleaned.lstrip()
            if head.lower().startswith(cust.lower() + ":"):
                cleaned = head[len(cust) + 1 :]

    # Drop every bracketed token.
    cleaned = _BRACKET_TOKEN_RE.sub("", cleaned)

    # Collapse whitespace.
    cleaned = _WS_COLLAPSE_RE.sub(" ", cleaned).strip()

    # Don't return an empty string — if cleaning destroyed everything, keep
    # the original so the embedder has at least something.
    return cleaned or rule_name


def clean_rule_name(rule_name: str | None, customer: str | None) -> str | None:
    """Public wrapper around the rule_name normalizer used at index/query time.

    The exact-match gate uses this to normalize a *stored* rule_name (which may be
    raw, e.g. a SKILL-seeded row) the same way the query name was cleaned at
    build() time, so equal rules compare equal regardless of who wrote the row.
    """
    return _clean_rule_name(rule_name, customer)


@lru_cache(maxsize=1)
def _alert_class():
    """isoc's NormalizedAlert subclass with a richer embed_text (fix #3).

    The vendored ``build_embed_text`` omits email sender/recipient/subject, embeds
    ``dst_ip`` only as a suffix of the src_ip line, and never embeds the file hash
    — so email alerts embed almost no distinguishing content and same-path samples
    collide. This override appends those fields. Both the index and query paths
    construct alerts via ``build()``, so the richer text is used symmetrically on
    both sides. Kept isoc-side; the vendored normalizer (and the SKILL workflow)
    are unchanged.
    """
    base_cls = _normalizer().NormalizedAlert

    class _IsocNormalizedAlert(base_cls):  # type: ignore[valid-type,misc]
        def build_embed_text(self) -> str:
            base = base_cls.build_embed_text(self)
            extra: list[str] = []
            if getattr(self, "sender", None):
                extra.append(f"Sender: {str(self.sender)[:200]}")
            if getattr(self, "recipient", None):
                extra.append(f"Recipient: {str(self.recipient)[:200]}")
            if getattr(self, "subject", None):
                extra.append(f"Subject: {str(self.subject)[:200]}")
            # Standalone destination IP — the base only emits dst as a suffix of the
            # src_ip line, so a dst-only alert embeds no network context.
            if getattr(self, "dst_ip", None) and not getattr(self, "src_ip", None):
                dst = self.dst_ip
                if getattr(self, "dst_port", None):
                    dst = f"{self.dst_ip}:{self.dst_port}"
                extra.append(f"Destination: {dst}")
            # File hash — the base embeds the path but not the hash.
            h = getattr(self, "file_hash_sha256", None) or getattr(self, "file_hash_sha1", None)
            if h:
                extra.append(f"File hash: {h}")
            return base + "\n" + "\n".join(extra) if extra else base

    return _IsocNormalizedAlert


def build(d: dict[str, Any]):
    """Construct a NormalizedAlert from a (possibly noisy) dict.

    Drops any key not declared on the dataclass to avoid TypeError on extras
    like `application`, `url_category`, `src_zone`, etc. Also cleans
    `rule_name` so the embed_text isn't dominated by SIEM boilerplate. Returns
    isoc's subclass (richer embed_text — see _alert_class).
    """
    accepted = _accepted_keys()
    cleaned = {k: v for k, v in (d or {}).items() if k in accepted and v is not None}

    # Clean the rule_name before construction — affects what gets embedded.
    if "rule_name" in cleaned:
        cleaned["rule_name"] = _clean_rule_name(
            cleaned["rule_name"],
            cleaned.get("customer"),
        )

    return _alert_class()(**cleaned)


def passthrough_fields(d: dict[str, Any]) -> dict[str, Any]:
    """Return the keys in `d` that are NOT part of the NormalizedAlert constructor.

    The pipeline still wants these (auto-close uses `application`, briefing displays
    `http_method`, etc.) — they live in incident.normalized as extra keys alongside
    the canonical NormalizedAlert.to_dict() output.
    """
    accepted = _accepted_keys()
    return {k: v for k, v in (d or {}).items() if k not in accepted and v is not None}
