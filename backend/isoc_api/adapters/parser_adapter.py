"""Adapter for `alert-memory-mcp/parsers/` + `normalizer.py`.

The existing scripts at /opt/alert-memory-mcp are on PYTHONPATH (set in the
Dockerfile). We import them as-is — no copying, no patching.

Upstream API (verified against alert-memory-mcp HEAD):

    parsers.detect_source(raw: str) -> str
    parsers.parse(raw: str | dict, customer: str = None) -> NormalizedAlert
    normalizer.NormalizedAlert.to_dict() -> dict
    normalizer.infer_category(rule_name: str) -> str
"""

from __future__ import annotations

import importlib
import json
from typing import Any

from ..logging_config import get_logger
from .connectors import severity as _sev
from .connectors.routing import KNOWN_PARSER_SOURCES, resolve_parser_source

logger = get_logger("isoc.adapter.parser")


def _with_ocsf_severity(d: dict[str, Any]) -> dict[str, Any]:
    """Additively stamp OCSF ``severity_id`` (0-6) onto a normalized alert dict (ADR-0006 P1c).

    Derived from the existing ``severity_label``/``severity`` so it is monotonic with the word the
    analyst sees. Purely additive: ``severity`` and ``severity_label`` are left unchanged, so no
    existing consumer is affected; new consumers can read the open-standard ``severity_id``.
    """
    try:
        d["severity_id"] = _sev.severity_id_from_alert(d.get("severity_label"), d.get("severity"))
    except Exception:  # noqa: BLE001 — severity stamping must never break parsing
        d["severity_id"] = 0
    return d


def _parsers():
    return importlib.import_module("parsers")


def _normalizer():
    return importlib.import_module("normalizer")


def _as_dict_if_json(raw: Any) -> Any:
    """A pulled alert is stored as a JSON string; hand the parser the DICT so its
    JSON detectors run (parsers.detect_source/parse accept str | dict). Text
    formats (qradar/syslog email bodies) don't start with '{' and pass through."""
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("{"):
            try:
                val = json.loads(s)
                if isinstance(val, dict):
                    return val
            except (ValueError, TypeError):
                pass
    return raw


def detect_source(raw: Any) -> str:
    try:
        return _parsers().detect_source(_as_dict_if_json(raw)) or "unknown"
    except Exception as e:
        logger.warning("parser.detect_failed", error=str(e))
        return "unknown"


def _native_parse_fn(source: str):
    """isoc_api-side parser for ``source``, or None to fall through to the vendored one.

    Native OCSF-first parsers supersede the retiring vendored parsers as the project moves
    to connector-based OCSF ingestion (see CLAUDE.md). Imported lazily so the vendored
    ``normalizer`` is only loaded when a native parser actually runs.
    """
    if source == "microsoft_defender":
        from . import ocsf_defender

        return ocsf_defender.parse
    if source == "visionone":
        from . import ocsf_v1

        return ocsf_v1.parse
    return None


def parse_to_normalized(
    raw: Any,
    source_hint: str | None = None,
    customer: str | None = None,
    field_map: dict | None = None,
) -> dict[str, Any]:
    """Parse a raw alert and return a normalized dict.

    Upstream `parsers.parse` runs detect_source + selects the right parser. When
    no bespoke parser matches and the source has a `field_map`, normalize by
    configuration; otherwise return an empty alert for the analyst to hand-edit.
    """
    parsers = _parsers()
    parse_input = _as_dict_if_json(raw)
    # ADR-0006 P0: route on the connector's DECLARED source when we have a parser for it, and
    # only fall back to detect_source key-sniffing for the genuinely-unknown paste/webhook path.
    # This makes pull-source routing deterministic as the catalogue grows (no key collisions).
    source, _reason = resolve_parser_source(
        source_hint, KNOWN_PARSER_SOURCES, lambda: detect_source(parse_input)
    )
    native_parse = _native_parse_fn(source)
    parser_mod = (
        None
        if native_parse is not None
        else (getattr(parsers, source, None) if source in KNOWN_PARSER_SOURCES else None)
    )
    try:
        if native_parse is not None:
            alert = (
                native_parse(parse_input, customer=customer)
                if customer
                else native_parse(parse_input)
            )
        elif parser_mod is not None:
            alert = (
                parser_mod.parse(parse_input, customer=customer)
                if customer
                else parser_mod.parse(parse_input)
            )
        else:
            alert = (
                parsers.parse(parse_input, customer=customer)
                if customer
                else parsers.parse(parse_input)
            )
    except Exception as e:
        # No bespoke parser matched. Config-driven field map is the fallback.
        if field_map and isinstance(parse_input, dict):
            try:
                from . import field_map as _fm

                return _with_ocsf_severity(
                    _fm.apply_field_map(
                        parse_input, field_map, source_product=source_hint, customer=customer
                    )
                )
            except Exception as fe:
                logger.warning("parser.field_map_failed", error=str(fe))
        logger.warning("parser.parse_failed", error=str(e))
        alert = _normalizer().NormalizedAlert(
            source_product=source_hint or "unknown",
            raw=raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False, default=str),
            customer=customer,
        )

    alert = alert.finalize()
    return _with_ocsf_severity(alert.to_dict())


def infer_category(rule_name: str) -> str:
    try:
        return _normalizer().infer_category(rule_name) or "unknown"
    except Exception:
        return "unknown"
