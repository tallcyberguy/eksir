"""Adapter for `alert-memory-mcp/auto_close.py`.

**Why this file is more than a one-line shim:** the admin UI lets analysts
create auto-close rules in Postgres (`auto_close_rules` table). The base
matcher (`AutoCloseChecker`) only loads YAML from disk — it has no notion of
the DB store. The admin UI page even claimed "rules are merged at evaluation
time" — which was a lie until this adapter was rewritten to actually do the
merge.

Flow on every check():
  1. Load YAML rules via `AutoCloseChecker` (existing behavior).
  2. Query `auto_close_rules` table for `enabled=true` rows.
  3. Translate each DB row's JSONB `match` into the matcher's schema:
       {"rule_name": "X"}  →  {"rule_name_contains": "X"}   (substring)
       {"dst_ip":    "X"}  →  {"dst_ip":             "X"}   (exact, same)
       …                   →  …
  4. Append DB rules into the checker's `_rules` list (after YAML, so YAML
     rules retain their priority unless analysts want to override).
  5. Call `checker.check(...)` — same matching logic for both sources.

DB rules with `customer = NULL` apply to any tenant (matching how the YAML
treats a missing `customer` key); DB rules with a specific customer string
gate on alert.customer just like YAML rules.

The pipeline calls `check()` synchronously via `asyncio.to_thread` today.
The DB lookup needs an async session, so this module now exposes BOTH a
sync `check_sync()` (legacy, YAML-only — kept for back-compat) and a new
async `check()` that includes the DB merge. Callers should switch to
`await check(...)`.
"""

from __future__ import annotations

import importlib
from typing import Any

from sqlalchemy import select

from ..db.models import AutoCloseRule
from ..db.session import AsyncSessionLocal
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.adapter.autoclose")


# Map DB-side condition keys → matcher-side condition keys.
# YAML uses `_contains` suffix for substring fields; DB JSONB tends to use the
# bare field name. We pick the more permissive (substring) variant for any
# field that has a `_contains` form because the admin UI doesn't yet expose
# the distinction and substring is the friendlier default for hand-typed
# rules — "Wazuh agent started" should match "Wazuh agent started." (period).
_DB_KEY_REMAP = {
    "rule_name": "rule_name_contains",
    "dst_asn": "dst_asn_contains",
    "dst_hostname": "dst_hostname_contains",
    # Fields with no substring equivalent in the matcher — passed through:
    # dst_ip, src_ip, application, url_category, src_zone, dst_port,
    # vt_clean, abuseipdb_clean
}


def _db_rule_to_matcher_rule(row: AutoCloseRule) -> dict[str, Any]:
    """Translate a DB row into the dict shape AutoCloseChecker expects."""
    raw_conditions = row.match or {}
    conditions = {_DB_KEY_REMAP.get(k, k): v for k, v in raw_conditions.items()}
    return {
        "id": row.rule_id,
        "name": row.rule_id,  # admin UI doesn't expose a separate name yet
        "customer": row.customer,  # None == applies to all customers
        "conditions": conditions,
        "verdict": row.verdict,
        "confidence": "MEDIUM",
        "reason": row.reason,
        "_source": "db",  # diagnostic — surfaces in audit if matched
    }


async def _load_db_rules() -> list[dict[str, Any]]:
    """Pull enabled rules from Postgres and translate them."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(AutoCloseRule).where(AutoCloseRule.enabled.is_(True))
            rows = (await session.scalars(stmt)).all()
            return [_db_rule_to_matcher_rule(r) for r in rows]
    except Exception as e:
        logger.error("autoclose.db_load_failed", error=str(e))
        return []


def _checker():
    mod = importlib.import_module("auto_close")
    return mod.AutoCloseChecker(rules_path=str(settings.auto_close_yaml_path))


def _coerce_alert_fields(alert_fields: dict[str, Any]) -> dict[str, Any]:
    """The upstream matcher does `alert_fields.get('customer', '').upper()`,
    which blows up with `NoneType has no attribute 'upper'` when the key IS
    present but its value is None (the default arg only fires on missing key).
    Wazuh agent-started alerts have no customer field — produce empty string
    so the upstream comparison just returns False instead of throwing.
    """
    coerced = dict(alert_fields)
    for k in (
        "customer",
        "rule_name",
        "src_ip",
        "dst_ip",
        "application",
        "url_category",
        "src_zone",
    ):
        if coerced.get(k) is None:
            coerced[k] = ""
    return coerced


def _coerce_enrichment(enrichment: dict[str, Any]) -> dict[str, Any]:
    """The enrichment-side twin of `_coerce_alert_fields`, same trap.

    The matcher reads `enrichment.get("dst_asn", "").lower()` and iterates
    `h.lower() for h in enrichment["dst_hostnames"]`. Both keys are ALWAYS set
    by the orchestrator's post-enrichment pass, so the `.get` defaults never
    fire, and both can legitimately hold None:

      * `dst_asn` is None whenever there was no public IP to enrich, or the
        ipinfo branch failed (the enrich step maps a failed branch to []).
      * `dst_hostnames` is built with a bare `h.get("name")`, so any triage
        hostname record missing that key contributes a None ELEMENT.

    Either one raises `AttributeError: 'NoneType' object has no attribute
    'lower'` inside the matcher, which `check()` swallows into a None return
    that is indistinguishable from "no rule matched", i.e. auto-close
    silently stops working. Coerce here so the comparison just returns False.
    """
    coerced = dict(enrichment)
    # `k in coerced`, not `.get(k) is None`: only neutralise a key that is
    # PRESENT but None. Inventing an absent key would hand the matcher an
    # empty string it was never given.
    for k in ("dst_asn", "dst_hostname"):
        if k in coerced and coerced[k] is None:
            coerced[k] = ""
    hostnames = coerced.get("dst_hostnames")
    if isinstance(hostnames, list):
        coerced["dst_hostnames"] = [h for h in hostnames if h]
    return coerced


async def check(
    alert_fields: dict[str, Any], enrichment: dict[str, Any] | None = None
) -> dict | None:
    """Run the auto-close matcher against the union of YAML + DB rules.

    Returns the matched rule dict (with rule_id, verdict, confidence, reason)
    or None if no rule fires.
    """
    try:
        checker = _checker()
        db_rules = await _load_db_rules()
        yaml_count = len(checker._rules)
        # Append DB rules — YAML rules evaluate first (preserves existing
        # priority order), then DB rules add coverage for whatever YAML misses.
        if db_rules:
            checker._rules = list(checker._rules) + db_rules
        logger.info("autoclose.rules_loaded", yaml=yaml_count, db=len(db_rules))

        fields = _coerce_alert_fields(alert_fields)
        if enrichment is not None:
            return checker.check(fields, enrichment=_coerce_enrichment(enrichment))
        return checker.check(fields)
    except Exception as e:
        logger.error("autoclose.failed", error=str(e))
        return None


def check_sync(
    alert_fields: dict[str, Any], enrichment: dict[str, Any] | None = None
) -> dict | None:
    """**Deprecated** — YAML-only matcher kept for backward compat.

    Pipeline callers should use the async `check()` so DB rules are evaluated.
    This sync wrapper only loads YAML and is left in place so any external
    importer continues working until they migrate.
    """
    try:
        checker = _checker()
        if enrichment is not None:
            return checker.check(
                _coerce_alert_fields(alert_fields), enrichment=_coerce_enrichment(enrichment)
            )
        return checker.check(_coerce_alert_fields(alert_fields))
    except Exception as e:
        logger.error("autoclose.failed", error=str(e))
        return None
