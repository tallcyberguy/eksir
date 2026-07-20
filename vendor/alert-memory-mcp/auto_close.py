"""
Auto-Close Rule Matcher — YAML-based pre-triage filter.

Loads auto_close_rules.yaml and evaluates rules against alert fields
and optional enrichment data. First matching rule wins.

Usage:
    from auto_close import AutoCloseChecker

    checker = AutoCloseChecker()

    # Pre-enrichment (alert fields only):
    result = checker.check(
        alert_fields={
            "customer": "CONTOSO",
            "rule_name": "CONTOSO: Threat: X-Force as Malware...",
            "dst_ip": "203.0.113.89",
        }
    )

    # Post-enrichment (alert + enrichment data):
    result = checker.check(
        alert_fields={...},
        enrichment={
            "dst_asn": "AS45102 Alibaba (US) Technology Co., Ltd.",
            "dst_hostname": "tracking.intl.miui.com",
            "vt_clean": True,
            "abuseipdb_score": 0,
        }
    )

    if result:
        print(result["verdict"], result["reason"], result["confidence"])
"""

from __future__ import annotations

import os
import yaml
from typing import Optional

_DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "auto_close_rules.yaml")


class AutoCloseChecker:

    def __init__(self, rules_path: str = _DEFAULT_RULES_PATH):
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
        self._rules: list[dict] = data.get("rules", [])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        alert_fields: dict,
        enrichment: Optional[dict] = None,
    ) -> Optional[dict]:
        """
        Evaluate all rules against alert_fields (and optional enrichment).

        Returns the first matching rule as:
            {
                "rule_id":    str,
                "rule_name":  str,
                "verdict":    "FP" | "benign",
                "confidence": "HIGH" | "MEDIUM" | "LOW",
                "reason":     str,
            }

        Returns None if no rule matches.
        """
        enrichment = enrichment or {}

        for rule in self._rules:
            # Customer gate — null in YAML means global (applies to all)
            rule_customer = rule.get("customer")
            if rule_customer is not None:
                if alert_fields.get("customer", "").upper() != rule_customer.upper():
                    continue

            if self._matches(rule.get("conditions", {}), alert_fields, enrichment):
                return {
                    "rule_id":    rule["id"],
                    "rule_name":  rule.get("name", rule["id"]),
                    "verdict":    rule["verdict"],
                    "confidence": rule.get("confidence", "MEDIUM"),
                    "reason":     rule.get("reason", "").strip(),
                }

        return None

    def list_rules(self) -> list[dict]:
        """Return all loaded rules (for debugging / display)."""
        return self._rules

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def _matches(
        self,
        conditions: dict,
        alert_fields: dict,
        enrichment: dict,
    ) -> bool:
        """
        ALL conditions in the rule must match for the rule to fire.
        Enrichment-only conditions are skipped if enrichment is empty.

        Safety gate: if a rule has ONLY enrichment conditions and no enrichment
        is provided, the rule must NOT fire — all conditions would be vacuously
        skipped, causing false positives on any alert.
        """
        _ENRICHMENT_KEYS = {
            "dst_asn_contains", "dst_hostname_contains", "vt_clean", "abuseipdb_clean"
        }

        # Safety gate: if the rule has ANY enrichment conditions and no enrichment
        # was provided, the rule cannot fire — wait for the post-enrichment pass.
        has_enrichment_condition = any(k in _ENRICHMENT_KEYS for k in conditions)
        if has_enrichment_condition and not enrichment:
            return False

        for key, expected in conditions.items():
            # ── Alert field conditions ─────────────────────────────────

            if key == "rule_name_contains":
                actual = alert_fields.get("rule_name", "")
                if expected.lower() not in actual.lower():
                    return False

            elif key == "dst_ip":
                if alert_fields.get("dst_ip", "") != expected:
                    return False

            elif key == "src_ip":
                if alert_fields.get("src_ip", "") != expected:
                    return False

            elif key == "application":
                actual = alert_fields.get("application", "")
                if actual.lower() != expected.lower():
                    return False

            elif key == "url_category":
                actual = alert_fields.get("url_category", "")
                if actual.lower() != expected.lower():
                    return False

            elif key == "src_zone":
                actual = alert_fields.get("src_zone", "")
                if actual.lower() != expected.lower():
                    return False

            elif key == "dst_port":
                try:
                    if int(alert_fields.get("dst_port", -1)) != int(expected):
                        return False
                except (TypeError, ValueError):
                    return False

            # ── Enrichment conditions (skip if not provided) ──────────

            elif key == "dst_asn_contains":
                if not enrichment:
                    continue  # skip, not a blocker
                actual = enrichment.get("dst_asn", "")
                if expected.lower() not in actual.lower():
                    return False

            elif key == "dst_hostname_contains":
                if not enrichment:
                    continue
                # Check all hostnames in the list
                hostnames = enrichment.get("dst_hostnames", [])
                if isinstance(hostnames, str):
                    hostnames = [hostnames]
                single = enrichment.get("dst_hostname", "")
                if single:
                    hostnames = list(hostnames) + [single]
                if not any(expected.lower() in h.lower() for h in hostnames):
                    return False

            elif key == "vt_clean":
                if not enrichment:
                    continue
                actual = enrichment.get("vt_clean", None)
                if actual is None:
                    continue
                if bool(actual) != bool(expected):
                    return False

            elif key == "abuseipdb_clean":
                if not enrichment:
                    continue
                score = enrichment.get("abuseipdb_score", None)
                if score is None:
                    continue
                is_clean = (int(score) == 0)
                if is_clean != bool(expected):
                    return False

            # Unknown condition key — ignore gracefully
            # (forward-compatibility with future YAML additions)

        return True


# ------------------------------------------------------------------
# CLI helper — test a rule file quickly
# ------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys

    checker = AutoCloseChecker()
    print(f"Loaded {len(checker.list_rules())} rules\n")

    # Quick self-test with known FP pattern
    test_alert = {
        "customer": "CONTOSO",
        "rule_name": "CONTOSO: Threat: Possible Communication With Networks Categorized by X-Force as Malware L2R",
        "dst_ip": "203.0.113.89",
        "dst_port": 443,
    }
    result = checker.check(test_alert)
    if result:
        print(f"[MATCH] rule_id={result['rule_id']}")
        print(f"        verdict={result['verdict']} confidence={result['confidence']}")
        print(f"        reason={result['reason'][:80]}...")
    else:
        print("[NO MATCH] — no auto-close rule fired")

    # Test with enrichment
    test_enrichment = {
        "dst_asn": "AS45102 Alibaba (US) Technology Co., Ltd.",
        "dst_hostnames": ["bigdata-onetrack01-pri-alisgp.alb.xiaomi.com", "tracking.intl.miui.com"],
        "vt_clean": True,
        "abuseipdb_score": 0,
    }
    test_alert2 = {
        "customer": "CONTOSO",
        "rule_name": "CONTOSO: Threat: Possible Communication With Networks Categorized by X-Force as Malware L2R",
        "dst_ip": "203.0.113.200",  # different IP, same ASN
        "dst_port": 443,
    }
    result2 = checker.check(test_alert2, enrichment=test_enrichment)
    if result2:
        print(f"\n[MATCH with enrichment] rule_id={result2['rule_id']}")
        print(f"        verdict={result2['verdict']} confidence={result2['confidence']}")
    else:
        print("\n[NO MATCH with enrichment]")
