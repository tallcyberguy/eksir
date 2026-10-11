"""Regression tests for the auto-close None-coercion trap.

The upstream matcher reads `enrichment.get("dst_asn", "").lower()` and
iterates `h.lower() for h in enrichment["dst_hostnames"]`. Both keys are
always set by the orchestrator's post-enrichment pass, so the `.get`
defaults never fire, and both could hold None. The resulting AttributeError
was swallowed by `check()` into a None return that is indistinguishable from
"no rule matched", so auto-close silently stopped working.

Two fixes are covered here:
  * `_coerce_enrichment` guards the boundary for every caller.
  * `_post_enrichment_hostnames` stops producing None elements at the source.
"""

from __future__ import annotations

from isoc_api.adapters.autoclose_adapter import _coerce_enrichment
from isoc_api.pipeline.orchestrator import _post_enrichment_hostnames

# ── the boundary guard ──────────────────────────────────────────────────


def test_none_asn_becomes_empty_string():
    assert _coerce_enrichment({"dst_asn": None})["dst_asn"] == ""


def test_none_single_hostname_becomes_empty_string():
    assert _coerce_enrichment({"dst_hostname": None})["dst_hostname"] == ""


def test_none_elements_dropped_from_hostname_list():
    out = _coerce_enrichment({"dst_hostnames": ["ok.example", None, "two.example"]})
    assert out["dst_hostnames"] == ["ok.example", "two.example"]


def test_all_none_hostname_list_becomes_empty():
    assert _coerce_enrichment({"dst_hostnames": [None]})["dst_hostnames"] == []


def test_real_values_are_untouched():
    enr = {"dst_asn": "CLOUDFLARENET", "dst_hostnames": ["a.example"], "vt_clean": True}
    assert _coerce_enrichment(enr) == enr


def test_absent_keys_are_not_invented():
    """Only coerce what is present. Inventing keys would let a rule with an
    enrichment condition match on an empty string it was never given."""
    assert _coerce_enrichment({}) == {}


def test_input_is_not_mutated():
    enr = {"dst_asn": None, "dst_hostnames": [None]}
    _coerce_enrichment(enr)
    assert enr == {"dst_asn": None, "dst_hostnames": [None]}


def test_non_list_hostnames_passed_through():
    """The matcher itself handles the str case; don't second-guess it."""
    assert _coerce_enrichment({"dst_hostnames": "a.example"})["dst_hostnames"] == "a.example"


# ── the producer ────────────────────────────────────────────────────────


def test_hostname_records_without_a_name_are_dropped():
    triage = [{"hostnames": [{"name": "a.example"}, {"ttl": 300}, {"name": None}]}]
    assert _post_enrichment_hostnames(triage) == ["a.example"]


def test_producer_handles_missing_and_empty_hostnames():
    assert _post_enrichment_hostnames([{}, {"hostnames": None}, {"hostnames": []}]) == []


def test_producer_flattens_across_triage_results_and_caps_at_ten():
    triage = [{"hostnames": [{"name": f"h{i}.example"}]} for i in range(15)]
    out = _post_enrichment_hostnames(triage)
    assert len(out) == 10
    assert out[0] == "h0.example"


# ── end to end against the real vendored matcher ────────────────────────
#
# `autoclose_adapter._checker()` points at `settings.auto_close_yaml_path`,
# which is the in-container path. Build the checker from the vendored module's
# own default instead, so these run on the host and in the image alike.


def _probe_checker(conditions: dict):
    import importlib

    mod = importlib.import_module("auto_close")
    checker = mod.AutoCloseChecker()
    checker._rules = [
        {
            "id": "probe",
            "name": "probe",
            "verdict": "FP",
            "confidence": "high",
            "reason": "probe",
            "conditions": conditions,
        }
    ]
    return checker


def _fields():
    from isoc_api.adapters.autoclose_adapter import _coerce_alert_fields

    return _coerce_alert_fields({"rule_name": "x"})


def test_real_matcher_survives_none_bearing_hostnames():
    """The actual production crash. Without the coercion this raises
    AttributeError: 'NoneType' object has no attribute 'lower'."""
    checker = _probe_checker({"dst_hostname_contains": "example"})
    checker.check(_fields(), enrichment=_coerce_enrichment({"dst_hostnames": [None]}))


def test_real_matcher_survives_none_asn():
    """Latent twin: masked in production only because the real rules carry
    rule_name_contains first, which short-circuits before reaching this."""
    checker = _probe_checker({"dst_asn_contains": "cloudflare"})
    checker.check(_fields(), enrichment=_coerce_enrichment({"dst_asn": None}))


def test_raw_none_still_raises_without_the_coercion():
    """Pin the bug itself, so this test fails if the coercion is removed."""
    import pytest

    checker = _probe_checker({"dst_hostname_contains": "example"})
    with pytest.raises(AttributeError):
        checker.check(_fields(), enrichment={"dst_hostnames": [None]})


def test_a_genuine_match_still_fires_after_coercion():
    """Guard against 'fixed the crash by never matching anything'."""
    checker = _probe_checker({"dst_hostname_contains": "good"})
    enr = _coerce_enrichment({"dst_hostnames": [None, "good.example"]})
    assert checker.check(_fields(), enrichment=enr) is not None
