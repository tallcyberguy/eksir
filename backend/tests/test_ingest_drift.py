"""Unit tests for the pull-ingest schema-drift sentinel (ADR-0006 P1a).

Pure — no stack. `drift_check` fingerprints the RAW vendor payloads a source emits and flags when
their field shape changes between polls (a silent field_map rot risk).
"""

from __future__ import annotations

from isoc_api.pipeline.ingest_sources import drift_check


def _pulled(original: object, severity: str = "high") -> dict:
    """A PulledAlert-shaped dict: the vendor payload lives under 'original'."""
    return {
        "external_id": "x",
        "source_hint": "acme",
        "original": original,
        "severity": severity,
    }


def test_first_poll_is_never_flagged_but_returns_a_fingerprint():
    r = drift_check(None, [_pulled({"src_ip": "1.1.1.1", "sev": "high"})])
    assert r is not None and r.changed is False and r.fingerprint


def test_stable_shape_across_polls_is_not_drift():
    first = drift_check(None, [_pulled({"src_ip": "1.1.1.1", "sev": "high"})])
    later = drift_check(first.fingerprint, [_pulled({"src_ip": "9.9.9.9", "sev": "low"})])
    assert later is not None and later.changed is False


def test_renamed_vendor_field_flags_drift():
    first = drift_check(None, [_pulled({"src_ip": "1.1.1.1"})])
    drift = drift_check(first.fingerprint, [_pulled({"src": "1.1.1.1"})])  # src_ip -> src
    assert drift is not None and drift.changed is True


def test_fingerprint_ignores_the_pulledalert_wrapper():
    # same vendor payload shape but different wrapper severity => no drift
    first = drift_check(None, [_pulled({"a": 1, "b": 2}, severity="high")])
    later = drift_check(first.fingerprint, [_pulled({"a": 9, "b": 8}, severity="low")])
    assert later is not None and later.changed is False


def test_none_when_batch_has_no_dict_payloads():
    # a no-op / non-dict-payload poll must not raise a false alarm or clobber the fingerprint
    assert drift_check(None, [{"external_id": "x", "original": "not-a-dict"}]) is None
    assert drift_check("abc123", []) is None
