"""Unit tests for the Vision One verdict write-back (ADR-0005, item 2a).

The mapping is pure; the guard paths (flag off / not a V1 alert / no workbench id) return before any
network call, so they're testable on the host without a live tenant.
"""

from __future__ import annotations

from types import SimpleNamespace

from isoc_api.adapters import v1_adapter
from isoc_api.db.enums import Verdict


def test_verdict_to_v1_status_map():
    assert v1_adapter.verdict_to_v1_status(Verdict.FP) == ("Closed", "False Positive")
    assert v1_adapter.verdict_to_v1_status(Verdict.BENIGN) == ("Closed", "Benign True Positive")
    assert v1_adapter.verdict_to_v1_status(Verdict.TP) == ("In Progress", "True Positive")
    assert v1_adapter.verdict_to_v1_status(Verdict.INCONCLUSIVE) == ("In Progress", "Noteworthy")
    # PENDING has no mapping (never mirror an uncommitted verdict)
    assert v1_adapter.verdict_to_v1_status(Verdict.PENDING) is None
    # a bare string works too
    assert v1_adapter.verdict_to_v1_status("fp") == ("Closed", "False Positive")


def _inc(**norm) -> SimpleNamespace:
    return SimpleNamespace(normalized=norm or None, customer="acme")


async def test_mirror_noop_when_flag_off_by_default():
    # default flag is OFF -> no-op, no network, never raises (even for a real V1 alert)
    inc = _inc(source_product="visionone", v1_workbench_id="WB-1-20260713-00001")
    await v1_adapter.mirror_verdict_to_v1(inc, Verdict.FP)


async def test_mirror_noop_when_not_a_v1_alert(monkeypatch):
    monkeypatch.setattr(v1_adapter.settings, "v1_status_writeback_enabled", True)
    # wrong source -> early return before any creds/HTTP
    await v1_adapter.mirror_verdict_to_v1(
        _inc(source_product="sentinelone", v1_workbench_id="x"), Verdict.FP
    )
    # V1 source but no workbench id -> early return
    await v1_adapter.mirror_verdict_to_v1(_inc(source_product="visionone"), Verdict.FP)
    # pending verdict -> unmapped -> early return
    await v1_adapter.mirror_verdict_to_v1(
        _inc(source_product="visionone", v1_workbench_id="WB-1"), Verdict.PENDING
    )
