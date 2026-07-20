"""Unit tests for the Investigation Queue pure ranking builder (`sla.build_queue`)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from isoc_api.pipeline import sla

NOW = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)
ME = str(uuid.uuid4())
OTHER = str(uuid.uuid4())


def _row(**kw):
    base = {
        "id": uuid.uuid4(),
        "case_number": "CASE-000001",
        "title": "t",
        "severity": "high",
        "status": "awaiting_review",
        "tenant_id": None,
        "customer": None,
        "assignee_id": None,
        "snoozed_until": None,
        "created_at": NOW - timedelta(minutes=10),
        "proposed_actions": [],
        "asset": None,
    }
    base.update(kw)
    return base


def _q(rows):
    return sla.build_queue(rows, me_id=ME, now=NOW)


def test_mine_first_then_unassigned():
    out = _q([_row(assignee_id=None, severity="critical"), _row(assignee_id=ME, severity="low")])
    assert [it["bucket"] for it in out["items"]] == ["mine", "unassigned"]


def test_other_analysts_rows_dropped():
    out = _q([_row(assignee_id=OTHER), _row(assignee_id=ME)])
    assert out["total"] == 1
    assert out["items"][0]["bucket"] == "mine"
    assert out["counts"] == {"mine": 1, "unassigned": 0, "all": 1}


def test_snoozed_dropped_until_passed():
    future = _row(assignee_id=ME, snoozed_until=NOW + timedelta(hours=1))
    past = _row(assignee_id=ME, snoozed_until=NOW - timedelta(minutes=1))
    out = _q([future, past])
    assert out["total"] == 1  # only the expired-snooze row re-enters


def test_sla_due_ascending_within_bucket():
    # Both unassigned/critical; older created_at → earlier due → ranks first.
    older = _row(assignee_id=None, severity="critical", created_at=NOW - timedelta(minutes=50))
    newer = _row(assignee_id=None, severity="critical", created_at=NOW - timedelta(minutes=5))
    out = _q([newer, older])
    assert out["items"][0]["created_at"] == older["created_at"].isoformat()


def test_severity_tiebreak():
    # Same bucket + same created_at → severity rank decides (critical before high).
    crit = _row(assignee_id=None, severity="critical")
    high = _row(assignee_id=None, severity="high")
    out = _q([high, crit])
    assert [it["severity"] for it in out["items"]] == ["critical", "high"]


def test_sla_state_thresholds():
    # critical target = 60 min. Within first 45 min → green; last 25% (<15 min) → amber; past → breached.
    green = _row(assignee_id=ME, severity="critical", created_at=NOW - timedelta(minutes=10))
    amber = _row(assignee_id=ME, severity="critical", created_at=NOW - timedelta(minutes=50))
    breached = _row(assignee_id=ME, severity="critical", created_at=NOW - timedelta(minutes=90))
    states = {it["id"]: it["sla_state"] for it in _q([green, amber, breached])["items"]}
    assert states[str(green["id"])] == "green"
    assert states[str(amber["id"])] == "amber"
    assert states[str(breached["id"])] == "breached"


def test_counts_and_next_up():
    rows = [
        _row(assignee_id=ME, severity="high", created_at=NOW - timedelta(minutes=50)),
        _row(assignee_id=None, severity="critical"),
        _row(assignee_id=OTHER),  # dropped
    ]
    out = _q(rows)
    assert out["counts"] == {"mine": 1, "unassigned": 1, "all": 2}
    # mine ranks ahead of unassigned regardless of SLA — next_up is the mine row.
    assert out["next_up_id"] == out["items"][0]["id"]
    assert out["items"][0]["bucket"] == "mine"


def test_proposed_actions_projected_and_empty_safe():
    out = _q([_row(assignee_id=ME, proposed_actions=["isolate_host", "tag"])])
    assert out["items"][0]["proposed_actions"] == ["isolate_host", "tag"]
    out2 = _q([_row(assignee_id=ME)])
    assert out2["items"][0]["proposed_actions"] == []


def test_empty_queue():
    out = _q([])
    assert out == {
        "items": [],
        "total": 0,
        "counts": {"mine": 0, "unassigned": 0, "all": 0},
        "next_up_id": None,
        "generated_at": NOW.isoformat(),
    }


def test_ids_and_tenant_stringified():
    tid = uuid.uuid4()
    out = _q([_row(assignee_id=ME, tenant_id=tid)])
    it = out["items"][0]
    assert isinstance(it["id"], str)
    assert it["tenant_id"] == str(tid)
    assert it["assignee_id"] == ME
