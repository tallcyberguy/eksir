"""Shift Handoff (Phase 3) — pure builder tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from isoc_api.pipeline.shifts import build_handoff, render_handoff_markdown

NOW = datetime(2026, 6, 29, 18, 0, 0, tzinfo=timezone.utc)


def _open(**kw):
    base = {
        "id": "i1",
        "case_number": "CASE-1",
        "title": "Suspicious login",
        "severity": "medium",
        "status": "enriching",
        "verdict": None,
        "customer": "acme",
        "assignee_id": None,
        "assignee_name": None,
        "created_at": NOW - timedelta(hours=2),
        "snoozed_until": None,
        "proposed_actions": [],
    }
    base.update(kw)
    return base


def test_empty_board_is_clean():
    out = build_handoff([], [], now=NOW, window_hours=12)
    assert out["counts"]["open"] == 0
    assert out["items"] == []
    assert out["summary"]["escalations"] == 0


def test_gate_items_rank_first_and_flagged():
    rows = [
        _open(id="a", severity="critical", status="enriching"),
        _open(id="b", severity="low", status="awaiting_signoff", verdict="TP"),
    ]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    # gate item surfaces first even though it's lower severity
    assert out["items"][0]["id"] == "b"
    assert out["items"][0]["at_gate"] is True
    assert out["counts"]["at_gate"] == 1
    assert out["summary"]["escalations"] == 1


def test_severity_then_age_within_bucket():
    rows = [
        _open(id="m", severity="medium", created_at=NOW - timedelta(hours=1)),
        _open(id="c", severity="critical", created_at=NOW - timedelta(hours=5)),
        _open(id="c2", severity="critical", created_at=NOW - timedelta(hours=1)),
    ]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    ids = [it["id"] for it in out["items"]]
    # both criticals before medium; older critical first
    assert ids == ["c", "c2", "m"]


def test_snoozed_and_closed_excluded():
    rows = [
        _open(id="snz", snoozed_until=NOW + timedelta(hours=3)),
        _open(id="closed", status="closed"),
        _open(id="failed", status="failed"),
        _open(id="live"),
    ]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    assert [it["id"] for it in out["items"]] == ["live"]


def test_assignee_drives_bucket_and_note():
    rows = [
        _open(id="u", assignee_id=None),
        _open(id="claimed", assignee_id="x", assignee_name="alice", status="enriching"),
    ]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    by_id = {it["id"]: it for it in out["items"]}
    assert by_id["u"]["bucket"] == "new"
    assert "Unassigned" in by_id["u"]["note"]
    assert by_id["claimed"]["bucket"] == "in_progress"
    assert by_id["claimed"]["assignee"] == "alice"


def test_window_rollup_counts():
    window = [
        # ingested + auto-resolved (closed, no approver)
        {
            "created_at": NOW - timedelta(hours=1),
            "closed_at": NOW - timedelta(minutes=30),
            "signed_off_at": None,
            "approved_by_id": None,
        },
        # ingested + signed off (closed by a human)
        {
            "created_at": NOW - timedelta(hours=2),
            "closed_at": NOW - timedelta(hours=1),
            "signed_off_at": NOW - timedelta(hours=1),
            "approved_by_id": "u9",
        },
        # closed but created long before the window — counts for closed only
        {
            "created_at": NOW - timedelta(days=3),
            "closed_at": NOW - timedelta(hours=2),
            "signed_off_at": None,
            "approved_by_id": None,
        },
        # old + untouched — counts for nothing
        {
            "created_at": NOW - timedelta(days=3),
            "closed_at": None,
            "signed_off_at": None,
            "approved_by_id": None,
        },
    ]
    out = build_handoff([], window, now=NOW, window_hours=12)
    s = out["summary"]
    assert s["ingested"] == 2
    assert s["closed"] == 3
    assert s["auto_resolved"] == 2  # the two with no approver
    assert s["signed_off"] == 1


def test_markdown_render_has_gate_marker():
    rows = [_open(id="b", status="awaiting_signoff", verdict="TP", severity="high")]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    md = render_handoff_markdown(out)
    assert "# Shift Handoff" in md
    assert "GATE" in md
    assert "CASE-1" in md


def test_analyst_handoff_note_overrides_auto():
    rows = [_open(id="u", handoff_note="  Watch the C2 beacon on WS01 — creds rotated  ")]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    it = out["items"][0]
    # analyst note wins (trimmed) and is flagged separately from the auto default
    assert it["note"] == "Watch the C2 beacon on WS01 — creds rotated"
    assert it["handoff_note"] == "Watch the C2 beacon on WS01 — creds rotated"
    assert "Unassigned" in it["auto_note"]
    # the markdown report carries the analyst note, not the derived one
    md = render_handoff_markdown(out)
    assert "Watch the C2 beacon on WS01" in md


def test_blank_handoff_note_falls_back_to_auto():
    rows = [_open(id="u", handoff_note="   ")]
    out = build_handoff(rows, [], now=NOW, window_hours=12)
    it = out["items"][0]
    assert it["handoff_note"] is None
    assert "Unassigned" in it["note"]  # falls back to the auto note
