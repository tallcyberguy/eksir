"""Batch / historical import — pure helpers + streaming reader.

No DB/Redis: exercises format detection, record→payload mapping, dedup hashing,
the workspace path guard, and the JSONL/CSV/JSON readers over tmp files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from isoc_api.pipeline import batch_import as bi


# ── format detection ────────────────────────────────────────────────────
def test_detect_format_explicit_wins_and_folds_ndjson():
    assert bi.detect_format("x.csv", "jsonl") == "jsonl"
    assert bi.detect_format("x.csv", "ndjson") == "jsonl"
    assert bi.detect_format("x.jsonl", "csv") == "csv"
    assert bi.detect_format("x.jsonl", "json") == "json"


def test_detect_format_auto_by_extension():
    assert bi.detect_format("alerts.jsonl", "auto") == "jsonl"
    assert bi.detect_format("alerts.ndjson") == "jsonl"
    assert bi.detect_format("export.csv", "auto") == "csv"
    assert bi.detect_format("dump.tsv") == "csv"
    assert bi.detect_format("blob.json") == "json"
    # unknown extension → jsonl default
    assert bi.detect_format("mystery.log") == "jsonl"
    assert bi.detect_format("") == "jsonl"


# ── raw-text fallback + dedup hashing ───────────────────────────────────
def test_record_raw_text_variants():
    assert bi.record_raw_text("plain text alert") == "plain text alert"
    assert bi.record_raw_text({"raw": "R"}) == "R"
    assert bi.record_raw_text({"text": "T"}) == "T"
    # neither raw nor text → canonical json of the dict
    out = bi.record_raw_text({"a": 1})
    assert json.loads(out) == {"a": 1}


def test_dedup_hash_stable_and_key_ordering_invariant():
    a = bi.dedup_hash({"x": 1, "y": 2})
    b = bi.dedup_hash({"y": 2, "x": 1})  # different key order, same content
    assert a == b
    assert a != bi.dedup_hash({"x": 1, "y": 3})
    assert bi.dedup_key(a) == f"ingest:batch:seen:{a}"


# ── payload builder ─────────────────────────────────────────────────────
def test_build_import_payload_carries_hint_map_and_provenance():
    rec = {"id": "A-1", "sev": "high"}
    fmap = {"severity": "sev"}
    payload = bi.build_import_payload(rec, source_hint="acme_edr", field_map=fmap, job_id="job-9")
    assert payload["source_hint"] == "acme_edr"
    assert payload["field_map"] == fmap
    assert payload["original"] == rec
    assert payload["batch"]["job_id"] == "job-9"
    assert payload["batch"]["content_hash"] == bi.dedup_hash(rec)
    # a text record carries no `original` dict
    tpayload = bi.build_import_payload("just text", source_hint=None, field_map=None, job_id="j")
    assert tpayload["original"] is None
    assert tpayload["text"] == "just text"


# ── workspace path guard ────────────────────────────────────────────────
def test_resolve_import_path_confines_to_workspace(tmp_path: Path):
    ws = tmp_path / "workspace"
    (ws / "imports").mkdir(parents=True)
    target = ws / "imports" / "history.jsonl"
    target.write_text("{}\n")

    # relative + absolute inside the volume both resolve
    assert bi.resolve_import_path("imports/history.jsonl", ws) == target.resolve()
    assert bi.resolve_import_path(str(target), ws) == target.resolve()

    # traversal / outside the volume is rejected
    with pytest.raises(ValueError):
        bi.resolve_import_path("../../../etc/passwd", ws)
    with pytest.raises(ValueError):
        bi.resolve_import_path("/etc/passwd", ws)


# ── streaming readers ───────────────────────────────────────────────────
def test_iter_records_jsonl_streams_and_tolerates_bad_lines(tmp_path: Path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"id":1}\n\n  {"id":2}\nnot json\n')
    recs = list(bi.iter_records(p, "auto"))
    assert recs[0] == {"id": 1}
    assert recs[1] == {"id": 2}
    assert recs[2] == {"raw": "not json"}  # malformed line degrades, doesn't abort


def test_iter_records_csv_and_tsv(tmp_path: Path):
    p = tmp_path / "a.csv"
    p.write_text("rule,severity\nBrute force,high\nPort scan,low\n")
    recs = list(bi.iter_records(p, "auto"))
    assert recs == [
        {"rule": "Brute force", "severity": "high"},
        {"rule": "Port scan", "severity": "low"},
    ]
    t = tmp_path / "a.tsv"
    t.write_text("rule\tseverity\nX\tmedium\n")
    assert list(bi.iter_records(t, "auto")) == [{"rule": "X", "severity": "medium"}]


def test_iter_records_json_array_and_wrapped(tmp_path: Path):
    arr = tmp_path / "arr.json"
    arr.write_text(json.dumps([{"id": 1}, {"id": 2}]))
    assert list(bi.iter_records(arr, "json")) == [{"id": 1}, {"id": 2}]

    wrapped = tmp_path / "w.json"
    wrapped.write_text(json.dumps({"alerts": [{"id": 9}], "meta": "x"}))
    assert list(bi.iter_records(wrapped, "json")) == [{"id": 9}]

    single = tmp_path / "one.json"
    single.write_text(json.dumps({"id": 42, "sev": "high"}))
    assert list(bi.iter_records(single, "json")) == [{"id": 42, "sev": "high"}]
