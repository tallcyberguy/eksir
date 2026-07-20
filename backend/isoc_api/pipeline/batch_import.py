"""Batch / historical import — stream a file of alerts into RECEIVED incidents.

Reuses the pull-ingestion path exactly: each record becomes an ``Incident``
(``RECEIVED``) carrying the same ``raw_payload`` shape ``_create_pull_incident``
builds, so parse → field-map → normalize → enrich → human gate all run downstream
unchanged. The reader streams (line-by-line for JSONL/CSV) so a 90-day history file
never loads whole into memory.

Pure helpers (format detection, record → payload, dedup hash, path guard) are
unit-tested and import nothing heavy; ``iter_records`` does the file I/O and
``create_received_incident`` is the shared incident creator the worker calls.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# Reader formats accepted from the API. "auto" resolves by extension then defaults
# to jsonl (the common EDR export shape). "ndjson" folds into "jsonl".
FORMATS = ("auto", "jsonl", "ndjson", "json", "csv")

_JSONL_EXT = {".jsonl", ".ndjson"}
_JSON_EXT = {".json"}
_CSV_EXT = {".csv", ".tsv"}

# Common wrapper keys a single JSON document may nest its alert list under.
_LIST_KEYS = ("alerts", "data", "items", "results", "value", "records")


def detect_format(filename: str, fmt: str = "auto") -> str:
    """Resolve an effective reader format from the requested `fmt` + `filename`.

    An explicit `fmt` wins (ndjson folded into jsonl); "auto" falls back to the
    file extension, then defaults to jsonl.
    """
    fmt = (fmt or "auto").lower()
    if fmt in ("jsonl", "ndjson"):
        return "jsonl"
    if fmt in ("json", "csv"):
        return fmt
    ext = Path(filename or "").suffix.lower()
    if ext in _JSONL_EXT:
        return "jsonl"
    if ext in _CSV_EXT:
        return "csv"
    if ext in _JSON_EXT:
        return "json"
    return "jsonl"


def record_raw_text(record: Any) -> str:
    """Text fallback handed to the parser, mirroring ``alerts.upload``."""
    if isinstance(record, str):
        return record
    if isinstance(record, dict):
        raw = record.get("raw") or record.get("text")
        if isinstance(raw, str) and raw:
            return raw
        return json.dumps(record, ensure_ascii=False, default=str)
    return str(record)


def dedup_hash(record: Any) -> str:
    """Stable content hash so re-importing the same file is idempotent."""
    if isinstance(record, str):
        blob = record
    else:
        blob = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


def dedup_key(content_hash: str) -> str:
    """Redis key claiming one record's content as already imported."""
    return f"ingest:batch:seen:{content_hash}"


def build_import_payload(
    record: Any,
    *,
    source_hint: str | None,
    field_map: dict | None,
    job_id: str,
) -> dict[str, Any]:
    """Build ``Incident.raw_payload`` for one imported record.

    Same shape ``_create_pull_incident`` uses (text + original + source_hint +
    field_map) plus a ``batch`` provenance block carrying the job id + content hash
    (the DB backstop for dedup, mirroring ``raw_payload.pull``).
    """
    return {
        "text": record_raw_text(record),
        "source_hint": source_hint,
        "original": record if isinstance(record, dict) else None,
        "field_map": field_map,
        "batch": {"job_id": job_id, "content_hash": dedup_hash(record)},
    }


def resolve_import_path(user_path: str, workspace: Path) -> Path:
    """Resolve a server-path import target, confined to the workspace volume.

    Guards against traversal / reading arbitrary host files: the resolved path
    MUST live under `workspace`. Raises ``ValueError`` otherwise.
    """
    workspace = Path(workspace).resolve()
    p = Path(user_path)
    candidate = (p if p.is_absolute() else workspace / user_path).resolve()
    if candidate != workspace and workspace not in candidate.parents:
        raise ValueError("import path must be inside the workspace volume")
    return candidate


def iter_records(path: Path, fmt: str = "auto") -> Iterator[Any]:
    """Stream records from a file.

    JSONL/CSV stream line-by-line; a JSON document is loaded (a single document
    can't be streamed without a streaming parser) and unwrapped if it is a list
    or a dict nesting one under a common key. A malformed JSONL line degrades to
    ``{"raw": line}`` rather than aborting the whole import.
    """
    path = Path(path)
    eff = detect_format(path.name, fmt)
    if eff == "jsonl":
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    yield {"raw": line}
    elif eff == "csv":
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            sample = fh.readline()
            fh.seek(0)
            delimiter = "\t" if sample.count("\t") > sample.count(",") else ","
            for row in csv.DictReader(fh, delimiter=delimiter):
                yield {k: v for k, v in row.items() if k is not None}
    else:  # json
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            yield from data
        elif isinstance(data, dict):
            for key in _LIST_KEYS:
                nested = data.get(key)
                if isinstance(nested, list):
                    yield from nested
                    return
            yield data
        # scalar / None → nothing to import


async def create_received_incident(session: Any, *, customer: str | None, raw_payload: dict) -> str:
    """Create one ``RECEIVED`` incident from an imported record (shared creator).

    Flushes to assign the id and returns it as a string; the caller commits and
    enqueues ``pipeline_run``. Kept here (not in the worker) so the pipeline test
    suite can import the batch module without pulling the worker in.
    """
    from ..db.enums import CaseStatus, IngestSource
    from ..db.models import Incident

    inc = Incident(
        title="(unparsed)",
        status=CaseStatus.RECEIVED,
        ingest_source=IngestSource.BATCH,
        customer=customer,
        raw_payload=raw_payload,
    )
    session.add(inc)
    await session.flush()
    return str(inc.id)
