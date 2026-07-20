"""Batch / historical import (admin) — Sources → Import tab.

Streams a file of alerts (uploaded, or a path under the shared /workspace volume)
into RECEIVED incidents on the same deterministic pipeline the pull sources ride.
Uploads land in /workspace/imports/<job_id>/ so the ARQ `batch_import` worker can
stream them; a `dry_run` returns a normalized preview of the first records without
creating anything. Read endpoints back the progress list. No verdict is committed —
imported alerts park at the human gate like any other.
"""

from __future__ import annotations

import json as _json
import uuid
from pathlib import Path
from typing import Annotated, Any

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters import parser_adapter
from ..auth.deps import require_admin
from ..db.models import ImportJob, User
from ..db.session import get_session
from ..pipeline import batch_import as bi
from ..queue import get_arq
from ..settings import settings

router = APIRouter()

_PREVIEW_N = 20  # normalized samples returned by a dry run
_COUNT_CAP = 100_000  # bound the dry-run total scan on a huge file
_MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB per uploaded file


# ── helpers ─────────────────────────────────────────────────────────────
def _parse_field_map(field_map_json: str | None) -> dict | None:
    if not field_map_json or not field_map_json.strip():
        return None
    try:
        val = _json.loads(field_map_json)
    except _json.JSONDecodeError as e:
        raise HTTPException(400, f"field_map must be valid JSON: {e}") from e
    if not isinstance(val, dict):
        raise HTTPException(400, "field_map must be a JSON object")
    return val


def _validate_fmt(fmt: str) -> None:
    if fmt not in bi.FORMATS:
        raise HTTPException(400, f"fmt must be one of {bi.FORMATS}")


def _import_dir() -> Path:
    d = Path(settings.workspace_path) / "imports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _job_dict(j: ImportJob) -> dict[str, Any]:
    return {
        "id": str(j.id),
        "filename": j.filename,
        "customer": j.customer,
        "source_hint": j.source_hint,
        "fmt": j.fmt,
        "dedupe": j.dedupe,
        "status": j.status,
        "total": j.total,
        "processed": j.processed,
        "created": j.created_count,
        "skipped": j.skipped_count,
        "failed": j.failed_count,
        "error": j.error,
        "created_at": j.created_at.isoformat() if j.created_at else None,
        "updated_at": j.updated_at.isoformat() if j.updated_at else None,
    }


def _preview(path: Path, fmt: str, customer: str | None, field_map: dict | None) -> dict[str, Any]:
    """Read-only: normalize the first records + count the file, creating nothing."""
    previews: list[dict[str, Any]] = []
    total = 0
    for record in bi.iter_records(path, fmt):
        if total < _PREVIEW_N:
            previews.append(
                {
                    "detected_source": parser_adapter.detect_source(record),
                    "normalized": parser_adapter.parse_to_normalized(
                        record, customer=customer, field_map=field_map
                    ),
                }
            )
        total += 1
        if total >= _COUNT_CAP:
            break
    return {"preview": previews, "count": total, "capped": total >= _COUNT_CAP}


async def _start_job(
    session: AsyncSession,
    arq: ArqRedis,
    admin: User,
    *,
    filename: str,
    path: str,
    customer: str | None,
    source_hint: str | None,
    fmt: str,
    field_map: dict | None,
    dedupe: bool,
) -> dict[str, Any]:
    job = ImportJob(
        created_by_id=admin.id,
        customer=(customer or None),
        filename=filename,
        path=path,
        fmt=fmt,
        source_hint=(source_hint or None),
        field_map=field_map,
        dedupe=dedupe,
        status="queued",
    )
    session.add(job)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="ingest.batch_import",
        target_type="import_job",
        target_id=job.id,
        diff={"filename": filename, "fmt": fmt, "customer": customer},
    )
    await session.commit()
    await arq.enqueue_job("batch_import", str(job.id))
    await session.refresh(job)
    return {"job": _job_dict(job)}


# ── upload mode (multipart) ─────────────────────────────────────────────
@router.post("/batch/upload")
async def batch_upload(
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    file: Annotated[UploadFile, File()],
    customer: Annotated[str | None, Form()] = None,
    source_hint: Annotated[str | None, Form()] = None,
    fmt: Annotated[str, Form()] = "auto",
    field_map: Annotated[str | None, Form()] = None,
    dedupe: Annotated[bool, Form()] = True,
    dry_run: Annotated[bool, Form()] = False,
) -> dict[str, Any]:
    _validate_fmt(fmt)
    fm = _parse_field_map(field_map)
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file too large (> {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
    if not data:
        raise HTTPException(400, "empty file")

    if dry_run:
        tmp = _import_dir() / "_preview" / f"{uuid.uuid4()}"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        try:
            return _preview(tmp, fmt, customer, fm)
        finally:
            tmp.unlink(missing_ok=True)

    # Create the row first to get its id, then persist the file under it so the
    # /workspace path and the job row line up (path filled in before commit).
    job = ImportJob(
        created_by_id=admin.id,
        customer=(customer or None),
        filename=(file.filename or "import.dat"),
        path="",
        fmt=fmt,
        source_hint=(source_hint or None),
        field_map=fm,
        dedupe=dedupe,
        status="queued",
    )
    session.add(job)
    await session.flush()
    dest_dir = _import_dir() / str(job.id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / Path(file.filename or "import.dat").name
    dest.write_bytes(data)
    job.path = str(dest)
    await audit.log(
        session,
        user_id=admin.id,
        action="ingest.batch_import",
        target_type="import_job",
        target_id=job.id,
        diff={"filename": job.filename, "fmt": fmt, "customer": customer},
    )
    await session.commit()
    await arq.enqueue_job("batch_import", str(job.id))
    await session.refresh(job)
    return {"job": _job_dict(job)}


# ── server-path mode (json) ─────────────────────────────────────────────
class BatchPathRequest(BaseModel):
    server_path: str
    customer: str | None = None
    source_hint: str | None = None
    fmt: str = "auto"
    field_map: dict[str, str] | None = None
    dedupe: bool = True
    dry_run: bool = False


@router.post("/batch/path")
async def batch_path(
    body: BatchPathRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
) -> dict[str, Any]:
    _validate_fmt(body.fmt)
    try:
        path = bi.resolve_import_path(body.server_path, Path(settings.workspace_path))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if not path.exists() or not path.is_file():
        raise HTTPException(404, f"no file at {path} (place it under the workspace volume first)")

    if body.dry_run:
        return _preview(path, body.fmt, body.customer, body.field_map)

    return await _start_job(
        session,
        arq,
        admin,
        filename=path.name,
        path=str(path),
        customer=body.customer,
        source_hint=body.source_hint,
        fmt=body.fmt,
        field_map=body.field_map,
        dedupe=body.dedupe,
    )


# ── progress / history ──────────────────────────────────────────────────
@router.get("/batch/jobs")
async def list_jobs(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
    limit: int = 25,
) -> dict[str, Any]:
    rows = (
        (
            await session.execute(
                select(ImportJob)
                .order_by(desc(ImportJob.created_at))
                .limit(min(max(limit, 1), 100))
            )
        )
        .scalars()
        .all()
    )
    return {"jobs": [_job_dict(r) for r in rows]}


@router.get("/batch/jobs/{job_id}")
async def get_job(
    job_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    job = await session.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(404, "import job not found")
    return {"job": _job_dict(job)}
