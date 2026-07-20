"""Manual ingest (paste / file upload)."""

from __future__ import annotations

from typing import Annotated

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db.enums import CaseStatus, IngestSource
from ..db.models import Incident, User
from ..db.session import get_session
from ..queue import get_arq
from ..rate_limit import limiter, user_key
from ..schemas import IngestResponse, PasteIngestRequest

router = APIRouter()


@router.post("/paste", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute", key_func=user_key)
async def paste(
    request: Request,
    body: PasteIngestRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
) -> IngestResponse:
    cleaned = (body.raw_text or "").strip()
    if len(cleaned) < 20:
        from fastapi import HTTPException

        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Alert text is empty or too short — paste the full alert payload.",
        )
    incident = Incident(
        title="(pending parse)",  # pipeline parse step overwrites with best-effort title
        status=CaseStatus.RECEIVED,
        ingest_source=IngestSource.PASTE,
        customer=body.customer,
        raw_payload={"text": cleaned, "source_hint": body.source_hint},
    )
    session.add(incident)
    await session.flush()
    await session.commit()
    await session.refresh(incident)

    await arq.enqueue_job("pipeline_run", str(incident.id))
    return IngestResponse(
        incident_id=incident.id,
        case_number=incident.case_number,
        status=incident.status,
    )


@router.post("/upload", response_model=list[IngestResponse], status_code=status.HTTP_201_CREATED)
async def upload(
    file: UploadFile,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    customer: str | None = None,
    source_hint: str | None = None,
) -> list[IngestResponse]:
    import json as _json

    payload = (await file.read()).decode("utf-8", errors="replace")
    items: list[dict] = []

    name = (file.filename or "").lower()
    if name.endswith(".ndjson") or "\n{" in payload:
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(_json.loads(line))
            except _json.JSONDecodeError:
                items.append({"raw": line})
    else:
        try:
            parsed = _json.loads(payload)
            items = parsed if isinstance(parsed, list) else [parsed]
        except _json.JSONDecodeError:
            items = [{"raw": payload}]

    if not items:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no records")

    created: list[Incident] = []
    for item in items:
        raw_text = item.get("raw") or item.get("text") or _json.dumps(item)
        inc = Incident(
            title="(unparsed)",
            status=CaseStatus.RECEIVED,
            ingest_source=IngestSource.FILE,
            customer=customer,
            raw_payload={"text": raw_text, "source_hint": source_hint, "original": item},
        )
        session.add(inc)
        created.append(inc)

    # flush assigns each client-side UUID PK and the server-side case_number;
    # commit persists the batch.
    await session.flush()
    await session.commit()

    # Enqueue EXACTLY the rows we just created. The old code re-queried the N
    # most-recent FILE incidents globally (no user/batch filter, DESC order),
    # which under concurrent uploads enqueued other users' incidents and missed
    # its own. Holding the objects avoids that race entirely.
    out: list[IngestResponse] = []
    for inc in created:
        await session.refresh(inc)  # load server-generated case_number
        await arq.enqueue_job("pipeline_run", str(inc.id))
        out.append(
            IngestResponse(
                incident_id=inc.id,
                case_number=inc.case_number,
                status=inc.status,
            )
        )
    return out
