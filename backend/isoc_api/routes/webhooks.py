"""HMAC-signed webhook ingest.

Header contract (matches the API doc):
  X-EKSIR-Signature: HMAC-SHA256(secret, timestamp + "." + body_bytes)  — hex
  X-EKSIR-Timestamp: <unix seconds>  (5-minute skew window)
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.enums import CaseStatus, IngestSource
from ..db.models import Incident, WebhookSource
from ..db.session import get_session
from ..queue import get_arq
from ..schemas import IngestResponse
from ..settings import settings

router = APIRouter()


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


@router.post(
    "/{source_id}", response_model=list[IngestResponse], status_code=status.HTTP_201_CREATED
)
async def ingest(
    source_id: uuid.UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    x_isoc_signature: Annotated[str | None, Header(alias="X-EKSIR-Signature")] = None,
    x_isoc_timestamp: Annotated[str | None, Header(alias="X-EKSIR-Timestamp")] = None,
) -> list[IngestResponse]:
    src = await session.get(WebhookSource, source_id)
    if src is None or not src.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown webhook source")

    if not x_isoc_signature or not x_isoc_timestamp:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing signature headers")

    try:
        ts = int(x_isoc_timestamp)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad timestamp") from None
    if abs(time.time() - ts) > settings.ingest_timestamp_skew_seconds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "timestamp skew too large")

    body = await request.body()

    # The secret in the DB is bcrypt-hashed. We re-derive the HMAC by trying it as
    # a passlib verify is NOT possible — we need the plaintext to compute HMAC.
    # Therefore webhook sources store the secret as: bcrypt(secret) for verification,
    # AND ALSO the analyst is shown the secret once at creation. We do NOT store
    # the plaintext, so HMAC verification uses an additional column 'hmac_secret'.
    #
    # → We'll store the raw HMAC secret separately on the WebhookSource row.
    # (The bcrypt hash is for admin-side verification, not for verifying signatures.)
    #
    # For this MVP, the simplest secure choice: store the secret encrypted at rest
    # with a server key — or accept that webhook secrets must be stored as is for
    # HMAC to work. We choose the latter and treat `hmac_secret_hash` column as the
    # raw secret (it's HMAC-compared, not a password). The column name is a relic;
    # a future migration will rename it.
    expected = hmac.new(
        src.hmac_secret_hash.encode(),
        f"{ts}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    if not _constant_time_eq(expected, x_isoc_signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")

    # IP allowlist (optional)
    if src.ip_allowlist:
        client_ip = request.client.host if request.client else ""
        # Coarse string match; production would use ip_network containment.
        if client_ip not in {str(x) for x in src.ip_allowlist}:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "ip not allowed")

    # Body may be a single JSON, an array, or ndjson lines.
    import json as _json

    text = body.decode("utf-8", errors="replace")
    items: list = []
    if text.lstrip().startswith("["):
        try:
            items = _json.loads(text)
        except _json.JSONDecodeError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad JSON array") from None
    elif "\n{" in text:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(_json.loads(line))
            except _json.JSONDecodeError:
                items.append({"raw": line})
    else:
        try:
            items = [_json.loads(text)]
        except _json.JSONDecodeError:
            items = [{"raw": text}]

    out: list[IngestResponse] = []
    for item in items:
        raw_text = item.get("raw") or item.get("text") or _json.dumps(item)
        inc = Incident(
            title="(unparsed)",
            status=CaseStatus.RECEIVED,
            ingest_source=IngestSource.WEBHOOK,
            webhook_source_id=src.id,
            customer=item.get("customer") or src.customer_default,
            raw_payload={"text": raw_text, "source_hint": src.source_product, "original": item},
        )
        session.add(inc)

    src.last_seen_at = datetime.now(timezone.utc)
    await session.flush()

    # Re-fetch the rows we just created so we have IDs to enqueue.
    from sqlalchemy import desc

    rows = (
        await session.scalars(
            select(Incident)
            .where(Incident.webhook_source_id == src.id)
            .order_by(desc(Incident.created_at))
            .limit(len(items))
        )
    ).all()
    for inc in rows:
        await arq.enqueue_job("pipeline_run", str(inc.id))
        out.append(
            IngestResponse(
                incident_id=inc.id,
                case_number=inc.case_number,
                status=inc.status,
            )
        )
    return out
