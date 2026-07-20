"""Threat-intel routes.

Read endpoints (list IOCs, list feeds, stats) are open to any authenticated
user. Mutations (CRUD feeds, manual sync) are admin-only.

The IOC table is *global* — no tenant scoping. Threat indicators are
universal and would just be duplicated N times if scoped.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import current_user, require_admin
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.enums import Verdict
from ..db.models import Incident, IOCRecord, ThreatFeed, ThreatIOC, User
from ..db.session import get_session
from ..queue import get_arq
from ..security import url_safety
from ..threat_intel import export as ioc_export
from ..threat_intel import scoring

router = APIRouter()


async def _guard_feed_url(url: str | None) -> None:
    """SSRF guard for an admin-supplied threat-feed URL (the worker fetches it)."""
    if not url:
        return
    try:
        await url_safety.assert_public_url(url)
    except url_safety.UrlSafetyError as e:
        raise HTTPException(400, f"feed url rejected (SSRF guard): {e}") from e


# ── Schemas ──────────────────────────────────────────────────────────────
class FeedCreate(BaseModel):
    name: str
    url: str
    kind_hint: str = "auto"
    enabled: bool = True
    # Optional parser config (JSONB). For a TAXII feed: {"format":"taxii",
    # "version":"2.1", "auth":{...}} — `url` is the collection URL.
    parser_config: dict | None = None


class FeedPatch(BaseModel):
    name: str | None = None
    url: str | None = None
    kind_hint: str | None = None
    enabled: bool | None = None
    parser_config: dict | None = None


def _redact_parser_config(pc: dict | None) -> dict | None:
    """Strip auth secrets from a parser_config before it goes into an audit
    diff (feeds are admin-only, but secrets never belong in the audit log)."""
    if isinstance(pc, dict) and pc.get("auth"):
        auth = pc["auth"] if isinstance(pc["auth"], dict) else {}
        return {**pc, "auth": {"type": auth.get("type", "?"), "value": "***redacted***"}}
    return pc


def _feed_out(f: ThreatFeed) -> dict:
    return {
        "id": str(f.id),
        "name": f.name,
        "url": f.url,
        "kind_hint": f.kind_hint,
        "enabled": f.enabled,
        # Feed type for the UI (taxii/csv/lines). NB: never expose parser_config
        # itself — it holds TAXII auth secrets.
        "format": (f.parser_config or {}).get("format", "lines"),
        "last_sync_at": f.last_sync_at.isoformat() if f.last_sync_at else None,
        "last_sync_status": f.last_sync_status,
        "last_sync_error": f.last_sync_error,
        "last_sync_count": f.last_sync_count,
        "last_sync_new_count": f.last_sync_new_count,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


# ── IOC reads ────────────────────────────────────────────────────────────
@router.get("/iocs")
async def list_iocs(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    q: str | None = Query(None, description="substring search on value"),
    ioc_type: str | None = Query(None, description="filter: ip | domain | url"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """Searchable IOC list. Returns rows + total for pagination."""
    where = []
    if q:
        where.append(ThreatIOC.value.ilike(f"%{q}%"))
    if ioc_type:
        where.append(ThreatIOC.ioc_type == ioc_type)

    total_stmt = select(func.count(ThreatIOC.id))
    rows_stmt = select(ThreatIOC).order_by(ThreatIOC.last_seen_at.desc())
    for clause in where:
        total_stmt = total_stmt.where(clause)
        rows_stmt = rows_stmt.where(clause)

    total = (await session.execute(total_stmt)).scalar() or 0
    rows = (await session.scalars(rows_stmt.limit(limit).offset(offset))).all()
    now = datetime.now(timezone.utc)
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": str(r.id),
                "value": r.value,
                "ioc_type": r.ioc_type,
                "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "sources": r.sources or [],
                # Standing reputation from corroboration (# feeds) + recency.
                "reputation": scoring.reputation(len(r.sources or []), r.last_seen_at, now=now),
            }
            for r in rows
        ],
    }


@router.get("/stats")
async def stats(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
) -> dict:
    """Topline counts + last successful sync, for the IOC tab header."""
    total = (await session.execute(select(func.count(ThreatIOC.id)))).scalar() or 0
    by_type_rows = (
        await session.execute(
            select(ThreatIOC.ioc_type, func.count(ThreatIOC.id)).group_by(ThreatIOC.ioc_type)
        )
    ).all()
    by_type = {k: int(n) for (k, n) in by_type_rows}

    last_sync = (
        await session.execute(
            select(func.max(ThreatFeed.last_sync_at)).where(ThreatFeed.last_sync_status == "ok")
        )
    ).scalar()

    return {
        "total": int(total),
        "by_type": by_type,
        "last_sync": last_sync.isoformat() if last_sync else None,
    }


# ── Export analyst-confirmed IOCs (read-only intel producer, Feature 4) ──
@router.get("/export")
async def export_confirmed_iocs(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    fmt: Annotated[str, Query(alias="format")] = "csv",
    window_days: Annotated[int | None, Query(ge=1, le=3650)] = None,
) -> Response:
    """Download analyst-confirmed indicators (incident verdict == TP, not
    excluded) as CSV or a STIX 2.1 bundle. Tenant-scoped through the incident
    join, so an analyst only exports IOCs from incidents they can see."""
    fmt = fmt.lower().strip()
    if fmt not in ("csv", "stix"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be 'csv' or 'stix'")

    stmt = (
        select(
            IOCRecord.ioc_type,
            IOCRecord.value,
            IOCRecord.first_seen_at,
            Incident.case_number,
            IOCRecord.tenant,
        )
        .join(Incident, IOCRecord.incident_id == Incident.id)
        .where(Incident.verdict == Verdict.TP)
        .where(IOCRecord.excluded.is_(False))
        .where(scope_clause_for_incidents(scope))
    )
    if window_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        stmt = stmt.where(Incident.created_at >= cutoff)

    raw = [tuple(r) for r in (await session.execute(stmt)).all()]
    rows = ioc_export.dedupe(raw)
    now = datetime.now(timezone.utc)

    if fmt == "csv":
        content, media, ext = ioc_export.to_csv(rows), "text/csv", "csv"
    else:
        content, media, ext = (
            ioc_export.to_stix_bundle(rows, now),
            "application/json",
            "json",
        )

    filename = f"eksir-confirmed-iocs-{now:%Y%m%d}.{ext}"
    await audit.log(
        session,
        user_id=user.id,
        action="threat_intel.export",
        target_type="ioc_export",
        diff={"format": fmt, "indicators": len(rows), "window_days": window_days},
    )
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Feeds (read for all; mutate for admin) ───────────────────────────────
@router.get("/feeds")
async def list_feeds(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
) -> list[dict]:
    rows = (await session.scalars(select(ThreatFeed).order_by(ThreatFeed.name.asc()))).all()
    return [_feed_out(r) for r in rows]


@router.post("/feeds", status_code=status.HTTP_201_CREATED)
async def create_feed(
    body: FeedCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    pc = body.parser_config
    is_taxii = bool(pc) and pc.get("format") == "taxii"
    # kind_hint drives the line/CSV classifier; a TAXII feed derives the type
    # from the STIX pattern, so it's irrelevant there.
    if not is_taxii and body.kind_hint not in ("auto", "ip", "domain", "url"):
        raise HTTPException(400, "kind_hint must be one of: auto, ip, domain, url")
    await _guard_feed_url(body.url)  # for TAXII, `url` is the collection URL
    f = ThreatFeed(
        name=body.name.strip(),
        url=body.url.strip(),
        kind_hint=body.kind_hint,
        enabled=body.enabled,
        parser_config=pc,
    )
    session.add(f)
    await session.flush()
    await audit.log(
        session,
        user_id=user.id,
        action="threat_feed.create",
        target_type="threat_feed",
        target_id=f.id,
        diff={"name": f.name, "url": f.url, "format": (pc or {}).get("format", "lines")},
    )
    return _feed_out(f)


@router.patch("/feeds/{feed_id}")
async def patch_feed(
    feed_id: uuid.UUID,
    body: FeedPatch,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    f = await session.get(ThreatFeed, feed_id)
    if not f:
        raise HTTPException(404, "feed not found")

    updates = body.model_dump(exclude_unset=True)
    # A TAXII feed (existing or newly set) exempts the kind_hint check.
    is_taxii = (updates.get("parser_config") or f.parser_config or {}).get("format") == "taxii"
    if (
        "kind_hint" in updates
        and not is_taxii
        and updates["kind_hint"]
        not in (
            "auto",
            "ip",
            "domain",
            "url",
        )
    ):
        raise HTTPException(400, "kind_hint must be one of: auto, ip, domain, url")
    if updates.get("url"):
        await _guard_feed_url(updates["url"])
    for k, v in updates.items():
        setattr(f, k, v)
    await audit.log(
        session,
        user_id=user.id,
        action="threat_feed.patch",
        target_type="threat_feed",
        target_id=f.id,
        diff={**updates, "parser_config": _redact_parser_config(updates.get("parser_config"))}
        if "parser_config" in updates
        else updates,
    )
    return _feed_out(f)


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_feed(
    feed_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
):
    f = await session.get(ThreatFeed, feed_id)
    if not f:
        raise HTTPException(404, "feed not found")
    await audit.log(
        session,
        user_id=user.id,
        action="threat_feed.delete",
        target_type="threat_feed",
        target_id=f.id,
        diff={"name": f.name, "url": f.url},
    )
    await session.delete(f)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Sync trigger ─────────────────────────────────────────────────────────
@router.post("/sync")
async def trigger_sync(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
) -> dict:
    """Enqueue an out-of-band sync. The cron runs daily at 04:00 UTC; this
    is the 'Sync now' button. Returns immediately with a job_id; the IOC
    page will reflect new counts once the worker finishes."""
    job = await arq.enqueue_job("threat_intel_sync")
    await audit.log(
        session,
        user_id=user.id,
        action="threat_feed.sync_manual",
        target_type="threat_feed",
        target_id=None,
        diff={"job_id": getattr(job, "job_id", None)},
    )
    return {"status": "queued", "job_id": getattr(job, "job_id", None)}
