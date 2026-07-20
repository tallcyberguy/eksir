"""Entity read API — list / search / detail for resolved OCSF entities.

Entities have NO tenant_id of their own. They are scoped THROUGH their linked
incidents: an entity is visible only if it is linked to at least one in-scope
incident (mirrors how dashboard.py scopes IOCRecord through Incident). The
`Entity.customer` column is a display/filter field ONLY, never the security
boundary — a global (customer NULL) file-hash entity is still gated by whichever
in-scope incidents reference it.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import desc, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import (
    TenantScope,
    current_tenant_scope,
    scope_clause_for_incidents,
)
from ..db.models import Entity, Incident, IncidentEntity, User
from ..db.session import get_session
from ..schemas import EntityDetail, EntityIncidentLink, EntitySummary

router = APIRouter()


@router.get("", response_model=list[EntitySummary])
async def list_entities(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    entity_type: str | None = Query(default=None),
    customer: str | None = Query(default=None),
    q: str | None = Query(default=None, description="ILIKE on display_name / canonical_key"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> list[EntitySummary]:
    """Searchable entity list, scoped to entities linked to >=1 in-scope incident.

    Visibility is an EXISTS subquery joining IncidentEntity -> Incident under
    scope_clause_for_incidents(scope); the per-row incident_count is a correlated
    subquery counting only those same in-scope links.
    """
    # Visibility: at least one in-scope, non-archived incident links this entity.
    # deleted_at IS NULL mirrors the incident list's default archive-hiding
    # (cases.py _build_incident_filter) so the entity API can't disclose an
    # archived incident's existence/metadata that the list hides.
    visible = exists(
        select(IncidentEntity.id)
        .join(Incident, Incident.id == IncidentEntity.incident_id)
        .where(
            IncidentEntity.entity_id == Entity.id,
            scope_clause_for_incidents(scope),
            Incident.deleted_at.is_(None),
        )
    )

    conditions = [visible]
    if entity_type:
        conditions.append(Entity.entity_type == entity_type)
    if customer:
        conditions.append(Entity.customer.ilike(f"%{customer}%"))
    if q:
        like = f"%{q}%"
        conditions.append(Entity.display_name.ilike(like) | Entity.canonical_key.ilike(like))

    total = await session.scalar(select(func.count(Entity.id)).where(*conditions)) or 0
    response.headers["X-Total-Count"] = str(total)
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"

    # Correlated count of DISTINCT in-scope, non-archived incidents per entity.
    # count(distinct incident_id) — not count(link rows) — so a future entity
    # linked to one incident under multiple roles never double-counts it.
    incident_count = (
        select(func.count(func.distinct(IncidentEntity.incident_id)))
        .join(Incident, Incident.id == IncidentEntity.incident_id)
        .where(
            IncidentEntity.entity_id == Entity.id,
            scope_clause_for_incidents(scope),
            Incident.deleted_at.is_(None),
        )
        .correlate(Entity)
        .scalar_subquery()
    )

    stmt = (
        select(Entity, incident_count.label("incident_count"))
        .where(*conditions)
        .order_by(desc(Entity.last_seen))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await session.execute(stmt)).all()
    out: list[EntitySummary] = []
    for entity, count in rows:
        summary = EntitySummary.model_validate(entity)
        summary.incident_count = int(count or 0)
        out.append(summary)
    return out


@router.get("/{entity_id}", response_model=EntityDetail)
async def get_entity(
    entity_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> EntityDetail:
    """One entity + its in-scope linked incidents (newest first).

    404 if the entity is missing OR has no in-scope linked incidents — the same
    existence-hiding contract as require_in_scope on incidents. Incident ORM
    objects are loaded so the read-only confidence_score/threat_score props are
    available on each link.
    """
    entity = await session.get(Entity, entity_id)
    if not entity:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "entity not found")

    # In-scope links, newest incident first. Loading the Incident ORM object
    # (not just columns) exposes the confidence_score/threat_score props.
    link_rows = (
        await session.execute(
            select(IncidentEntity.role, Incident)
            .join(Incident, Incident.id == IncidentEntity.incident_id)
            .where(
                IncidentEntity.entity_id == entity_id,
                scope_clause_for_incidents(scope),
                Incident.deleted_at.is_(None),
            )
            .order_by(desc(Incident.created_at))
        )
    ).all()

    # No in-scope links → treat as not found (don't leak existence).
    if not link_rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "entity not found")

    # Dedup by incident: if one incident links this entity under >1 role, keep
    # the first (newest, since ordered created_at desc) so it appears once.
    seen: set[uuid.UUID] = set()
    incidents: list[EntityIncidentLink] = []
    for role, inc in link_rows:
        if inc.id in seen:
            continue
        seen.add(inc.id)
        incidents.append(
            EntityIncidentLink(
                role=role,
                incident_id=inc.id,
                case_number=inc.case_number,
                title=inc.title,
                status=inc.status,
                severity=inc.severity,
                verdict=inc.verdict,
                customer=inc.customer,
                created_at=inc.created_at,
                closed_at=inc.closed_at,
                confidence_score=inc.confidence_score,
                threat_score=inc.threat_score,
            )
        )

    detail = EntityDetail.model_validate(entity)
    detail.incident_count = len(incidents)
    detail.incidents = incidents
    return detail
