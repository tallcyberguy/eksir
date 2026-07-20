"""Shared OCSF-entity persistence — race-safe UPSERT + idempotent incident link.

These two helpers used to live in ``pipeline/orchestrator.py`` (as
``_upsert_entity`` / ``_link_incident_entity``). They were lifted here verbatim
so both the live pipeline (``_step_entities``) and the offline backfill script
(``scripts/backfill_entities_from_db.py``) share one implementation.

Both operate on a caller-supplied ``AsyncSession`` and issue PG
``INSERT ... ON CONFLICT`` statements, so they are safe under concurrent inserts
of the same host/hash and are idempotent on re-run.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Entity, Incident, IncidentEntity
from ..pipeline import entity_risk


async def upsert_entity(session: AsyncSession, e: dict, now: datetime) -> uuid.UUID | None:
    """Race-safe UPSERT of one OCSF entity; returns its id (never None on success).

    Uses PG ``INSERT ... ON CONFLICT`` so two alerts for the same host/hash
    running concurrently can't raise ``IntegrityError`` on a duplicate insert
    (the losing racer would otherwise poison the whole transaction). The conflict
    target differs by tenancy: GLOBAL entities (customer IS NULL — file hashes)
    dedupe on the partial unique index; tenant entities on the composite unique
    constraint. ``DO UPDATE`` (not ``DO NOTHING``) so ``RETURNING`` yields the id
    whether the row was just inserted or already existed.
    """
    set_ = {"last_seen": now, "display_name": e["display_name"], "attributes": e["attributes"]}
    stmt = pg_insert(Entity).values(
        customer=e["customer"],
        entity_type=e["entity_type"],
        canonical_key=e["canonical_key"],
        display_name=e["display_name"],
        attributes=e["attributes"],
        first_seen=now,
        last_seen=now,
    )
    if e["customer"] is None:
        stmt = stmt.on_conflict_do_update(
            index_elements=["entity_type", "canonical_key"],
            index_where=text("customer IS NULL"),
            set_=set_,
        )
    else:
        stmt = stmt.on_conflict_do_update(constraint="uq_entity_customer_type_key", set_=set_)
    result = await session.execute(stmt.returning(Entity.id))
    return result.scalar_one_or_none()


async def link_incident_entity(
    session: AsyncSession, incident_id: uuid.UUID, entity_id: uuid.UUID, role: str
) -> None:
    """Idempotently link an incident to an entity in a role (ON CONFLICT DO NOTHING)."""
    stmt = (
        pg_insert(IncidentEntity)
        .values(incident_id=incident_id, entity_id=entity_id, role=role)
        .on_conflict_do_nothing(constraint="uq_incident_entity_role")
    )
    await session.execute(stmt)


async def get_risk_scores(
    session: AsyncSession, entity_ids: list[uuid.UUID]
) -> dict[uuid.UUID, float]:
    """risk_score per entity id (only entities that HAVE one — None rows omitted)."""
    if not entity_ids:
        return {}
    rows = (
        await session.execute(
            select(Entity.id, Entity.risk_score).where(
                Entity.id.in_(entity_ids), Entity.risk_score.is_not(None)
            )
        )
    ).all()
    return {eid: float(risk) for eid, risk in rows}


async def recompute_entity_risk(
    session: AsyncSession,
    entity_ids: list[uuid.UUID],
    *,
    now: datetime | None = None,
) -> int:
    """Recompute + persist ``Entity.risk_score`` from confirmed-verdict history.

    For each entity, folds its linked non-archived incidents' (verdict,
    threat_score, created_at) through ``entity_risk.compute_entity_risk`` —
    confirmed-TP-only, 30-day half-life, noisy-OR. Called best-effort at the
    verdict gate (the only place verdicts change) and by the recompute script.
    Returns the number of entities whose risk was written.
    """
    if not entity_ids:
        return 0
    rows = (
        await session.execute(
            select(
                IncidentEntity.entity_id,
                Incident.verdict,
                Incident.enrichment,
                Incident.created_at,
            )
            .join(Incident, Incident.id == IncidentEntity.incident_id)
            .where(
                IncidentEntity.entity_id.in_(entity_ids),
                Incident.deleted_at.is_(None),
            )
        )
    ).all()

    history: dict[uuid.UUID, list[dict]] = {eid: [] for eid in entity_ids}
    for eid, verdict, enrichment, created_at in rows:
        scores = (enrichment or {}).get("scores") or {}
        history.setdefault(eid, []).append(
            {
                "verdict": str(getattr(verdict, "value", verdict) or ""),
                "threat_score": scores.get("threat"),
                "created_at": created_at,
            }
        )

    written = 0
    for eid, incidents in history.items():
        risk = entity_risk.compute_entity_risk(incidents, now=now)
        await session.execute(update(Entity).where(Entity.id == eid).values(risk_score=risk))
        written += 1
    return written
