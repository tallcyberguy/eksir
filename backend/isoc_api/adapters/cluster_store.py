"""Alert correlation persistence — group same-tenant incidents into clusters.

The DB side of Phase 2a. Called best-effort by ``pipeline/_step_correlate``.
An incident is correlated with same-tenant siblings that share a STRONG entity
(see ``pipeline/correlation.is_strong_entity``) within a time window; the group
is materialized as an ``IncidentCluster`` + ``IncidentClusterMember`` rows.

Concurrency posture mirrors ``entity_store``:
  * a per-tenant PG advisory *transaction* lock serializes the union decision so
    two racing incidents can't create two clusters for the same entity;
  * each membership INSERT runs inside its own ``begin_nested`` SAVEPOINT with
    ``ON CONFLICT DO NOTHING``, so a losing racer can't poison the transaction.

Safety invariant: the same-tenant guard (``tenant_id IS NOT DISTINCT FROM``) is
mandatory — a GLOBAL entity (a file hash, shared across every customer) must
NEVER fuse two tenants' incidents into one cluster.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import (
    Entity,
    Incident,
    IncidentCluster,
    IncidentClusterMember,
    IncidentEntity,
)
from ..logging_config import get_logger
from ..pipeline import correlation

logger = get_logger("isoc.cluster")


async def _strong_entity_ids(
    session: AsyncSession, incident: Incident, *, fanout_cap: int
) -> list[uuid.UUID]:
    """STRONG entity ids of this incident, dropping high-fan-out ones.

    An entity is kept only if (a) it is a strong signal and (b) it links to no
    more than ``fanout_cap`` in-tenant, non-deleted incidents. A shared entity
    that touches half the estate would over-correlate, so it is excluded.
    """
    rows = (
        await session.execute(
            select(IncidentEntity.entity_id, Entity.entity_type, Entity.attributes)
            .join(Entity, Entity.id == IncidentEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
        )
    ).all()

    kept: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for entity_id, entity_type, attributes in rows:
        if entity_id in seen:
            continue
        seen.add(entity_id)
        if not correlation.is_strong_entity(entity_type, attributes):
            continue
        # count DISTINCT in-tenant, non-deleted incidents linked to this entity.
        fanout = (
            await session.execute(
                select(func.count(func.distinct(IncidentEntity.incident_id)))
                .select_from(IncidentEntity)
                .join(Incident, Incident.id == IncidentEntity.incident_id)
                .where(
                    IncidentEntity.entity_id == entity_id,
                    Incident.deleted_at.is_(None),
                    Incident.tenant_id.is_not_distinct_from(incident.tenant_id),
                )
            )
        ).scalar_one()
        if fanout > fanout_cap:
            continue
        kept.append(entity_id)
    return kept


async def _sibling_incident_ids(
    session: AsyncSession,
    incident: Incident,
    entity_ids: list[uuid.UUID],
    *,
    window_hours: int,
    min_shared: int,
) -> list[uuid.UUID]:
    """Same-tenant incidents (not this one) sharing >= min_shared of entity_ids.

    Counts DISTINCT entity_id (never ``count(*)``) because one entity can link to
    an incident under multiple roles. The same-tenant guard is mandatory.
    """
    window_start = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    rows = (
        await session.execute(
            select(IncidentEntity.incident_id)
            .join(Incident, Incident.id == IncidentEntity.incident_id)
            .where(
                IncidentEntity.entity_id.in_(entity_ids),
                IncidentEntity.incident_id != incident.id,
                Incident.deleted_at.is_(None),
                Incident.tenant_id.is_not_distinct_from(incident.tenant_id),
                Incident.created_at >= window_start,
            )
            .group_by(IncidentEntity.incident_id)
            .having(func.count(func.distinct(IncidentEntity.entity_id)) >= min_shared)
        )
    ).all()
    return [r[0] for r in rows]


async def _shared_entity_for(
    session: AsyncSession, incident_id: uuid.UUID, entity_ids: list[uuid.UUID]
) -> uuid.UUID | None:
    """Best-effort: one strong entity id linking this incident (for provenance)."""
    return (
        await session.execute(
            select(IncidentEntity.entity_id)
            .where(
                IncidentEntity.incident_id == incident_id,
                IncidentEntity.entity_id.in_(entity_ids),
            )
            .limit(1)
        )
    ).scalar_one_or_none()


async def _insert_member(
    session: AsyncSession,
    cluster_id: uuid.UUID,
    incident_id: uuid.UUID,
    shared_entity_id: uuid.UUID | None,
) -> None:
    """Idempotent membership INSERT inside its own SAVEPOINT.

    ``ON CONFLICT DO NOTHING`` on either unique constraint (cluster+incident, or
    incident-alone) so a race that already placed this incident in a cluster is
    a no-op rather than an IntegrityError that poisons the outer transaction.
    """
    try:
        async with session.begin_nested():  # SAVEPOINT
            stmt = (
                pg_insert(IncidentClusterMember)
                .values(
                    cluster_id=cluster_id,
                    incident_id=incident_id,
                    shared_entity_id=shared_entity_id,
                    method="auto",
                )
                .on_conflict_do_nothing()
            )
            await session.execute(stmt)
    except Exception as ex:  # noqa: BLE001 — one racer can't drop the rest
        logger.warning(
            "cluster.member_insert_failed",
            cluster_id=str(cluster_id),
            incident_id=str(incident_id),
            error=str(ex),
        )


async def correlate_incident(
    session: AsyncSession,
    incident: Incident,
    *,
    window_hours: int,
    fanout_cap: int,
    min_shared: int,
) -> dict | None:
    """Best-effort correlation. Returns {cluster_id, member_count} or None.

    Returns None when the incident has no strong entities or no in-window
    same-tenant siblings (i.e. nothing to cluster).
    """
    # 1. strong entity ids (drop high-fan-out).
    entity_ids = await _strong_entity_ids(session, incident, fanout_cap=fanout_cap)
    if not entity_ids:
        return None

    # 2/3. candidate siblings sharing >= min_shared, same tenant, in-window.
    siblings = await _sibling_incident_ids(
        session, incident, entity_ids, window_hours=window_hours, min_shared=min_shared
    )
    if not siblings:
        return None

    # 4. serialize the union per tenant so two racing incidents don't both
    #    create a cluster for the same entity. hashtext -> int4 advisory key.
    tenant_key = str(incident.tenant_id) if incident.tenant_id is not None else "global"
    await session.execute(select(func.pg_advisory_xact_lock(func.hashtext(f"corr:{tenant_key}"))))

    # 5. member set = {X} ∪ siblings.
    member_ids = list({incident.id, *siblings})

    # existing clusters for those incidents (each incident is in <=1 cluster).
    existing = (
        (
            await session.execute(
                select(IncidentClusterMember.cluster_id)
                .where(IncidentClusterMember.incident_id.in_(member_ids))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    cluster_ids = [c for c in existing if c is not None]

    if not cluster_ids:
        # A) none exist -> create a fresh cluster anchored on the oldest member.
        cluster_id = await _create_cluster(session, incident, member_ids)
    elif len(cluster_ids) == 1:
        # B) exactly one -> reuse it, insert missing members.
        cluster_id = cluster_ids[0]
    else:
        # C) multiple -> transitive merge into the winner (oldest seed).
        cluster_id = await _merge_clusters(session, cluster_ids)

    # insert all members (ON CONFLICT DO NOTHING handles the already-present ones).
    for mid in member_ids:
        shared = await _shared_entity_for(session, mid, entity_ids)
        await _insert_member(session, cluster_id, mid, shared)

    # 6. recompute member_count + reseed to the oldest current member.
    member_count = await _reconcile_cluster(session, cluster_id)
    return {"cluster_id": str(cluster_id), "member_count": member_count}


async def _create_cluster(
    session: AsyncSession, incident: Incident, member_ids: list[uuid.UUID]
) -> uuid.UUID:
    """Create an IncidentCluster anchored on the oldest member incident."""
    seed = await _oldest_incident(session, member_ids)
    seed_id = seed.id if seed is not None else incident.id
    title = (seed.title if seed is not None else incident.title) or None
    cluster = IncidentCluster(
        tenant_id=incident.tenant_id,
        seed_incident_id=seed_id,
        title=title[:512] if title else None,
        status="open",
        member_count=len(member_ids),
    )
    session.add(cluster)
    await session.flush()  # assign cluster.id
    return cluster.id


async def _merge_clusters(session: AsyncSession, cluster_ids: list[uuid.UUID]) -> uuid.UUID:
    """Transitive merge: winner = cluster with the oldest seed incident.

    Reparent all loser members onto the winner, then delete the loser clusters.
    Tiebreak on cluster.id for determinism when seeds are equal/NULL.
    """
    clusters = (
        (await session.execute(select(IncidentCluster).where(IncidentCluster.id.in_(cluster_ids))))
        .scalars()
        .all()
    )

    # seed created_at for each cluster (NULL sorts last).
    seed_ids = [c.seed_incident_id for c in clusters if c.seed_incident_id is not None]
    seed_created: dict[uuid.UUID, object] = {}
    if seed_ids:
        rows = (
            await session.execute(
                select(Incident.id, Incident.created_at).where(Incident.id.in_(seed_ids))
            )
        ).all()
        seed_created = {r[0]: r[1] for r in rows}

    def _rank(c: IncidentCluster):
        ts = seed_created.get(c.seed_incident_id) if c.seed_incident_id else None
        # (has_ts, ts, id): clusters WITH a known seed ts sort first (oldest wins).
        return (ts is None, ts, str(c.id))

    winner = min(clusters, key=_rank)
    loser_ids = [c.id for c in clusters if c.id != winner.id]
    if loser_ids:
        # Reparent loser members onto the winner. ON CONFLICT (incident_id) is
        # possible if the winner already holds that incident; SAVEPOINT it and
        # fall back to deleting the duplicate loser membership.
        for lid in loser_ids:
            member_pks = (
                (
                    await session.execute(
                        select(IncidentClusterMember.id).where(
                            IncidentClusterMember.cluster_id == lid
                        )
                    )
                )
                .scalars()
                .all()
            )
            for member_pk in member_pks:
                try:
                    async with session.begin_nested():  # SAVEPOINT per reparent
                        await session.execute(
                            IncidentClusterMember.__table__.update()
                            .where(IncidentClusterMember.id == member_pk)
                            .values(cluster_id=winner.id)
                        )
                except Exception:  # noqa: BLE001 — winner already has this incident
                    await session.execute(
                        IncidentClusterMember.__table__.delete().where(
                            IncidentClusterMember.id == member_pk
                        )
                    )
        # delete the now-empty loser clusters.
        await session.execute(
            IncidentCluster.__table__.delete().where(IncidentCluster.id.in_(loser_ids))
        )
    return winner.id


async def _oldest_incident(session: AsyncSession, incident_ids: list[uuid.UUID]) -> Incident | None:
    """The oldest (min created_at) incident among the ids."""
    return (
        await session.execute(
            select(Incident)
            .where(Incident.id.in_(incident_ids))
            .order_by(Incident.created_at.asc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _reconcile_cluster(session: AsyncSession, cluster_id: uuid.UUID) -> int:
    """Recompute member_count + reseed to the oldest current member. Returns count."""
    member_incident_ids = (
        (
            await session.execute(
                select(IncidentClusterMember.incident_id).where(
                    IncidentClusterMember.cluster_id == cluster_id
                )
            )
        )
        .scalars()
        .all()
    )
    count = len(member_incident_ids)

    cluster = await session.get(IncidentCluster, cluster_id)
    if cluster is None:
        return count
    cluster.member_count = count
    seed = await _oldest_incident(session, list(member_incident_ids))
    if seed is not None:
        cluster.seed_incident_id = seed.id
        if seed.title:
            cluster.title = seed.title[:512]
    await session.flush()
    return count
