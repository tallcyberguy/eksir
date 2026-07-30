"""Incidents (cases) — list / detail / patch / timeline / IOCs / regenerate."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from arq.connections import ArqRedis
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from .. import audit, mentions, notify
from ..adapters import defender_adapter, entity_store, integration_store, store_adapter, v1_adapter
from ..auth.deps import current_user, require_admin, require_analyst
from ..auth.tenancy import (
    TenantScope,
    current_tenant_scope,
    ensure_tenant_for_customer,
    require_in_scope,
    scope_clause_for_incidents,
)
from ..db.enums import CaseStatus, Role, Severity, UserStatus, Verdict
from ..db.models import (
    CustomerCase,
    Entity,
    Incident,
    IncidentCluster,
    IncidentClusterMember,
    IncidentComment,
    IncidentEntity,
    IncidentWatcher,
    IOCRecord,
    LLMCall,
    TimelineEvent,
    User,
)
from ..db.session import get_session
from ..logging_config import get_logger
from ..pipeline import sla
from ..queue import get_arq
from ..schemas import (
    ClusterMember,
    ClusterSummary,
    IncidentDetail,
    IncidentEntityLink,
    IncidentPatch,
    IncidentSummary,
    IOCOut,
    TimelineEventOut,
)
from ..settings import settings

logger = get_logger("isoc.cases")
router = APIRouter()


async def _notify_assignment(
    session: AsyncSession,
    arq: ArqRedis,
    *,
    inc: Incident,
    assignee_id: uuid.UUID,
    actor: User,
) -> None:
    """Notify a user that they were newly assigned an incident: one in-app
    notification (added to the caller's transaction) plus a best-effort email via
    the worker. The caller guarantees assignee_id is a real, changed, non-actor
    assignee. Never raises, so a notification failure cannot fail the assignment.
    """
    assignee = await session.get(User, assignee_id)
    if assignee is None or assignee.status != UserStatus.ACTIVE:
        return
    await notify.notify_users(
        session,
        [assignee_id],
        kind="assignment",
        title=f"Assigned to you: {inc.case_number}",
        body=inc.title or None,
        link=f"/incidents/{inc.id}",
        actor_id=actor.id,
    )
    if not assignee.email:
        return
    try:
        await arq.enqueue_job(
            "send_assignment_email",
            {
                "to": assignee.email,
                "actor": actor.full_name or actor.email,
                "case_number": inc.case_number,
                "title": inc.title or "",
                "url": f"{settings.isoc_public_url.rstrip('/')}/incidents/{inc.id}",
            },
        )
    except Exception as e:  # pragma: no cover - enqueue failure is non-fatal
        logger.warning("assignment_email.enqueue_failed", error=str(e))


async def _notify_bulk_assignment(
    session: AsyncSession,
    arq: ArqRedis,
    *,
    incidents: list[Incident],
    assignee_id: uuid.UUID,
    actor: User,
) -> None:
    """Bulk variant: one summary in-app notification + one summary email for a
    batch of incidents newly assigned to the same user (avoids flooding the bell /
    inbox with one message per incident). Never raises."""
    assignee = await session.get(User, assignee_id)
    if assignee is None or assignee.status != UserStatus.ACTIVE or not incidents:
        return
    n = len(incidents)
    numbers = ", ".join(i.case_number for i in incidents[:5])
    more = "" if n <= 5 else f" +{n - 5} more"
    await notify.notify_users(
        session,
        [assignee_id],
        kind="assignment",
        title=f"Assigned to you: {n} incident{'s' if n != 1 else ''}",
        body=f"{numbers}{more}",
        link="/incidents",
        actor_id=actor.id,
    )
    if not assignee.email:
        return
    try:
        await arq.enqueue_job(
            "send_assignment_email",
            {
                "to": assignee.email,
                "actor": actor.full_name or actor.email,
                "count": n,
                "case_numbers": [i.case_number for i in incidents[:10]],
                "url": f"{settings.isoc_public_url.rstrip('/')}/incidents",
            },
        )
    except Exception as e:  # pragma: no cover - enqueue failure is non-fatal
        logger.warning("assignment_email.enqueue_failed", error=str(e))


@router.get("/customers")
async def list_customers(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    """Distinct customer values with incident counts — used by the new-incident
    page to seed a combobox of existing customers."""
    stmt = (
        select(Incident.customer, func.count(Incident.id))
        .where(Incident.customer.is_not(None))
        .where(scope_clause_for_incidents(scope))
        .group_by(Incident.customer)
        .order_by(func.count(Incident.id).desc())
    )
    rows = (await session.execute(stmt)).all()
    return [{"name": c, "count": int(n)} for c, n in rows if c]


def _build_incident_filter(
    scope: TenantScope,
    status_: CaseStatus | None,
    severity: Severity | None,
    verdict: Verdict | None,
    customer: str | None,
    q: str | None,
    include_deleted: str,
    escalated: bool | None = None,
):
    """Shared WHERE-clause builder. `include_deleted` is "false" (default — hide
    archived), "true" (show only archived), or "all" (show both). The endpoint
    enforces admin-only for the latter two."""
    conditions = [scope_clause_for_incidents(scope)]
    if include_deleted == "false":
        conditions.append(Incident.deleted_at.is_(None))
    elif include_deleted == "true":
        conditions.append(Incident.deleted_at.is_not(None))
    # "all" → no deleted_at filter
    if status_:
        conditions.append(Incident.status == status_)
    if severity:
        conditions.append(Incident.severity == severity)
    if verdict:
        conditions.append(Incident.verdict == verdict)
    if escalated is True:
        conditions.append(Incident.escalated_at.is_not(None))
    elif escalated is False:
        conditions.append(Incident.escalated_at.is_(None))
    if customer:
        conditions.append(Incident.customer.ilike(f"%{customer}%"))
    if q:
        pat = f"%{q}%"
        conditions.append(
            or_(
                Incident.title.ilike(pat),
                Incident.rule_name.ilike(pat),
                Incident.case_number.ilike(pat),
            )
        )
    return conditions


@router.get("", response_model=list[IncidentSummary])
async def list_incidents(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    status_: CaseStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = None,
    verdict: Verdict | None = None,
    customer: str | None = None,
    q: str | None = None,  # free-text: title + rule_name
    escalated: bool | None = None,  # true = only L2-escalated; false = only non-escalated
    sort: str = Query(default="desc", pattern="^(asc|desc)$"),  # newest-first by default
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    include_deleted: str = Query(
        default="false",
        pattern="^(false|true|all)$",
        description="false=hide archived (default), true=only archived, all=both. "
        "Non-default values require admin.",
    ),
) -> list[IncidentSummary]:
    # Non-admin callers can't peek into the archive. We don't error — we silently
    # coerce. Easier on the frontend than handling 403 every time someone has
    # the wrong role.
    if include_deleted != "false" and user.role != Role.ADMIN:
        include_deleted = "false"

    conditions = _build_incident_filter(
        scope,
        status_,
        severity,
        verdict,
        customer,
        q,
        include_deleted,
        escalated=escalated,
    )

    # Total count (matches the filters but ignores pagination). One extra query
    # per page-load is cheaper than threading total through a wrapper model.
    total = await session.scalar(select(func.count(Incident.id)).where(*conditions)) or 0
    response.headers["X-Total-Count"] = str(total)
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"

    order = asc(Incident.created_at) if sort == "asc" else desc(Incident.created_at)
    # Per-row correlation cluster size: count of LIVE (non-archived) members in
    # the incident's cluster, 0/NULL when unclustered. Counted from membership
    # rows rather than the stored IncidentCluster.member_count column — archiving
    # a member doesn't reconcile that column, and the cluster detail route already
    # derives its count from live members, so this keeps the badge and the detail
    # header in agreement. Correlated scalar subquery: one row per incident.
    sibling_link = aliased(IncidentClusterMember)
    sibling_inc = aliased(Incident)
    cluster_size_sq = (
        select(func.count())
        .select_from(IncidentClusterMember)
        .join(sibling_link, sibling_link.cluster_id == IncidentClusterMember.cluster_id)
        .join(sibling_inc, sibling_inc.id == sibling_link.incident_id)
        .where(
            IncidentClusterMember.incident_id == Incident.id,
            sibling_inc.deleted_at.is_(None),
        )
        .correlate(Incident)
        .scalar_subquery()
    )
    # Assignee display name (full_name or email), so the list shows who owns each
    # incident without an admin-only users lookup. NULL when unassigned.
    assignee_u = aliased(User)
    assignee_name_sq = (
        select(func.coalesce(assignee_u.full_name, assignee_u.email))
        .where(assignee_u.id == Incident.assignee_id)
        .correlate(Incident)
        .scalar_subquery()
    )
    stmt = (
        select(
            Incident,
            cluster_size_sq.label("cluster_size"),
            assignee_name_sq.label("assignee_name"),
        )
        .where(*conditions)
        .order_by(order)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await session.execute(stmt)).all()
    out: list[IncidentSummary] = []
    for inc, cluster_size, assignee_name in rows:
        summary = IncidentSummary.model_validate(inc)
        # Only surface a badge for a real cluster (>1 member); size-1 is just self.
        summary.cluster_size = int(cluster_size) if cluster_size and cluster_size > 1 else None
        summary.assignee_name = assignee_name
        out.append(summary)
    return out


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> IncidentDetail:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    return _detail_out(inc)


def _detail_out(inc: Incident) -> IncidentDetail:
    """IncidentDetail with the (potentially large) raw hunt evidence stripped —
    it's served on demand by GET /{id}/hunt-evidence, not in the gate poll."""
    detail = IncidentDetail.model_validate(inc)
    if detail.enrichment and "hunt_evidence" in detail.enrichment:
        detail.enrichment = {k: v for k, v in detail.enrichment.items() if k != "hunt_evidence"}
    return detail


class AssignIn(BaseModel):
    assignee_id: uuid.UUID | None = None  # omit / null → assign to self


@router.post("/{incident_id}/assign")
async def assign_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    body: AssignIn | None = None,
) -> dict[str, Any]:
    """Assign an incident (default: to self) and stamp the response-SLA anchor.

    `claimed_at` is set on the FIRST claim only (NULL → now), so the response-SLA
    clock starts when an analyst first takes ownership from the incident page — the
    same signal the Queue claim records (incl. the `acknowledged` SLA event).
    Re-assignments never reset it, so the response time stays honest.
    """
    now = datetime.now(timezone.utc)
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    target = body.assignee_id if (body and body.assignee_id) else user.id
    prior = inc.assignee_id
    first_claim = inc.claimed_at is None
    inc.assignee_id = target
    if first_claim:
        inc.claimed_at = now
        sla.record_sla_event(session, inc, sla.ACKNOWLEDGED, actor_id=user.id)

    mine = target == user.id
    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=now,
            actor=user.email,
            event_type="assigned",
            display="Assigned to self" if mine else f"Assigned to {target}",
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.assign",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={"assignee_id": str(target), "first_claim": first_claim},
    )
    # Notify the new owner (skip self-assignment and no-op re-assignment).
    if target != user.id and target != prior:
        await _notify_assignment(session, arq, inc=inc, assignee_id=target, actor=user)
    await session.commit()
    return {
        "assignee_id": str(target),
        "claimed_at": inc.claimed_at.isoformat() if inc.claimed_at else None,
        "first_claim": first_claim,
    }


async def _notify_escalation(session: AsyncSession, inc: Incident, *, actor: User) -> None:
    """In-app notify the incident's watchers that it was escalated to L2 (best-
    effort). L2 analysts primarily discover escalations via the `escalated=true`
    queue filter; once the L2 role ships (PR l1-l2-action-gating), this can also
    notify active L2-role users."""
    watcher_ids = await _incident_watcher_ids(session, inc.id)
    await notify.notify_users(
        session,
        watcher_ids,
        kind="escalation",
        title=f"Escalated to L2: {inc.case_number}",
        body=inc.title or None,
        link=f"/incidents/{inc.id}",
        actor_id=actor.id,
    )


class EscalateIn(BaseModel):
    note: str | None = None  # optional one-line reason


@router.post("/{incident_id}/escalate")
async def escalate_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    body: EscalateIn | None = None,
) -> dict[str, Any]:
    """Escalate an incident to L2 (an L1 hands off a case they can't action, e.g.
    when a critical response action needs L2). Idempotent: a no-op if already
    escalated. Escalated incidents surface to L2 via the `escalated=true` filter.
    """
    now = datetime.now(timezone.utc)
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    if inc.escalated_at is not None:
        return {
            "escalated_at": inc.escalated_at.isoformat(),
            "escalated_by_id": str(inc.escalated_by_id) if inc.escalated_by_id else None,
            "already": True,
        }

    note = (body.note.strip() if body and body.note else None) or None
    inc.escalated_at = now
    inc.escalated_by_id = user.id
    inc.escalation_note = note
    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=now,
            actor=user.email,
            event_type="escalated_l2",
            display="Escalated to L2" + (f": {note}" if note else ""),
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.escalate",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={"note": note},
    )
    await _notify_escalation(session, inc, actor=user)
    await session.commit()
    return {"escalated_at": now.isoformat(), "escalated_by_id": str(user.id)}


@router.post("/{incident_id}/deescalate")
async def deescalate_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    """Clear an incident's L2 escalation (idempotent)."""
    now = datetime.now(timezone.utc)
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    if inc.escalated_at is None:
        return {"escalated_at": None, "already": True}
    inc.escalated_at = None
    inc.escalated_by_id = None
    inc.escalation_note = None
    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=now,
            actor=user.email,
            event_type="deescalated",
            display="Escalation cleared",
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.deescalate",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
    )
    await session.commit()
    return {"escalated_at": None}


@router.get("/{incident_id}/hunt-evidence")
async def download_hunt_evidence(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> Response:
    """Download the raw endpoint-activity records the threat hunter matched during
    an analyst-triggered live hunt, as a JSON evidence log."""
    import json

    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    evidence = (inc.enrichment or {}).get("hunt_evidence")
    if not evidence:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no hunt evidence for this incident")
    payload = {
        "case_number": inc.case_number,
        "source": "trend_vision_one_endpoint_activity",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs": evidence,
    }
    filename = f"hunt-evidence-{inc.case_number}.json"
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch("/{incident_id}", response_model=IncidentDetail)
async def patch_incident(
    incident_id: uuid.UUID,
    body: IncidentPatch,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
) -> IncidentDetail:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    prior_assignee = inc.assignee_id
    updates = body.model_dump(exclude_unset=True)
    for k, v in updates.items():
        setattr(inc, k, v)

    # Assigning an owner is a "response" — stamp the response-SLA anchor on the
    # first claim (NULL → now), consistent with the queue claim + /assign endpoint.
    if updates.get("assignee_id") and inc.claimed_at is None:
        inc.claimed_at = datetime.now(timezone.utc)
        sla.record_sla_event(session, inc, sla.ACKNOWLEDGED, actor_id=user.id)

    # Re-resolve tenant_id if the analyst changed the customer field
    if "customer" in updates and updates["customer"]:
        inc.tenant_id = await ensure_tenant_for_customer(session, updates["customer"])
    elif "customer" in updates and not updates["customer"]:
        inc.tenant_id = None

    if "verdict" in updates and updates["verdict"] not in (Verdict.PENDING, None):
        # Precedence: the analyst's verdict-time rationale wins over their
        # free-form notes, which win over the LLM report. This is what a
        # future identical alert retrieves via exact-match / n-way.
        await _commit_verdict(
            session,
            inc,
            updates["verdict"],
            reason=(inc.verdict_reason or inc.analyst_notes or inc.llm_report_markdown or ""),
            actor=user,
        )

    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type="patch",
            display=f"Updated: {', '.join(updates.keys())}",
            payload=updates,
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.patch",
        target_type="incident",
        target_id=inc.id,
        tenant_id=inc.tenant_id,
        diff={"case_number": inc.case_number, "fields": updates},
    )
    # Notify a newly-set owner (skip unassign, no-op, and self-assignment).
    new_assignee = inc.assignee_id
    if (
        "assignee_id" in updates
        and new_assignee
        and new_assignee != prior_assignee
        and new_assignee != user.id
    ):
        await _notify_assignment(session, arq, inc=inc, assignee_id=new_assignee, actor=user)
    return _detail_out(inc)


@router.get("/{incident_id}/timeline", response_model=list[TimelineEventOut])
async def get_timeline(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[TimelineEventOut]:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    rows = (
        await session.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.incident_id == incident_id)
            .order_by(TimelineEvent.ts.asc())
        )
    ).all()
    return [TimelineEventOut.model_validate(r) for r in rows]


@router.get("/{incident_id}/iocs", response_model=list[IOCOut])
async def get_iocs(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[IOCOut]:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    rows = (
        await session.scalars(select(IOCRecord).where(IOCRecord.incident_id == incident_id))
    ).all()
    return [IOCOut.model_validate(r) for r in rows]


@router.get("/{incident_id}/entities", response_model=list[IncidentEntityLink])
async def get_entities(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[IncidentEntityLink]:
    """Resolved OCSF entities linked to this incident (mirror of get_iocs).
    Scoped by the incident itself; entities carry no tenant of their own."""
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    rows = (
        await session.execute(
            select(IncidentEntity.role, Entity)
            .join(Entity, Entity.id == IncidentEntity.entity_id)
            .where(IncidentEntity.incident_id == incident_id)
            .order_by(IncidentEntity.role.asc(), Entity.display_name.asc())
        )
    ).all()
    return [
        IncidentEntityLink(
            role=role,
            entity_id=e.id,
            entity_type=e.entity_type,
            canonical_key=e.canonical_key,
            display_name=e.display_name,
            customer=e.customer,
            risk_score=e.risk_score,
            first_seen=e.first_seen,
            last_seen=e.last_seen,
        )
        for role, e in rows
    ]


@router.get("/{incident_id}/cluster", response_model=ClusterSummary | None)
async def get_cluster(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> ClusterSummary | None:
    """The incident's correlation cluster + its sibling members (newest first).

    Returns 200 `null` when the incident belongs to no cluster (the common case —
    correlation is off by default and only groups incidents sharing a strong
    entity). Members carry the read-only confidence/threat props, a `is_seed`
    flag, and the entity that linked them (when recorded)."""
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    # One incident is in at most one cluster (uq_cluster_member_incident).
    cluster_id = await session.scalar(
        select(IncidentClusterMember.cluster_id).where(
            IncidentClusterMember.incident_id == incident_id
        )
    )
    if cluster_id is None:
        return None

    cluster = await session.get(IncidentCluster, cluster_id)
    if cluster is None:  # membership row without its cluster — treat as unclustered
        return None

    # Members joined to their live incident + (optionally) the entity that linked
    # them. LEFT JOIN entities so a null/purged shared_entity_id still yields a row.
    # Loading the Incident ORM object exposes the confidence/threat props.
    member_rows = (
        await session.execute(
            select(Incident, IncidentClusterMember.shared_entity_id, Entity.display_name)
            .join(Incident, Incident.id == IncidentClusterMember.incident_id)
            .join(Entity, Entity.id == IncidentClusterMember.shared_entity_id, isouter=True)
            .where(
                IncidentClusterMember.cluster_id == cluster_id,
                Incident.deleted_at.is_(None),
            )
            .order_by(desc(Incident.created_at))
        )
    ).all()

    members: list[ClusterMember] = []
    for member_inc, shared_entity_id, shared_entity_name in member_rows:
        members.append(
            ClusterMember(
                incident_id=member_inc.id,
                case_number=member_inc.case_number,
                title=member_inc.title,
                severity=member_inc.severity,
                status=member_inc.status,
                verdict=member_inc.verdict,
                created_at=member_inc.created_at,
                confidence_score=member_inc.confidence_score,
                threat_score=member_inc.threat_score,
                is_seed=(member_inc.id == cluster.seed_incident_id),
                shared_entity=shared_entity_name if shared_entity_id else None,
            )
        )

    return ClusterSummary(
        id=cluster.id,
        cluster_key=cluster.cluster_key,
        title=cluster.title,
        status=cluster.status,
        # Derive from the live (non-archived) rows actually returned, not the
        # stored cluster.member_count column — archiving a member doesn't
        # reconcile that column, so the stored value can exceed the visible list.
        member_count=len(members),
        seed_incident_id=cluster.seed_incident_id,
        members=members,
    )


# ── Analyst-direct IOC exclusion (from the Technical-tab IOC table) ──────────
class IocExcludeRequest(BaseModel):
    ioc_type: str
    value: str
    scope: str = "customer"  # "customer" | "global"
    notes: str | None = None


def _host_of_url(url: str) -> str | None:
    try:
        after = url.split("://", 1)[1] if "://" in url else url
        host = after.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return host.split("@", 1)[-1].split(":", 1)[0].lower() or None
    except (IndexError, AttributeError):
        return None


def _ioc_to_exclusion(ioc_type: str, value: str) -> tuple[str, str] | None:
    """Map an IOC (type, value) to an exclusion (type, value), or None if the
    IOC type isn't exclusion-eligible. url/email collapse to their host/domain
    because the exclusion filter matches those against domain rules."""
    t = (ioc_type or "").lower()
    v = (value or "").strip()
    if not v:
        return None
    if t in ("ipv4", "ipv6", "ip"):
        return ("ip", v)
    if t in ("sha256", "sha1", "md5", "hash"):
        return ("hash", v.lower())
    if t == "domain":
        return ("domain", v.lower())
    if t == "url":
        host = _host_of_url(v)
        return ("domain", host) if host else None
    if t == "email":
        dom = v.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in v else None
        return ("domain", dom) if dom else None
    return None


@router.post("/{incident_id}/iocs/exclude", status_code=status.HTTP_201_CREATED)
async def exclude_ioc(
    incident_id: uuid.UUID,
    body: IocExcludeRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    """Analyst-initiated exclusion straight from the IOC table. Adds the IOC to
    the shared exclusion list (customer-scoped by default), so it's suppressed
    from future triage. Audit-logged and recorded on the incident timeline."""
    from ..db.models import Exclusion

    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    mapped = _ioc_to_exclusion(body.ioc_type, body.value)
    if not mapped:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"`{body.ioc_type}` is not an exclusion-eligible IOC type",
        )
    ex_type, ex_value = mapped
    customer = inc.customer if body.scope != "global" else None

    # Idempotent: if a matching rule already exists, report success instead of 409.
    existing = await session.scalar(
        select(Exclusion).where(Exclusion.value == ex_value, Exclusion.ioc_type == ex_type)
    )
    if existing:
        await _mark_ioc_excluded(session, incident_id, body.value)
        return {
            "status": "already_excluded",
            "id": str(existing.id),
            "ioc_type": ex_type,
            "value": ex_value,
            "customer": existing.customer,
        }

    note = body.notes or f"excluded by {user.email} from {inc.case_number}"
    rule = Exclusion(
        value=ex_value,
        ioc_type=ex_type,
        notes=note,
        enabled=True,
        customer=customer,
        created_by_id=user.id,
    )
    session.add(rule)
    try:
        await session.flush()
    except Exception:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "exclusion already exists")

    await _mark_ioc_excluded(session, incident_id, body.value)
    scope_label = customer or "global"
    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type="analyst_exclude",
            display=f"Analyst excluded {ex_type} `{ex_value}` — scope: {scope_label}",
            payload={"ioc_type": ex_type, "value": ex_value, "scope": body.scope},
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="exclusion.create_from_incident",
        target_type="exclusion",
        target_id=rule.id,
        tenant_id=inc.tenant_id,
        diff={"value": ex_value, "ioc_type": ex_type, "customer": customer},
    )
    return {
        "status": "created",
        "id": str(rule.id),
        "ioc_type": ex_type,
        "value": ex_value,
        "customer": customer,
    }


async def _mark_ioc_excluded(session: AsyncSession, incident_id: uuid.UUID, value: str) -> None:
    """Flag any IOCRecord on this incident whose value matches (so the row shows
    as excluded). Matches case-insensitively on the original IOC value."""
    rows = (
        await session.scalars(
            select(IOCRecord).where(
                IOCRecord.incident_id == incident_id,
                func.lower(IOCRecord.value) == value.strip().lower(),
            )
        )
    ).all()
    for r in rows:
        r.excluded = True


@router.get("/{incident_id}/llm-calls")
async def get_llm_calls(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_admin)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    """Full LLM transcript history for one incident.

    Admin-only — prompts can contain customer data + analyst reasoning.
    Returns every call (fast tier, deep tier, customer-brief generations,
    forced regenerations) ordered by created_at ASC.
    """
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    rows = (
        await session.scalars(
            select(LLMCall)
            .where(LLMCall.incident_id == incident_id)
            .order_by(LLMCall.created_at.asc())
        )
    ).all()

    return [
        {
            "id": str(r.id),
            "purpose": r.purpose,
            "model": r.model,
            "provider": r.provider,
            # status is a plain str in the DB (String column mapped to StrEnum) —
            # SQLAlchemy returns the string directly.
            "status": str(r.status) if r.status else None,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "latency_ms": r.latency_ms,
            "prompt_hash": r.prompt_hash,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "system_prompt": r.system_prompt,
            "user_prompt": r.user_prompt,
            "response_text": r.response_text,
            "error": r.error,
        }
        for r in rows
    ]


@router.post("/lookup-by-qdrant-ids")
async def lookup_by_qdrant_ids(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    body: Annotated[dict, Body(...)],
) -> dict[str, dict]:
    """Resolve Qdrant point IDs → ISOC incidents in the caller's tenant scope.

    Used by the Similar Cases panel to turn each `similar_top5[].alert_id`
    into a clickable link. Out-of-scope or unresolved IDs are silently omitted
    from the response (no leak, no 404 noise per ID).

    Body:  {"qdrant_ids": ["<uuid>", "<uuid>", ...]}
    Reply: {"<qdrant_id>": {id, case_number, title, customer, verdict}, ...}
    """
    raw_ids = body.get("qdrant_ids") or []
    if not isinstance(raw_ids, list) or not raw_ids:
        return {}

    parsed: list[uuid.UUID] = []
    for s in raw_ids:
        try:
            parsed.append(uuid.UUID(str(s)))
        except (ValueError, TypeError):
            continue
    if not parsed:
        return {}

    stmt = (
        select(
            Incident.id,
            Incident.case_number,
            Incident.title,
            Incident.customer,
            Incident.verdict,
            Incident.qdrant_alert_id,
        )
        .where(Incident.qdrant_alert_id.in_(parsed))
        .where(scope_clause_for_incidents(scope))
    )
    rows = (await session.execute(stmt)).all()
    return {
        str(qid): {
            "id": str(iid),
            "case_number": cnum,
            "title": title,
            "customer": customer,
            "verdict": verdict.value if verdict else None,
        }
        for (iid, cnum, title, customer, verdict, qid) in rows
    }


# ── CSV export ────────────────────────────────────────────────────────────────
# Same filter semantics as the list endpoint. Streams all matching incidents
# (no pagination) — guarded by the max_rows cap so a malformed filter can't
# OOM the server. Analyst+ because anyone who can see the data can export it.


@router.get("/export.csv")
async def export_csv(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    status_: CaseStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = None,
    verdict: Verdict | None = None,
    customer: str | None = None,
    q: str | None = None,
    sort: str = Query(default="desc", pattern="^(asc|desc)$"),
    include_deleted: str = Query(default="false", pattern="^(false|true|all)$"),
    max_rows: int = Query(default=10000, ge=1, le=50000),
) -> StreamingResponse:
    if include_deleted != "false" and user.role != Role.ADMIN:
        include_deleted = "false"
    conditions = _build_incident_filter(
        scope,
        status_,
        severity,
        verdict,
        customer,
        q,
        include_deleted,
    )
    order = asc(Incident.created_at) if sort == "asc" else desc(Incident.created_at)
    stmt = select(Incident).where(*conditions).order_by(order).limit(max_rows)
    rows = (await session.scalars(stmt)).all()

    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "case_number",
            "title",
            "customer",
            "rule_name",
            "source_product",
            "severity",
            "status",
            "verdict",
            "confidence",
            "assignee_id",
            "created_at",
            "closed_at",
            "deleted_at",
        ]
    )
    for r in rows:
        w.writerow(
            [
                r.case_number,
                r.title,
                r.customer or "",
                r.rule_name or "",
                r.source_product or "",
                r.severity,
                r.status,
                r.verdict,
                r.confidence or "",
                str(r.assignee_id) if r.assignee_id else "",
                r.created_at.isoformat() if r.created_at else "",
                r.closed_at.isoformat() if r.closed_at else "",
                r.deleted_at.isoformat() if r.deleted_at else "",
            ]
        )
    buf.seek(0)
    filename = f"incidents-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Bulk action ───────────────────────────────────────────────────────────────
# One endpoint for all bulk operations because they share scope checks, audit
# logging, and the ids/value plumbing. Splitting into five endpoints would
# triple the surface area for marginal clarity gain.
#
# Action permissions:
#   close / verdict / reassign  → analyst+
#   archive / purge             → admin only
# Each id is looked up + scope-checked individually. Out-of-scope ids are
# skipped silently — the frontend should never offer them anyway, but defense
# in depth.


@router.post("/bulk-action")
async def bulk_action(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    body: Annotated[dict, Body(...)],
) -> dict:
    """Body:
    {
      "ids":    ["<uuid>", ...],
      "action": "archive"|"purge"|"close"|"verdict"|"reassign",
      "value":  <optional, action-specific>
    }
    """
    raw_ids = body.get("ids") or []
    action = body.get("action")
    value = body.get("value")

    if not isinstance(raw_ids, list) or not raw_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "ids must be a non-empty list")
    if action not in {"archive", "purge", "close", "verdict", "reassign"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown action: {action}")
    if action in {"archive", "purge"} and user.role != Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin only")

    if action == "verdict":
        try:
            value = Verdict(value)
        except (ValueError, TypeError):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"value must be a Verdict for action=verdict (got {value!r})",
            )
    if action == "reassign":
        if value in ("", None):
            value = None  # unassign
        else:
            try:
                value = uuid.UUID(str(value))
            except (ValueError, TypeError):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "value must be a user UUID or null for action=reassign",
                )

    parsed_ids: list[uuid.UUID] = []
    for s in raw_ids:
        try:
            parsed_ids.append(uuid.UUID(str(s)))
        except (ValueError, TypeError):
            continue
    if not parsed_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no valid uuids in ids")

    affected: list[str] = []
    skipped: list[dict] = []
    bulk_assigned: list[
        Incident
    ] = []  # incidents newly assigned to `value`, for one summary notice
    now = datetime.now(timezone.utc)

    for inc_id in parsed_ids:
        inc = await session.get(Incident, inc_id)
        if not inc:
            skipped.append({"id": str(inc_id), "reason": "not_found"})
            continue
        try:
            require_in_scope(inc.tenant_id, scope)
        except HTTPException:
            skipped.append({"id": str(inc_id), "reason": "out_of_scope"})
            continue

        if action == "archive":
            if inc.deleted_at is None:
                inc.deleted_at = now
                session.add(
                    TimelineEvent(
                        incident_id=inc.id,
                        ts=now,
                        actor=user.email,
                        event_type="archived",
                        display="Bulk archive by admin",
                    )
                )
            affected.append(str(inc_id))

        elif action == "purge":
            if inc.deleted_at is None:
                skipped.append({"id": str(inc_id), "reason": "must_archive_first"})
                continue
            case_number = inc.case_number
            try:
                await session.delete(inc)
                await session.flush()
            except Exception as e:
                await session.rollback()
                skipped.append({"id": str(inc_id), "reason": f"fk_restrict: {str(e)[:100]}"})
                continue
            affected.append(case_number)

        elif action == "close":
            inc.status = CaseStatus.CLOSED
            inc.closed_at = inc.closed_at or now
            session.add(
                TimelineEvent(
                    incident_id=inc.id,
                    ts=now,
                    actor=user.email,
                    event_type="closed",
                    display="Bulk close (no verdict)",
                )
            )
            affected.append(str(inc_id))

        elif action == "verdict":
            inc.verdict = value  # type: ignore[assignment]
            inc.closed_at = inc.closed_at or now
            inc.status = CaseStatus.CLOSED
            session.add(
                TimelineEvent(
                    incident_id=inc.id,
                    ts=now,
                    actor=user.email,
                    event_type="verdict_bulk",
                    display=f"Bulk verdict: {value}",
                )
            )
            # Note: we deliberately skip Qdrant indexing in the bulk path —
            # bulk verdict is usually for cleanup, not training data. If you
            # need per-incident Qdrant writes, set verdict from the detail page.
            affected.append(str(inc_id))

        elif action == "reassign":
            prior_assignee = inc.assignee_id
            inc.assignee_id = value  # type: ignore[assignment]
            # First ownership stamps the response-SLA anchor (same as claim/assign);
            # a bulk unassign (value=None) leaves an existing claim intact.
            if value is not None and inc.claimed_at is None:
                inc.claimed_at = now
            label = "unassigned" if value is None else f"reassigned to {value}"
            session.add(
                TimelineEvent(
                    incident_id=inc.id,
                    ts=now,
                    actor=user.email,
                    event_type="reassigned",
                    display=f"Bulk {label}",
                )
            )
            # Collect for one summary notice (skip self and no-op re-assignment).
            if value is not None and value != user.id and prior_assignee != value:
                bulk_assigned.append(inc)
            affected.append(str(inc_id))

    await audit.log(
        session,
        user_id=user.id,
        action=f"incident.bulk.{action}",
        target_type="incident",
        target_id=user.id,  # no single target
        diff={"count": len(affected), "skipped": len(skipped), "ids": affected[:20]},
    )
    if action == "reassign" and value is not None and value != user.id and bulk_assigned:
        # A batch that newly-assigns exactly one incident is really a single
        # assignment: route it through the single helper so the email names the
        # case and the in-app notification links to that incident (not the list).
        if len(bulk_assigned) == 1:
            await _notify_assignment(
                session, arq, inc=bulk_assigned[0], assignee_id=value, actor=user
            )
        else:
            await _notify_bulk_assignment(
                session, arq, incidents=bulk_assigned, assignee_id=value, actor=user
            )
    await session.commit()
    return {"action": action, "affected": affected, "skipped": skipped}


@router.post("/{incident_id}/regenerate-report")
async def regenerate(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    was_short_circuit = bool(inc.short_circuit)
    inc.status = CaseStatus.AWAITING_SYNTHESIS
    # Manual regen always bypasses short-circuit gates — the analyst is
    # the source of authority here, not the gate logic.
    await arq.enqueue_job("pipeline_synthesize_only", str(incident_id), True)

    display = (
        "Deep analysis forced by analyst (bypassing short-circuit)"
        if was_short_circuit
        else "LLM regeneration requested"
    )
    session.add(
        TimelineEvent(
            incident_id=incident_id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type="regen_requested",
            display=display,
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.regenerate",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={
            "case_number": inc.case_number,
            "force_deep": True,
            "bypassed_short_circuit": was_short_circuit,
        },
    )
    return {"status": "queued", "bypassed_short_circuit": was_short_circuit}


# ── Human gate: approve / reject the manager's proposal ─────────────────────
# The persona pipeline parks an incident at AWAITING_SIGNOFF with a proposed
# verdict (+ optional response actions) in enrichment["proposal" / "proposed_actions"].
# Approving commits the verdict (and runs the analyst-checked actions); rejecting
# clears the proposal and either re-runs synthesis or drops to manual review.


class ApproveBody(BaseModel):
    verdict: Verdict | None = None  # override; defaults to the proposed verdict
    approve_action_ids: list[str] = []  # which proposed_actions to execute
    notes: str | None = None


class RejectBody(BaseModel):
    reason: str
    requeue: bool = False  # True → re-run synthesis; False → drop to manual review


_PROPOSED_VERDICT = {
    "tp": Verdict.TP,
    "fp": Verdict.FP,
    "benign": Verdict.BENIGN,
    "inconclusive": Verdict.INCONCLUSIVE,
    "pending": Verdict.PENDING,
}


def _verdict_from_str(s: str | None) -> Verdict:
    return _PROPOSED_VERDICT.get((s or "").lower(), Verdict.PENDING)


async def _commit_verdict(session, inc, verdict, *, reason: str = "", actor=None) -> None:
    """Write the analyst-confirmed verdict: close the incident, mirror to Qdrant,
    feed FP/benign auto-tuning. Shared by PATCH and the approve gate.

    `actor` (the signing analyst) is recorded as the verdict's attribution
    (`approved_by_id` / `signed_off_at`) and on the SLA resolved/closed events —
    the single source of truth for "who closed what, when" (F1)."""
    inc.verdict = verdict
    inc.closed_at = datetime.now(timezone.utc)
    inc.status = CaseStatus.CLOSED
    # F1 — gate attribution: the only place a human commits a verdict.
    if actor is not None:
        inc.approved_by_id = actor.id
        inc.signed_off_at = inc.closed_at
    try:
        qdrant_id = await store_adapter.index_alert(
            # Key the point by the incident id so re-approval upserts in place
            # (idempotent) instead of creating a duplicate memory entry.
            normalized={**(inc.normalized or {}), "alert_id": str(inc.id)},
            verdict=str(verdict),
            verdict_reason=(reason or "")[:4000],
            customer=inc.customer,
        )
        inc.qdrant_alert_id = uuid.UUID(qdrant_id) if _is_uuid(qdrant_id) else None
    except Exception:
        pass
    if verdict in (Verdict.FP, Verdict.BENIGN):
        from ..exclusions import auto_tune

        await auto_tune.record_fp_verdict(session, inc)
    # F1 — SLA lifecycle: case resolved + closed at the gate (best-effort).
    actor_id = actor.id if actor is not None else None
    sla.record_sla_event(session, inc, sla.RESOLVED, actor_id=actor_id)
    sla.record_sla_event(
        session, inc, sla.CLOSED, actor_id=actor_id, meta={"verdict": str(verdict)}
    )
    # Phase 3 — entity risk: a committed verdict is the only event that changes an
    # entity's confirmed history, so refresh risk for the entities this incident
    # links. Best-effort: a risk failure must never break the gate.
    try:
        entity_ids = (
            (
                await session.execute(
                    select(IncidentEntity.entity_id).where(IncidentEntity.incident_id == inc.id)
                )
            )
            .scalars()
            .all()
        )
        if entity_ids:
            await entity_store.recompute_entity_risk(session, list(entity_ids))
    except Exception:
        pass

    # ADR-0005: mirror the committed verdict back to the V1 Workbench alert (fail-soft,
    # flag-gated, V1-customer-guarded). Status reconciliation, not a response action.
    await v1_adapter.mirror_verdict_to_v1(inc, verdict)
    # Same for Microsoft Defender alerts (source microsoft_defender + Graph alert id),
    # fail-soft + flag-gated. Status reconciliation, not a response action.
    await defender_adapter.mirror_verdict_to_defender(inc, verdict)


async def _run_proposed_actions(session, inc, enrichment: dict, approve_ids, user) -> list[dict]:
    """Execute only the analyst-checked proposed response actions via Vision One.
    Updates each action's status in place; best-effort (a V1 failure is recorded,
    not raised). Returns a per-action outcome list for the audit trail."""
    proposed = list(enrichment.get("proposed_actions") or [])
    approve = set(approve_ids or [])
    v1_actions = list(enrichment.get("v1_actions") or [])
    executed: list[dict] = []
    # Resolve per-customer V1 credentials ONCE (DB integration row for this
    # customer, then the 'default' row). Fail closed below if none, so a write
    # never fires against the wrong tenant for an unmapped customer
    # (ADR-0003 #6 / the adversarial correction).
    creds = await integration_store.get_creds("vision_one", inc.customer)
    # Defender creds resolved lazily — only if a Defender-provider action is approved.
    def_creds = None
    def_creds_done = False
    for action in proposed:
        # 'create_case' is a workflow nudge, not a Vision One response action —
        # it's handled in approve_incident (opens a draft customer case). Skip it
        # here so it never hits the V1 dispatch.
        if action.get("kind") == "create_case":
            continue
        if action.get("id") not in approve:
            continue
        kind = action.get("kind")
        provider = action.get("provider") or "vision_one"
        params = action.get("params") or {}
        just = action.get("justification") or ""
        outcome = {"id": action.get("id"), "kind": kind, "provider": provider, "status": "executed"}
        task_id: str | None = None
        log_region: str | None = None
        log_source: str | None = None
        try:
            if provider == "microsoft_defender":
                if not def_creds_done:
                    def_creds = await integration_store.get_creds(
                        "microsoft_defender", inc.customer
                    )
                    def_creds_done = True
                if def_creds is None:
                    raise RuntimeError(
                        f"no Microsoft Defender credentials for customer '{inc.customer or '(none)'}'"
                    )
                log_source = def_creds.source
                _dc = {
                    "tenant_id": def_creds.oauth_tenant_id,
                    "client_id": def_creds.client_id,
                    "client_secret": def_creds.client_secret,
                }
                if kind == "isolate_host":
                    result = await defender_adapter.isolate_machine(
                        params.get("machine_id"), just, **_dc
                    )
                elif kind == "scan_endpoint":
                    result = await defender_adapter.run_av_scan(
                        params.get("machine_id"), just, **_dc
                    )
                elif kind == "blocklist_ioc":
                    result = await defender_adapter.add_indicator(
                        params.get("value"),
                        params.get("indicator_type"),
                        title=just,
                        description=just,
                        **_dc,
                    )
                elif kind == "disable_user":
                    result = await defender_adapter.set_user_enabled(
                        params.get("user_id"), False, **_dc
                    )
                else:
                    raise RuntimeError(f"unsupported Defender action kind: {kind}")
                # Defender returns the created machineAction/indicator; adapter raised on non-2xx.
                task_id = result.get("id")
            else:
                if creds is None:
                    raise RuntimeError(
                        f"no Vision One credentials for customer '{inc.customer or '(none)'}'"
                    )
                log_region, log_source = creds.region, creds.source
                if kind == "blocklist_ioc":
                    result = await v1_adapter.add_to_blocklist(
                        ioc_type=params.get("ioc_type"),
                        value=params.get("value"),
                        description=just,
                        scan_action=params.get("scan_action", "block"),
                        region=creds.region,
                        api_key=creds.api_key,
                    )
                elif kind == "isolate_host":
                    result = await v1_adapter.isolate_endpoint(
                        endpoint_name=params.get("endpoint_name"),
                        description=just,
                        region=creds.region,
                        api_key=creds.api_key,
                    )
                elif kind == "collect_file":
                    result = await v1_adapter.collect_file(
                        endpoint_name=params.get("endpoint_name"),
                        file_path=params.get("file_path", ""),
                        description=just,
                        agent_guid=params.get("agent_guid"),
                        region=creds.region,
                        api_key=creds.api_key,
                    )
                else:
                    raise RuntimeError(f"unknown action kind: {kind}")
                # V1 returns 207 Multi-Status: the batch item can have FAILED even
                # though the HTTP call didn't raise. Inspect the item + grab its task.
                parsed = v1_adapter.parse_response_task(result)
                if not parsed["ok"]:
                    raise RuntimeError(
                        parsed["error"]
                        or f"Vision One rejected the action (item status {parsed['item_status']})"
                    )
                task_id = parsed["task_id"]
            action["status"] = "executed"
            if task_id:
                action["task_id"] = task_id
                outcome["task_id"] = task_id
        except Exception as e:
            action["status"] = "failed"
            outcome["status"] = "failed"
            outcome["error"] = str(e)[:200]
        v1_actions.append(
            {
                "action": kind,
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": user.email,
                "payload": {
                    **params,
                    "proposed": True,
                    "status": action["status"],
                    "task_id": task_id,
                    "error": outcome.get("error"),
                    "provider": provider,
                    "v1_region": log_region,
                    "creds_source": log_source,
                },
            }
        )
        executed.append(outcome)
    enrichment["v1_actions"] = v1_actions
    enrichment["proposed_actions"] = proposed  # statuses mutated in place
    inc.enrichment = enrichment
    return executed


async def _maybe_create_customer_case(
    session, inc, enrichment: dict, approve_ids, user, executed: list[dict]
) -> None:
    """If the gate's 'create_case' nudge is among the approved actions, open a
    draft customer case for this incident — idempotently (one per incident).
    Updates the action's status in place + appends an outcome for the audit."""
    approve = set(approve_ids or [])
    for action in enrichment.get("proposed_actions") or []:
        if action.get("kind") != "create_case":
            continue
        if action.get("id") not in approve:
            action["status"] = "skipped"
            continue
        existing = await session.scalar(
            select(CustomerCase.id).where(CustomerCase.source_incident_id == inc.id).limit(1)
        )
        if existing is not None:
            action["status"] = "exists"
            executed.append({"id": action.get("id"), "kind": "create_case", "status": "exists"})
            continue
        try:
            from .customer_cases import create_case_for_incident

            cc = await create_case_for_incident(session, inc, user, via="gate")
            action["status"] = "executed"
            executed.append(
                {
                    "id": action.get("id"),
                    "kind": "create_case",
                    "status": "executed",
                    "case_number": cc.case_number,
                }
            )
        except Exception as e:  # never block the verdict on the nudge
            action["status"] = "failed"
            executed.append(
                {
                    "id": action.get("id"),
                    "kind": "create_case",
                    "status": "failed",
                    "error": str(e)[:200],
                }
            )


@router.post("/{incident_id}/approve", response_model=IncidentDetail)
async def approve_incident(
    incident_id: uuid.UUID,
    body: ApproveBody,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> IncidentDetail:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    if inc.status != CaseStatus.AWAITING_SIGNOFF:
        raise HTTPException(status.HTTP_409_CONFLICT, "incident is not awaiting sign-off")

    enrichment = dict(inc.enrichment or {})
    proposal = enrichment.get("proposal") or {}
    verdict = body.verdict or _verdict_from_str(proposal.get("proposed_verdict"))
    if verdict in (Verdict.PENDING, None):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no verdict to commit; provide `verdict`")

    if body.notes:
        inc.analyst_notes = body.notes
    executed = await _run_proposed_actions(session, inc, enrichment, body.approve_action_ids, user)
    # 'Create case' nudge: if the analyst kept it checked, open a draft customer
    # case (idempotent — one per incident) so the customer notification isn't
    # forgotten. Internal, no external send.
    await _maybe_create_customer_case(
        session, inc, enrichment, body.approve_action_ids, user, executed
    )
    inc.enrichment = enrichment
    await _commit_verdict(
        session,
        inc,
        verdict,
        reason=(inc.analyst_notes or inc.llm_report_markdown or ""),
        actor=user,
    )

    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type="analyst_approval",
            display=f"Analyst approved → {verdict}"
            + (f"; ran {len(executed)} action(s)" if executed else ""),
            payload={"verdict": str(verdict), "actions": executed},
            level="ok",
            step="synthesis",
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="pipeline.verdict_approved",
        target_type="incident",
        target_id=inc.id,
        tenant_id=inc.tenant_id,
        diff={"case_number": inc.case_number, "verdict": str(verdict), "actions": executed},
    )
    await session.commit()
    return _detail_out(inc)


@router.post("/{incident_id}/reject", response_model=IncidentDetail)
async def reject_incident(
    incident_id: uuid.UUID,
    body: RejectBody,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> IncidentDetail:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    if inc.status != CaseStatus.AWAITING_SIGNOFF:
        raise HTTPException(status.HTTP_409_CONFLICT, "incident is not awaiting sign-off")

    enrichment = dict(inc.enrichment or {})
    enrichment.pop("proposal", None)
    enrichment.pop("proposed_actions", None)
    inc.enrichment = enrichment

    if body.requeue:
        inc.status = CaseStatus.AWAITING_SYNTHESIS
        await arq.enqueue_job("pipeline_synthesize_only", str(incident_id), True)
        disp = f"Analyst rejected proposal — regenerating. Reason: {body.reason}"
    else:
        inc.status = CaseStatus.AWAITING_REVIEW
        disp = f"Analyst rejected proposal — manual review. Reason: {body.reason}"

    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type="analyst_rejection",
            display=disp,
            payload={"reason": body.reason, "requeue": body.requeue},
            level="warn",
            step="synthesis",
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="pipeline.verdict_rejected",
        target_type="incident",
        target_id=inc.id,
        tenant_id=inc.tenant_id,
        diff={"case_number": inc.case_number, "reason": body.reason, "requeue": body.requeue},
    )
    await session.commit()
    return _detail_out(inc)


class ManagerMessageBody(BaseModel):
    message: str


@router.post("/{incident_id}/manager", response_model=IncidentDetail)
async def manager_message(
    incident_id: uuid.UUID,
    body: ManagerMessageBody,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> IncidentDetail:
    """Converse with the Incident Manager at the gate. The manager may revise the
    proposed verdict/actions and re-task the hunter/forensic personas — but never
    commits (the /approve endpoint does). Available only at AWAITING_SIGNOFF."""
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    if inc.status != CaseStatus.AWAITING_SIGNOFF:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "manager chat is only available at the sign-off gate"
        )
    msg = (body.message or "").strip()
    if not msg:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty message")

    from ..pipeline import manager_chat

    await manager_chat.manager_turn(session, inc, msg)
    await audit.log(
        session,
        user_id=user.id,
        action="pipeline.manager_message",
        target_type="incident",
        target_id=inc.id,
        tenant_id=inc.tenant_id,
        diff={"case_number": inc.case_number, "message": msg[:300]},
    )
    await session.commit()
    return _detail_out(inc)


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False


# ── Admin: archive / restore / purge ──────────────────────────────────────────
# Three-step lifecycle:
#   1. archive  → sets deleted_at, incident hidden from default lists
#   2. restore  → clears deleted_at, incident visible again
#   3. purge    → permanently DELETEs the row + cascading children
# Purge requires the incident to be archived first — protects against accidental
# loss. Both archive and purge are admin-only. Restore is also admin-only because
# only admins can see archived incidents in the first place.


@router.post("/{incident_id}/archive")
async def archive_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    if inc.deleted_at is not None:
        return {"status": "already_archived", "id": str(incident_id)}

    inc.deleted_at = datetime.now(timezone.utc)
    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=inc.deleted_at,
            actor=user.email,
            event_type="archived",
            display="Incident archived by admin",
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.archive",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={"case_number": inc.case_number},
    )
    await session.commit()
    return {"status": "archived", "id": str(incident_id)}


@router.post("/{incident_id}/restore")
async def restore_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    if inc.deleted_at is None:
        return {"status": "not_archived", "id": str(incident_id)}

    inc.deleted_at = None
    session.add(
        TimelineEvent(
            incident_id=inc.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type="restored",
            display="Incident restored by admin",
        )
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.restore",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={"case_number": inc.case_number},
    )
    await session.commit()
    return {"status": "restored", "id": str(incident_id)}


@router.delete("/{incident_id}")
async def purge_incident(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    force: bool = Query(
        default=False, description="Bypass the must-be-archived-first guard. Use sparingly."
    ),
) -> dict:
    """Hard delete — row + cascading children (timeline, IOCs, case_incidents)
    are removed. forensics_jobs and llm_calls have their incident_id set NULL
    (preserved for billing/audit). If a CustomerCase references this incident
    as its source, the delete will fail with 409 — promote/detach the case first."""
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)

    if not force and inc.deleted_at is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Incident is not archived. Archive first, or pass ?force=true.",
        )

    case_number = inc.case_number
    tenant_id = inc.tenant_id
    try:
        await session.delete(inc)
        await audit.log(
            session,
            user_id=user.id,
            action="incident.purge",
            target_type="incident",
            target_id=incident_id,
            tenant_id=tenant_id,
            diff={"case_number": case_number, "force": force},
        )
        await session.commit()
    except Exception as e:
        await session.rollback()
        # Most likely: a CustomerCase still references this incident (RESTRICT FK).
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot purge — referenced by another row (likely a customer case): {e}",
        )
    return {"status": "purged", "id": str(incident_id), "case_number": case_number}


# ══════════════════════════════════════════════════════════════════════════
# Incident collaboration (Feature 8 mirror): comments, @mentions, watchers
#
# Comments are append-only; @mentions + watchers drive in-app notifications
# (notify.py / B1) and mention emails (reuses the send_mention_emails worker
# job). Reads are viewer-visible (current_user + scope); writes require an
# analyst. Mirrors routes/customer_cases.py, keyed on incidents.
# ══════════════════════════════════════════════════════════════════════════


async def _incident_in_scope(
    session: AsyncSession, incident_id: uuid.UUID, scope: TenantScope
) -> Incident:
    inc = await session.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    return inc


async def _mentionable_users(session: AsyncSession) -> list[dict]:
    """Active SOC users (the mention/watch roster). Internal staff, so the whole
    active roster is mentionable regardless of tenant."""
    rows = (
        await session.execute(
            select(User.id, User.full_name, User.email)
            .where(User.status == UserStatus.ACTIVE)
            .order_by(User.full_name, User.email)
        )
    ).all()
    return [{"id": str(r.id), "full_name": r.full_name, "email": r.email} for r in rows]


async def _incident_watcher_ids(session: AsyncSession, incident_id: uuid.UUID) -> list[str]:
    rows = (
        (
            await session.execute(
                select(IncidentWatcher.user_id).where(IncidentWatcher.incident_id == incident_id)
            )
        )
        .scalars()
        .all()
    )
    return [str(u) for u in rows]


async def _ensure_incident_watchers(
    session: AsyncSession, incident_id: uuid.UUID, user_ids
) -> None:
    """Idempotently add watchers (dedup against existing rows + the unique key)."""
    existing = set(await _incident_watcher_ids(session, incident_id))
    for raw in user_ids:
        uid = str(raw)
        if uid and uid not in existing:
            existing.add(uid)
            session.add(IncidentWatcher(incident_id=incident_id, user_id=uuid.UUID(uid)))


def _incident_comment_out(c: IncidentComment, full_name: str | None, email: str | None) -> dict:
    return {
        "id": str(c.id),
        "body": c.body,
        "mentions": c.mentions or [],
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "author": {"full_name": full_name, "email": email},
    }


@router.get("/{incident_id}/mentionable-users")
async def incident_mentionable_users(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    await _incident_in_scope(session, incident_id, scope)
    return await _mentionable_users(session)


@router.get("/{incident_id}/comments")
async def list_incident_comments(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    await _incident_in_scope(session, incident_id, scope)
    rows = (
        await session.execute(
            select(IncidentComment, User.full_name, User.email)
            .join(User, User.id == IncidentComment.author_id, isouter=True)
            .where(IncidentComment.incident_id == incident_id)
            .order_by(asc(IncidentComment.created_at))
        )
    ).all()
    return [_incident_comment_out(c, fn, em) for c, fn, em in rows]


@router.post("/{incident_id}/comments", status_code=status.HTTP_201_CREATED)
async def add_incident_comment(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    body: Annotated[str, Body(embed=True)],
) -> dict:
    """Post a comment on an incident. @mentions notify the named users in-app (and
    auto-watch them) AND email each of them; existing watchers get a 'commented'
    in-app notification. The author auto-watches."""
    inc = await _incident_in_scope(session, incident_id, scope)
    body = (body or "").strip()
    if not body:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "comment body is required")

    roster = await _mentionable_users(session)
    mentioned = mentions.parse_mentions(body, roster)
    existing_watchers = await _incident_watcher_ids(session, incident_id)  # before adding new ones

    comment = IncidentComment(
        incident_id=incident_id, author_id=user.id, body=body, mentions=mentioned or None
    )
    session.add(comment)
    await _ensure_incident_watchers(session, incident_id, [str(user.id), *mentioned])

    link = f"/incidents/{incident_id}"
    who = user.full_name or user.email
    preview = body[:140]
    # Mentions are the high-signal notification.
    await notify.notify_users(
        session,
        mentioned,
        kind="mention",
        title=f"{who} mentioned you on {inc.case_number}",
        link=link,
        body=preview,
        actor_id=user.id,
    )
    # Email each mentioned user (best-effort, via the shared send_mention_emails job).
    if mentioned:
        id_to_email = {u["id"]: u["email"] for u in roster if u.get("email")}
        recipients = [id_to_email[m] for m in mentioned if id_to_email.get(m)]
        if recipients:
            public = (settings.isoc_public_url or "").rstrip("/")
            try:
                await arq.enqueue_job(
                    "send_mention_emails",
                    {
                        "to": recipients,
                        "author": who,
                        "case_number": inc.case_number,
                        "url": f"{public}/incidents/{incident_id}" if public else "",
                        "preview": preview,
                        "subject": f"You were mentioned on {inc.case_number}",
                    },
                )
            except Exception:
                pass  # best-effort: never fail the comment on a queue hiccup

    # Existing watchers (not just-mentioned, not the author) get a comment ping.
    watch_only = [w for w in existing_watchers if w not in set(mentioned)]
    await notify.notify_users(
        session,
        watch_only,
        kind="comment",
        title=f"{who} commented on {inc.case_number}",
        link=link,
        body=preview,
        actor_id=user.id,
    )
    await audit.log(
        session,
        user_id=user.id,
        action="incident.comment",
        target_type="incident",
        target_id=incident_id,
        tenant_id=inc.tenant_id,
        diff={"mentions": mentioned, "chars": len(body)},
    )
    await session.flush()
    return _incident_comment_out(comment, user.full_name, user.email)


@router.get("/{incident_id}/watchers")
async def list_incident_watchers(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> list[dict]:
    await _incident_in_scope(session, incident_id, scope)
    rows = (
        await session.execute(
            select(IncidentWatcher.user_id, User.full_name, User.email)
            .join(User, User.id == IncidentWatcher.user_id)
            .where(IncidentWatcher.incident_id == incident_id)
            .order_by(User.full_name, User.email)
        )
    ).all()
    return [{"user_id": str(uid), "full_name": fn, "email": em} for uid, fn, em in rows]


@router.post("/{incident_id}/watchers", status_code=status.HTTP_201_CREATED)
async def add_incident_watcher(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    user_id: Annotated[uuid.UUID | None, Body(embed=True)] = None,
) -> dict:
    """Watch the incident. Defaults to self; pass user_id to add a teammate."""
    await _incident_in_scope(session, incident_id, scope)
    target = user_id or user.id
    if await session.get(User, target) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    await _ensure_incident_watchers(session, incident_id, [str(target)])
    return {"ok": True, "user_id": str(target)}


@router.delete("/{incident_id}/watchers/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_incident_watcher(
    incident_id: uuid.UUID,
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_analyst)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> Response:
    await _incident_in_scope(session, incident_id, scope)
    w = (
        await session.execute(
            select(IncidentWatcher).where(
                IncidentWatcher.incident_id == incident_id,
                IncidentWatcher.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if w is not None:
        await session.delete(w)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
