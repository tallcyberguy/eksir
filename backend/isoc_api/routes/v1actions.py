"""Trend Micro Vision One action routes.

All routes are under /api/v1/v1actions/{incident_id}/...

Read endpoints (enrichment):
  GET  /endpoints          — search V1 for endpoints matching IOCs in this incident
  GET  /endpoints/{id}     — get full endpoint profile

Write endpoints (response — require explicit body with justification):
  POST /blocklist          — add one IOC to the Suspicious Object list
  POST /isolate            — isolate an endpoint
  POST /restore            — restore an isolated endpoint
  POST /collect            — collect a file from an endpoint
  GET  /tasks/{task_id}    — poll a response task status
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters import integration_store, v1_adapter
from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, require_in_scope
from ..db.models import Incident, TimelineEvent, User
from ..db.session import get_session
from ..logging_config import get_logger

logger = get_logger("isoc.v1actions")
router = APIRouter()


# ── helpers ────────────────────────────────────────────────────────────────


async def _get_incident(
    incident_id: uuid.UUID,
    session: AsyncSession,
    scope: TenantScope | None = None,
) -> Incident:
    inc = await session.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    if scope is not None:
        require_in_scope(inc.tenant_id, scope)
    return inc


async def _log_action(
    session: AsyncSession,
    incident: Incident,
    action: str,
    payload: dict,
    user: User,
) -> None:
    session.add(
        TimelineEvent(
            incident_id=incident.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type=f"v1_{action}",
            display=f"V1 action: {action}",
            payload=payload,
        )
    )
    # Also persist to enrichment.v1_actions list
    enrichment = dict(incident.enrichment or {})
    actions: list = list(enrichment.get("v1_actions") or [])
    actions.append(
        {
            "action": action,
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": user.email,
            "payload": payload,
        }
    )
    enrichment["v1_actions"] = actions
    incident.enrichment = enrichment

    # Surface in the audit log too, tagged with the incident's tenant.
    await audit.log(
        session,
        user_id=user.id,
        action=f"v1.{action}",
        target_type="incident",
        target_id=incident.id,
        tenant_id=incident.tenant_id,
        diff={"case_number": incident.case_number, **payload},
    )
    await session.commit()


async def _resolve_creds(inc: Incident):
    """Resolve this incident's customer → Vision One creds (region + key).

    Fail closed (503) when nothing is configured, so an ad-hoc action never fires
    against the wrong/global tenant for an unmapped customer.
    """
    creds = await integration_store.get_creds_v1(
        inc.customer, region_hint=(inc.normalized or {}).get("v1_region")
    )
    if creds is None:
        raise HTTPException(
            503, f"No Vision One credentials for customer '{inc.customer or '(none)'}'"
        )
    return creds


def _require_task(result) -> str | None:
    """Interpret a V1 207 Multi-Status result: raise 502 on a per-item failure,
    else return the response task id (None if the action produced no task)."""
    parsed = v1_adapter.parse_response_task(result)
    if not parsed["ok"]:
        raise HTTPException(
            502,
            parsed["error"]
            or f"Vision One rejected the action (item status {parsed['item_status']})",
        )
    return parsed["task_id"]


# ── Request models ─────────────────────────────────────────────────────────


class BlocklistRequest(BaseModel):
    ioc_type: Literal["ip", "domain", "url", "fileSha1", "fileSha256", "senderMailAddress"]
    value: str
    description: str = ""
    scan_action: Literal["block", "log"] = "block"
    risk_level: Literal["high", "medium", "low"] = "high"


class IsolateRequest(BaseModel):
    endpoint_name: str
    justification: str  # required — must explain why


class RestoreRequest(BaseModel):
    endpoint_name: str
    justification: str


class CollectFileRequest(BaseModel):
    file_path: str
    justification: str
    # Identify the endpoint by agent GUID (preferred / FedRAMP-required) or by
    # hostname. At least one is required — enforced below.
    agent_guid: str | None = None
    endpoint_name: str | None = None

    @model_validator(mode="after")
    def _require_target(self) -> "CollectFileRequest":
        if not (self.agent_guid or self.endpoint_name):
            raise ValueError("provide agent_guid or endpoint_name")
        return self


# ── Routes ─────────────────────────────────────────────────────────────────


@router.get("/{incident_id}/endpoints")
async def search_endpoints(
    incident_id: uuid.UUID,
    q: str = "",
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    """Search V1 for endpoints. q = free-text hostname / IP filter."""
    inc = await _get_incident(incident_id, session, scope)  # 404 guard
    creds = await _resolve_creds(inc)
    try:
        filter_expr = f"endpointName eq '{q}'" if q else ""
        results = await v1_adapter.search_endpoints(
            filter_expr, top=20, region=creds.region, api_key=creds.api_key
        )
        return {"items": results, "query": q}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.get("/{incident_id}/endpoints/{endpoint_id}")
async def get_endpoint(
    incident_id: uuid.UUID,
    endpoint_id: str,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        return await v1_adapter.get_endpoint(
            endpoint_id, region=creds.region, api_key=creds.api_key
        )
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/blocklist")
async def add_to_blocklist(
    incident_id: uuid.UUID,
    body: BlocklistRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await v1_adapter.add_to_blocklist(
            ioc_type=body.ioc_type,
            value=body.value,
            description=body.description or f"ISOC incident {inc.case_number}",
            scan_action=body.scan_action,
            risk_level=body.risk_level,
            region=creds.region,
            api_key=creds.api_key,
        )
        await _log_action(
            session,
            inc,
            "blocklist",
            {
                "ioc_type": body.ioc_type,
                "value": body.value,
                "scan_action": body.scan_action,
                "risk_level": body.risk_level,
                "result": result,
            },
            user=user,
        )
        return {"ok": True, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/isolate")
async def isolate_endpoint(
    incident_id: uuid.UUID,
    body: IsolateRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await v1_adapter.isolate_endpoint(
            body.endpoint_name, body.justification, region=creds.region, api_key=creds.api_key
        )
        task_id = _require_task(result)
        await _log_action(
            session,
            inc,
            "isolate",
            {
                "endpoint_name": body.endpoint_name,
                "justification": body.justification,
                "task_id": task_id,
                "result": result,
            },
            user=user,
        )
        return {"ok": True, "task_id": task_id, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/restore")
async def restore_endpoint(
    incident_id: uuid.UUID,
    body: RestoreRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await v1_adapter.restore_endpoint(
            body.endpoint_name, body.justification, region=creds.region, api_key=creds.api_key
        )
        task_id = _require_task(result)
        await _log_action(
            session,
            inc,
            "restore",
            {
                "endpoint_name": body.endpoint_name,
                "justification": body.justification,
                "task_id": task_id,
                "result": result,
            },
            user=user,
        )
        return {"ok": True, "task_id": task_id, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/collect")
async def collect_file(
    incident_id: uuid.UUID,
    body: CollectFileRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await v1_adapter.collect_file(
            body.endpoint_name,
            body.file_path,
            body.justification,
            agent_guid=body.agent_guid,
            region=creds.region,
            api_key=creds.api_key,
        )
        task_id = _require_task(result)
        await _log_action(
            session,
            inc,
            "collect_file",
            {
                "agent_guid": body.agent_guid,
                "endpoint_name": body.endpoint_name,
                "file_path": body.file_path,
                "justification": body.justification,
                "task_id": task_id,
                "result": result,
            },
            user=user,
        )
        return {"ok": True, "task_id": task_id, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.get("/{incident_id}/tasks/{task_id}")
async def get_task(
    incident_id: uuid.UUID,
    task_id: str,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        return await v1_adapter.get_response_task(
            task_id, region=creds.region, api_key=creds.api_key
        )
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)
