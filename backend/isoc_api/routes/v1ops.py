"""Vision One operations — case-independent.

Same V1 actions as v1actions.py but without an incident_id. Used by the
global Response → Actions page where analysts run ad-hoc operations.
All writes are logged to audit_log instead of an incident timeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters import integration_store, v1_adapter
from ..auth.deps import current_user
from ..auth.permissions import require_permission
from ..db.models import AuditLog, User
from ..db.session import get_session
from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.v1ops")
router = APIRouter()


# ── helpers ────────────────────────────────────────────────────────────────


async def _audit(
    session: AsyncSession,
    user: User,
    action: str,
    target_type: str,
    target_value: str,
    diff: dict | None = None,
) -> None:
    session.add(
        AuditLog(
            user_id=user.id,
            action=f"v1_{action}",
            target_type=target_type,
            target_id=None,
            diff={"target": target_value, **(diff or {})},
            ts=datetime.now(timezone.utc),
        )
    )
    await session.commit()


async def _resolve(customer: str | None):
    """Resolve the picked customer/tenant → Vision One creds (region + key).

    Fail closed (503) when nothing is configured. ``customer`` None/'default' resolves
    the global 'default' Integration row (when not in strict-tenant mode)."""
    creds = await integration_store.get_creds("vision_one", customer)
    if creds is None:
        raise HTTPException(503, f"No Vision One credentials for tenant '{customer or 'default'}'")
    return creds


# ── Request models ─────────────────────────────────────────────────────────


class BlocklistRequest(BaseModel):
    customer: str | None = None
    ioc_type: Literal["ip", "domain", "url", "fileSha1", "fileSha256", "senderMailAddress"]
    value: str
    description: str = ""
    scan_action: Literal["block", "log"] = "block"
    risk_level: Literal["high", "medium", "low"] = "high"


class EndpointActionRequest(BaseModel):
    customer: str | None = None
    endpoint_name: str
    justification: str


class CollectFileRequest(BaseModel):
    customer: str | None = None
    file_path: str
    justification: str
    # Identify the endpoint by agent GUID (preferred / FedRAMP-required) or hostname.
    agent_guid: str | None = None
    endpoint_name: str | None = None

    @model_validator(mode="after")
    def _require_target(self) -> "CollectFileRequest":
        if not (self.agent_guid or self.endpoint_name):
            raise ValueError("provide agent_guid or endpoint_name")
        return self


# ── Status / config ────────────────────────────────────────────────────────


@router.get("/status")
async def status(_user: User = Depends(current_user)) -> dict:
    """Config check + the tenants an analyst may act against."""
    tenants = await integration_store.list_identifiers(integration_store.V1_PROVIDER)
    # Offer the global env key as a selectable "default" tenant when configured.
    if v1_adapter.is_configured() and not any(t["identifier"] == "default" for t in tenants):
        tenants.append(
            {"identifier": "default", "label": "Global (env key)", "region": settings.v1_region}
        )
    return {
        "configured": bool(tenants),
        "region": settings.v1_region,
        "tenants": tenants,
    }


# ── Endpoints ──────────────────────────────────────────────────────────────


@router.get("/endpoints")
async def search_endpoints(
    q: str = "",
    customer: str | None = None,
    _user: User = Depends(current_user),
):
    creds = await _resolve(customer)
    try:
        filter_expr = f"endpointName eq '{q}'" if q else ""
        results = await v1_adapter.search_endpoints(
            filter_expr, top=20, region=creds.region, api_key=creds.api_key
        )
        return {"items": results, "query": q}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.get("/endpoints/{endpoint_id}")
async def get_endpoint(
    endpoint_id: str,
    customer: str | None = None,
    _user: User = Depends(current_user),
):
    creds = await _resolve(customer)
    try:
        return await v1_adapter.get_endpoint(
            endpoint_id, region=creds.region, api_key=creds.api_key
        )
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


# ── Block List ─────────────────────────────────────────────────────────────


@router.post("/blocklist")
async def add_to_blocklist(
    body: BlocklistRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_permission("actions:blocklist")),
):
    creds = await _resolve(body.customer)
    try:
        result = await v1_adapter.add_to_blocklist(
            ioc_type=body.ioc_type,
            value=body.value,
            description=body.description or f"Ad-hoc block from {user.email}",
            scan_action=body.scan_action,
            risk_level=body.risk_level,
            region=creds.region,
            api_key=creds.api_key,
        )
        await _audit(
            session,
            user,
            "blocklist",
            body.ioc_type,
            body.value,
            {
                "scan_action": body.scan_action,
                "risk_level": body.risk_level,
                "description": body.description,
            },
        )
        return {"ok": True, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


# ── Response actions ───────────────────────────────────────────────────────


@router.post("/isolate")
async def isolate_endpoint(
    body: EndpointActionRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_permission("actions:isolate")),
):
    creds = await _resolve(body.customer)
    try:
        result = await v1_adapter.isolate_endpoint(
            body.endpoint_name, body.justification, region=creds.region, api_key=creds.api_key
        )
        await _audit(
            session,
            user,
            "isolate",
            "endpoint",
            body.endpoint_name,
            {
                "justification": body.justification,
            },
        )
        return {"ok": True, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/restore")
async def restore_endpoint(
    body: EndpointActionRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_permission("actions:isolate")),
):
    creds = await _resolve(body.customer)
    try:
        result = await v1_adapter.restore_endpoint(
            body.endpoint_name, body.justification, region=creds.region, api_key=creds.api_key
        )
        await _audit(
            session,
            user,
            "restore",
            "endpoint",
            body.endpoint_name,
            {
                "justification": body.justification,
            },
        )
        return {"ok": True, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/collect")
async def collect_file(
    body: CollectFileRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_permission("actions:collect")),
):
    creds = await _resolve(body.customer)
    try:
        result = await v1_adapter.collect_file(
            body.endpoint_name,
            body.file_path,
            body.justification,
            agent_guid=body.agent_guid,
            region=creds.region,
            api_key=creds.api_key,
        )
        await _audit(
            session,
            user,
            "collect_file",
            "endpoint",
            body.agent_guid or body.endpoint_name,
            {
                "agent_guid": body.agent_guid,
                "endpoint_name": body.endpoint_name,
                "file_path": body.file_path,
                "justification": body.justification,
            },
        )
        return {"ok": True, "result": result}
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


# ── Task status ────────────────────────────────────────────────────────────


@router.get("/tasks/{task_id}")
async def get_task(
    task_id: str,
    customer: str | None = None,
    _user: User = Depends(current_user),
):
    creds = await _resolve(customer)
    try:
        return await v1_adapter.get_response_task(
            task_id, region=creds.region, api_key=creds.api_key
        )
    except v1_adapter.VisionOneError as e:
        raise HTTPException(e.status or 502, e.message)


# ── Recent action history (audit log) ──────────────────────────────────────


@router.get("/history")
async def recent_history(
    limit: int = 25,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
):
    """Recent V1 actions across all users — pulls from audit_log."""
    from sqlalchemy import desc, select

    rows = (
        (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.action.like("v1_%"))
                .order_by(desc(AuditLog.ts))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "action": r.action.removeprefix("v1_"),
            "target_type": r.target_type,
            "target": (r.diff or {}).get("target"),
            "ts": r.ts.isoformat() if r.ts else None,
            "user_id": str(r.user_id) if r.user_id else None,
            "diff": r.diff,
        }
        for r in rows
    ]
