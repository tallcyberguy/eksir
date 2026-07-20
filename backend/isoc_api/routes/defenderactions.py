"""Microsoft Defender response-action routes (analyst-gated containment).

All routes are under /api/defenderactions/{incident_id}/...

Write endpoints (response — require an explicit justification):
  POST /isolate     — isolate a device (DESTRUCTIVE: cuts its network)
  POST /unisolate   — release a device from isolation
  POST /scan        — run an antivirus scan on a device

Mirrors routes/v1actions.py: each action requires an authenticated analyst, tenant-scope
check, a justification, fail-closed Defender credentials (503 when none), and is recorded
to the incident timeline + enrichment.defender_actions + the audit log. These are NEVER
auto-run — the LLM only ever proposes; firing is this explicit analyst request.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters import defender_adapter, integration_store
from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, require_in_scope
from ..db.models import Incident, TimelineEvent, User
from ..db.session import get_session
from ..logging_config import get_logger

logger = get_logger("isoc.defenderactions")
router = APIRouter()


# ── helpers ──────────────────────────────────────────────────────────────────


async def _get_incident(
    incident_id: uuid.UUID, session: AsyncSession, scope: TenantScope | None = None
) -> Incident:
    inc = await session.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    if scope is not None:
        require_in_scope(inc.tenant_id, scope)
    return inc


async def _resolve_creds(inc: Incident):
    """Resolve this incident's customer → Microsoft Defender OAuth creds.

    Fail closed (503) when nothing is configured, so an action never fires against
    the wrong/global tenant for an unmapped customer (mirrors v1actions)."""
    creds = await integration_store.get_creds("microsoft_defender", inc.customer)
    if creds is None:
        raise HTTPException(
            503, f"No Microsoft Defender credentials for customer '{inc.customer or '(none)'}'"
        )
    return creds


async def _log_action(
    session: AsyncSession, incident: Incident, action: str, payload: dict, user: User
) -> None:
    session.add(
        TimelineEvent(
            incident_id=incident.id,
            ts=datetime.now(timezone.utc),
            actor=user.email,
            event_type=f"defender_{action}",
            display=f"Defender action: {action}",
            payload=payload,
        )
    )
    enrichment = dict(incident.enrichment or {})
    actions: list = list(enrichment.get("defender_actions") or [])
    actions.append(
        {
            "action": action,
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": user.email,
            "payload": payload,
        }
    )
    enrichment["defender_actions"] = actions
    incident.enrichment = enrichment
    await audit.log(
        session,
        user_id=user.id,
        action=f"defender.{action}",
        target_type="incident",
        target_id=incident.id,
        tenant_id=incident.tenant_id,
        diff={"case_number": incident.case_number, **payload},
    )
    await session.commit()


# ── request models ───────────────────────────────────────────────────────────


class IsolateRequest(BaseModel):
    machine_id: str
    justification: str  # required — must explain why
    isolation_type: Literal["Full", "Selective"] = "Full"


class UnisolateRequest(BaseModel):
    machine_id: str
    justification: str


class ScanRequest(BaseModel):
    machine_id: str
    justification: str
    scan_type: Literal["Quick", "Full"] = "Quick"


class UpdateAlertRequest(BaseModel):
    alert_id: str
    justification: str
    status: Literal["new", "inProgress", "resolved"] | None = None
    classification: (
        Literal["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"] | None
    ) = None
    determination: str | None = None


class BlocklistRequest(BaseModel):
    indicator_value: str
    indicator_type: Literal["IpAddress", "DomainName", "Url", "FileSha256", "FileSha1"]
    justification: str
    action: Literal["Block", "Alert", "AlertAndBlock", "Audit"] = "Block"
    severity: Literal["Informational", "Low", "Medium", "High"] = "Medium"


class UserActionRequest(BaseModel):
    user_id: str  # Entra object id or userPrincipalName
    justification: str


# ── routes ───────────────────────────────────────────────────────────────────


@router.post("/{incident_id}/isolate")
async def isolate_machine(
    incident_id: uuid.UUID,
    body: IsolateRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await defender_adapter.isolate_machine(
            body.machine_id,
            body.justification,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            isolation_type=body.isolation_type,
        )
        await _log_action(
            session,
            inc,
            "isolate",
            {
                "machine_id": body.machine_id,
                "justification": body.justification,
                "isolation_type": body.isolation_type,
                "result": result,
            },
            user=user,
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/unisolate")
async def unisolate_machine(
    incident_id: uuid.UUID,
    body: UnisolateRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await defender_adapter.unisolate_machine(
            body.machine_id,
            body.justification,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        await _log_action(
            session,
            inc,
            "unisolate",
            {"machine_id": body.machine_id, "justification": body.justification, "result": result},
            user=user,
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/blocklist")
async def blocklist(
    incident_id: uuid.UUID,
    body: BlocklistRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    """Create a Defender custom indicator (blocklist entry) — Ti.ReadWrite."""
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await defender_adapter.add_indicator(
            body.indicator_value,
            body.indicator_type,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            action=body.action,
            title=body.justification,
            severity=body.severity,
            description=body.justification,
        )
        await _log_action(
            session,
            inc,
            "blocklist",
            {
                "indicator_value": body.indicator_value,
                "indicator_type": body.indicator_type,
                "action": body.action,
                "justification": body.justification,
            },
            user=user,
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


async def _set_user_enabled(incident_id, body, session, user, scope, *, enabled: bool, action: str):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await defender_adapter.set_user_enabled(
            body.user_id,
            enabled,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        await _log_action(
            session,
            inc,
            action,
            {"user_id": body.user_id, "justification": body.justification},
            user=user,
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/disable-user")
async def disable_user(
    incident_id: uuid.UUID,
    body: UserActionRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    """Disable an Entra user account (identity containment) — User.EnableDisableAccount.All."""
    return await _set_user_enabled(
        incident_id, body, session, user, scope, enabled=False, action="disable_user"
    )


@router.post("/{incident_id}/enable-user")
async def enable_user(
    incident_id: uuid.UUID,
    body: UserActionRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    """Re-enable a previously disabled Entra user account."""
    return await _set_user_enabled(
        incident_id, body, session, user, scope, enabled=True, action="enable_user"
    )


@router.post("/{incident_id}/update-alert")
async def update_alert(
    incident_id: uuid.UUID,
    body: UpdateAlertRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    """Write an analyst decision back to the Defender alert (status/classification/determination)."""
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await defender_adapter.update_alert(
            body.alert_id,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            status=body.status,
            classification=body.classification,
            determination=body.determination,
        )
        await _log_action(
            session,
            inc,
            "update_alert",
            {
                "alert_id": body.alert_id,
                "justification": body.justification,
                "status": body.status,
                "classification": body.classification,
                "determination": body.determination,
            },
            user=user,
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/{incident_id}/scan")
async def scan_machine(
    incident_id: uuid.UUID,
    body: ScanRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(current_user),
    scope: TenantScope = Depends(current_tenant_scope),
):
    inc = await _get_incident(incident_id, session, scope)
    creds = await _resolve_creds(inc)
    try:
        result = await defender_adapter.run_av_scan(
            body.machine_id,
            body.justification,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            scan_type=body.scan_type,
        )
        await _log_action(
            session,
            inc,
            "scan",
            {
                "machine_id": body.machine_id,
                "justification": body.justification,
                "scan_type": body.scan_type,
                "result": result,
            },
            user=user,
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)
