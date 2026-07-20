"""Microsoft Defender operations — case-independent (global Actions page).

The same Defender response actions as routes/defenderactions.py but WITHOUT an
incident_id: the analyst picks the tenant/customer explicitly and the action
resolves that customer's per-tenant OAuth credentials (fail-closed 503 when none
are configured). All writes are logged to audit_log (`defender_<action>`) instead
of an incident timeline. Mirrors routes/v1ops.py.

Read:
  GET  /status                  — configured? + selectable tenants
  GET  /machines?customer=&q=   — hostname → machine_id lookup (advanced hunting)
  GET  /history                 — recent Defender ad-hoc actions (audit_log)

Write (each requires a customer + a justification):
  POST /isolate | /unisolate    — device network containment
  POST /scan                    — antivirus scan
  POST /blocklist               — custom indicator (IOC add)
  POST /disable-user | /enable-user — Entra identity containment

These NEVER auto-run: the LLM only ever proposes; firing is this explicit analyst
request, exactly as on the incident gate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters import defender_adapter, integration_store
from ..auth.deps import current_user
from ..db.models import AuditLog, User
from ..db.session import get_session
from ..logging_config import get_logger

logger = get_logger("isoc.defenderops")
router = APIRouter()

PROVIDER = "microsoft_defender"


# ── helpers ────────────────────────────────────────────────────────────────


async def _resolve(customer: str):
    """Resolve the picked customer/tenant → Microsoft Defender OAuth creds.

    Fail closed (503) when nothing usable is configured, so an ad-hoc action never
    fires against the wrong tenant (mirrors defenderactions._resolve_creds)."""
    creds = await integration_store.get_creds(PROVIDER, customer)
    if creds is None or not (creds.client_id and creds.client_secret):
        raise HTTPException(503, f"No Microsoft Defender credentials for tenant '{customer}'")
    return creds


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
            action=f"defender_{action}",
            target_type=target_type,
            target_id=None,
            diff={"target": target_value, **(diff or {})},
            ts=datetime.now(timezone.utc),
        )
    )
    await session.commit()


def _sanitize_kql(q: str) -> str:
    """Strip quote/backslash so a hostname filter can't break out of the KQL string."""
    return q.replace("\\", "").replace('"', "").strip()[:120]


# ── request models ───────────────────────────────────────────────────────────


class IsolateRequest(BaseModel):
    customer: str
    machine_id: str
    justification: str
    isolation_type: Literal["Full", "Selective"] = "Full"


class UnisolateRequest(BaseModel):
    customer: str
    machine_id: str
    justification: str


class ScanRequest(BaseModel):
    customer: str
    machine_id: str
    justification: str
    scan_type: Literal["Quick", "Full"] = "Quick"


class BlocklistRequest(BaseModel):
    customer: str
    indicator_value: str
    indicator_type: Literal["IpAddress", "DomainName", "Url", "FileSha256", "FileSha1"]
    justification: str
    action: Literal["Block", "Alert", "AlertAndBlock", "Audit"] = "Block"
    severity: Literal["Informational", "Low", "Medium", "High"] = "Medium"


class UserActionRequest(BaseModel):
    customer: str
    user_id: str  # Entra object id or userPrincipalName
    justification: str


# ── status / lookup ────────────────────────────────────────────────────────


@router.get("/status")
async def status(_user: User = Depends(current_user)) -> dict:
    """Config check + the tenants an analyst may act against (enabled Defender rows)."""
    tenants = await integration_store.list_identifiers(PROVIDER)
    return {"configured": bool(tenants), "tenants": tenants}


@router.get("/machines")
async def search_machines(
    customer: str,
    q: str = "",
    _user: User = Depends(current_user),
):
    """Hostname → machine_id lookup via advanced hunting (read-only)."""
    creds = await _resolve(customer)
    term = _sanitize_kql(q)
    where = f'| where DeviceName contains "{term}" ' if term else ""
    kql = (
        "DeviceInfo "
        f"{where}"
        "| summarize arg_max(Timestamp, OSPlatform, PublicIP, HealthStatus) by DeviceId, DeviceName "
        "| top 20 by Timestamp desc"
    )
    try:
        rows = await defender_adapter.run_hunting_query(
            kql,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            max_records=20,
        )
        return {"items": rows, "query": term}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


# ── device response ────────────────────────────────────────────────────────


@router.post("/isolate")
async def isolate(
    body: IsolateRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    creds = await _resolve(body.customer)
    try:
        result = await defender_adapter.isolate_machine(
            body.machine_id,
            body.justification,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            isolation_type=body.isolation_type,
        )
        await _audit(
            session,
            user,
            "isolate",
            "machine",
            body.machine_id,
            {
                "customer": body.customer,
                "justification": body.justification,
                "isolation_type": body.isolation_type,
            },
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/unisolate")
async def unisolate(
    body: UnisolateRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    creds = await _resolve(body.customer)
    try:
        result = await defender_adapter.unisolate_machine(
            body.machine_id,
            body.justification,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        await _audit(
            session,
            user,
            "unisolate",
            "machine",
            body.machine_id,
            {"customer": body.customer, "justification": body.justification},
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/scan")
async def scan(
    body: ScanRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    creds = await _resolve(body.customer)
    try:
        result = await defender_adapter.run_av_scan(
            body.machine_id,
            body.justification,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            scan_type=body.scan_type,
        )
        await _audit(
            session,
            user,
            "scan",
            "machine",
            body.machine_id,
            {
                "customer": body.customer,
                "justification": body.justification,
                "scan_type": body.scan_type,
            },
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


# ── blocklist (IOC add) ────────────────────────────────────────────────────


@router.post("/blocklist")
async def blocklist(
    body: BlocklistRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Create a Defender custom indicator (blocklist entry) — Ti.ReadWrite."""
    creds = await _resolve(body.customer)
    try:
        result = await defender_adapter.add_indicator(
            body.indicator_value,
            body.indicator_type,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            action=body.action,
            title=body.justification or f"Ad-hoc block from {user.email}",
            severity=body.severity,
            description=body.justification or f"Ad-hoc block from {user.email}",
        )
        await _audit(
            session,
            user,
            "blocklist",
            body.indicator_type,
            body.indicator_value,
            {
                "customer": body.customer,
                "action": body.action,
                "severity": body.severity,
                "justification": body.justification,
            },
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


# ── identity containment ───────────────────────────────────────────────────


async def _set_user_enabled(body, session, user, *, enabled: bool, action: str):
    creds = await _resolve(body.customer)
    try:
        result = await defender_adapter.set_user_enabled(
            body.user_id,
            enabled,
            tenant_id=creds.oauth_tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        await _audit(
            session,
            user,
            action,
            "user",
            body.user_id,
            {"customer": body.customer, "justification": body.justification},
        )
        return {"ok": True, "result": result}
    except defender_adapter.DefenderError as e:
        raise HTTPException(e.status or 502, e.message)


@router.post("/disable-user")
async def disable_user(
    body: UserActionRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Disable an Entra user account (identity containment)."""
    return await _set_user_enabled(body, session, user, enabled=False, action="disable_user")


@router.post("/enable-user")
async def enable_user(
    body: UserActionRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Re-enable a previously disabled Entra user account."""
    return await _set_user_enabled(body, session, user, enabled=True, action="enable_user")


# ── recent action history (audit log) ──────────────────────────────────────


@router.get("/history")
async def recent_history(
    limit: int = 25,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
):
    """Recent Defender actions across all users — pulls from audit_log."""
    from sqlalchemy import desc, select

    rows = (
        (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.action.like("defender\\_%", escape="\\"))
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
            "action": r.action.removeprefix("defender_"),
            "target_type": r.target_type,
            "target": (r.diff or {}).get("target"),
            "ts": r.ts.isoformat() if r.ts else None,
            "user_id": str(r.user_id) if r.user_id else None,
            "diff": r.diff,
        }
        for r in rows
    ]
