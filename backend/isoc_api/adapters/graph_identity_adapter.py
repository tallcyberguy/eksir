"""Microsoft Graph identity reads (ADR-0009 PR-3).

Tenant-keyed user enrichment for ANY incident that names a user principal
(CrowdStrike / Vision One / email, not just Defender). The OAuth app that
authenticates the Microsoft Defender integration is the SAME Azure AD app
registration that holds the Graph identity scopes, so we reuse its
client-credentials (``defender_adapter._token`` returns a Graph token by default).

ALL reads here are GET / read-only. This module deliberately does NOT import or
expose ``set_user_enabled`` (the identity WRITE lives in ``defender_adapter`` and
stays analyst-gated), so a prompt-injected model can never reach a user write via
this enrichment path.

Field names + endpoints verified against the official Microsoft Graph v1.0 docs
(learn.microsoft.com/graph, 2026-07). Note: v1.0 ``auditLogs/signIns`` returns
INTERACTIVE sign-ins only; ``riskyUsers`` needs Entra ID P2, ``riskDetections``
P1/P2, ``userRegistrationDetails`` + sign-ins ``AuditLog.Read.All``.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..logging_config import get_logger
from .defender_adapter import DefenderError, _token

logger = get_logger("isoc.graph_identity")

_GRAPH = "https://graph.microsoft.com/v1.0"

# accountEnabled / department / jobTitle / userType / onPremisesSecurityIdentifier /
# city / country are NON-default on GET /users and are omitted unless $select'd.
# onPremisesSecurityIdentifier is the on-prem Windows SID (S-1-5-...).
_USER_SELECT = (
    "id,displayName,userPrincipalName,accountEnabled,department,jobTitle,mail,"
    "officeLocation,userType,onPremisesSecurityIdentifier,city,country"
)
# The bare /users/{id}/manager nav is app-only UNSUPPORTED; $expand on the user GET works.
_MANAGER_EXPAND = "manager($select=id,displayName,mail,userPrincipalName)"


async def _graph_get(
    path: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """Authenticated GET against Microsoft Graph v1.0. Non-2xx raises DefenderError."""
    token = await _token(tenant_id, client_id, client_secret)  # Graph .default (default scope)
    h = {"Authorization": f"Bearer {token}"}
    if headers:
        h.update(headers)
    async with httpx.AsyncClient(headers=h, timeout=30.0) as c:
        resp = await c.get(f"{_GRAPH}/{path}", params=params)
    if not resp.is_success:
        raise DefenderError(resp.status_code, resp.text[:300])
    return resp.json() or {}


async def get_user_profile(
    user: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Profile (incl. accountEnabled/department/jobTitle/SID) + the immediate manager
    via $expand. `user` may be an object id or a userPrincipalName. Returns the user
    object; `id` is the object GUID the other reads below key on. User.Read.All."""
    return await _graph_get(
        f"users/{user}",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        params={"$select": _USER_SELECT, "$expand": _MANAGER_EXPAND},
        headers={"ConsistencyLevel": "eventual"},
    )


async def get_risky_user(
    user_id: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Identity Protection risky-user STATE (riskLevel/riskState/riskDetail).
    `user_id` is the object GUID. IdentityRiskyUser.Read.All (Entra ID P2)."""
    return await _graph_get(
        f"identityProtection/riskyUsers/{user_id}",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def get_risk_detections(
    user_id: str, *, tenant_id: str | None, client_id: Any, client_secret: Any, top: int = 10
) -> dict:
    """WHY the user is risky (riskEventType: unfamiliarFeatures / leakedCredentials /
    unlikelyTravel / ...). Returns {"detections": [...]}. IdentityRiskEvent.Read.All."""
    body = await _graph_get(
        "identityProtection/riskDetections",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        params={"$filter": f"userId eq '{user_id}'", "$top": top},
    )
    return {"detections": body.get("value") or []}


async def get_registration_details(
    user_id: str, *, tenant_id: str | None, client_id: Any, client_secret: Any
) -> dict:
    """Auth-method REGISTRATION report: methodsRegistered[] (its length is the "N MFA
    factors" signal), isMfaCapable, isAdmin. AuditLog.Read.All."""
    return await _graph_get(
        f"reports/authenticationMethods/userRegistrationDetails/{user_id}",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


async def get_sign_ins(
    user_id: str,
    *,
    tenant_id: str | None,
    client_id: Any,
    client_secret: Any,
    start: str | None = None,
    top: int = 5,
) -> dict:
    """The last `top` INTERACTIVE sign-ins for the user (location/IP/status), newest
    first. Optionally bounded by `start` (RFC3339). Returns {"sign_ins": [...]}.
    AuditLog.Read.All. v1.0 is interactive-only (non-interactive needs /beta)."""
    flt = f"userId eq '{user_id}'"
    if start:
        flt += f" and createdDateTime ge {start}"
    body = await _graph_get(
        "auditLogs/signIns",
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        params={"$filter": flt, "$top": top},
    )
    return {"sign_ins": body.get("value") or []}
