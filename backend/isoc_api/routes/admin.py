"""Admin — users, webhook sources, auto-close rules, LLM settings. Admin-only."""

from __future__ import annotations

import secrets
import uuid
from typing import Annotated

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters.connectors import registry as _connector_registry
from ..auth.deps import require_admin
from ..auth.security import hash_password
from ..auth.tenancy import slugify
from ..db.enums import Role, TenantTier, UserStatus
from ..db.models import (
    AutoCloseRule,
    Incident,
    Integration,
    LLMConfig,
    Tenant,
    User,
    UserTenantMembership,
    WebhookSource,
)
from ..db.session import get_session
from ..llm.config_store import (
    decrypt_secret,
    encrypt_secret,
    invalidate_cache,
    mask_key,
)
from ..logging_config import get_logger
from ..queue import get_arq
from ..schemas import (
    AdminResetPasswordResult,
    UserCreate,
    UserCreateResult,
    UserOut,
    UserUpdate,
)
from ..security import url_safety
from ..settings import settings

logger = get_logger("isoc.admin")
router = APIRouter()


def _login_url() -> str:
    return f"{settings.isoc_public_url.rstrip('/')}/login"


async def _enqueue_credentials_email(
    arq: ArqRedis, user: User, temp_password: str, *, kind: str
) -> None:
    """Hand the credentials email to the worker. Best-effort: a mail/queue hiccup
    must never fail user creation or reset (the temp password is also returned once
    in the API response, so onboarding does not depend on email delivery)."""
    try:
        await arq.enqueue_job(
            "send_credentials_email",
            {
                "email": user.email,
                "full_name": user.full_name or "",
                "temp_password": temp_password,
                "login_url": _login_url(),
                "kind": kind,
            },
        )
    except Exception as e:  # pragma: no cover - enqueue failure is non-fatal
        logger.warning("credentials_email.enqueue_failed", error=str(e))


async def _guard_console_url(url: str | None) -> None:
    """SSRF guard for a connector/EDR console base_url (must be a public host)."""
    if not url:
        return
    try:
        await url_safety.assert_public_url(url)
    except url_safety.UrlSafetyError as e:
        raise HTTPException(400, f"base_url rejected (SSRF guard): {e}") from e


async def _guard_endpoint_url(url: str | None) -> None:
    """SSRF guard for an LLM endpoint (may be internal LiteLLM; blocks metadata)."""
    if not url:
        return
    try:
        await url_safety.assert_endpoint_url(url)
    except url_safety.UrlSafetyError as e:
        raise HTTPException(400, f"endpoint_url rejected (SSRF guard): {e}") from e


# ── Users ───────────────────────────────────────────────────────────────
@router.get("/users", response_model=list[UserOut])
async def list_users(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[UserOut]:
    rows = (await session.scalars(select(User))).all()
    return [UserOut.model_validate(r) for r in rows]


@router.post("/users", response_model=UserCreateResult, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
) -> UserCreateResult:
    if await session.scalar(select(User).where(User.email == body.email.lower())):
        raise HTTPException(status.HTTP_409_CONFLICT, "email exists")
    # When the admin doesn't set a password, generate a temporary one. Only a
    # generated password is echoed back (an admin-chosen one they already know).
    generated = body.password is None
    pw = body.password or secrets.token_urlsafe(12)
    user = User(
        email=body.email.lower(),
        password_hash=hash_password(pw),
        role=body.role,
        full_name=body.full_name,
    )
    session.add(user)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="user.create",
        target_type="user",
        target_id=user.id,
        diff={"email": user.email, "role": str(user.role)},
    )
    await _enqueue_credentials_email(arq, user, pw, kind="invite")
    return UserCreateResult(
        **UserOut.model_validate(user).model_dump(),
        temp_password=pw if generated else None,
    )


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> UserOut:
    """Edit a user's global role, status (enable/disable), or display name.

    Authorization is DB-authoritative (`current_user` re-reads the User on every
    request and disabled users are rejected there), so a role change or a disable
    takes effect on the target's very next request, so no token_version bump is needed.
    """
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    # Self-lockout guards: an admin may not strip their own admin role or disable
    # their own account, since either would revoke the session making the change.
    if user.id == admin.id:
        if body.role is not None and body.role != Role.ADMIN:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot remove your own admin role")
        if body.status is not None and body.status != UserStatus.ACTIVE:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot disable your own account")

    changes: dict = {}
    if body.full_name is not None and body.full_name != user.full_name:
        changes["full_name"] = body.full_name
        user.full_name = body.full_name
    if body.role is not None and body.role != user.role:
        changes["role"] = {"from": str(user.role), "to": str(body.role)}
        user.role = body.role
    if body.status is not None and body.status != user.status:
        changes["status"] = {"from": str(user.status), "to": str(body.status)}
        user.status = body.status

    if changes:
        await audit.log(
            session,
            user_id=admin.id,
            action="user.update",
            target_type="user",
            target_id=user.id,
            diff=changes,
        )
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/reset-password", response_model=AdminResetPasswordResult)
async def reset_password(
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
) -> AdminResetPasswordResult:
    """Set a fresh temporary password, revoke all outstanding sessions, and email
    it to the user. The temp password is also returned once so the admin can relay
    it when email delivery is not configured."""
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    pw = secrets.token_urlsafe(12)
    user.password_hash = hash_password(pw)
    user.token_version += 1  # a reset must end every active session
    await audit.log(
        session,
        user_id=admin.id,
        action="user.reset_password",
        target_type="user",
        target_id=user.id,
        diff={"email": user.email},
    )
    await _enqueue_credentials_email(arq, user, pw, kind="reset")
    return AdminResetPasswordResult(temp_password=pw)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # Prevent self-deletion (an admin removing their own account mid-session).
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete your own account")
    await audit.log(
        session,
        user_id=admin.id,
        action="user.delete",
        target_type="user",
        target_id=user.id,
        diff={"email": user.email},
    )
    await session.delete(user)


# ── User ↔ tenant memberships (user-centric, for the admin Users page) ──────
# Tenant scope is what lets a non-admin analyst SEE customers/incidents: with no
# membership, resolve_tenant_scope yields an empty scope ("sees nothing"). These
# endpoints let an admin grant a user access to specific tenants from the Users
# page (the tenant-centric /tenants/{id}/members endpoints still exist too).
@router.get("/users/{user_id}/tenants")
async def list_user_tenants(
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[dict]:
    if await session.get(User, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    rows = (
        await session.execute(
            select(
                UserTenantMembership.id,
                UserTenantMembership.tenant_id,
                UserTenantMembership.role,
                Tenant.name,
                Tenant.tier,
            )
            .join(Tenant, Tenant.id == UserTenantMembership.tenant_id)
            .where(UserTenantMembership.user_id == user_id)
            .order_by(Tenant.tier, Tenant.name)
        )
    ).all()
    return [
        {
            "membership_id": str(mid),
            "tenant_id": str(tid),
            "role": str(role),
            "tenant_name": name,
            "tenant_tier": str(tier),
        }
        for mid, tid, role, name, tier in rows
    ]


class UserTenantIn(BaseModel):
    tenant_id: uuid.UUID
    role: Role = Role.ANALYST


@router.post("/users/{user_id}/tenants", status_code=status.HTTP_201_CREATED)
async def add_user_tenant(
    user_id: uuid.UUID,
    body: UserTenantIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    if await session.get(User, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    t = await session.get(Tenant, body.tenant_id)
    if t is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    existing = await session.scalar(
        select(UserTenantMembership.id).where(
            UserTenantMembership.user_id == user_id,
            UserTenantMembership.tenant_id == body.tenant_id,
        )
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "user is already a member of this tenant")
    m = UserTenantMembership(user_id=user_id, tenant_id=body.tenant_id, role=body.role)
    session.add(m)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="membership.create",
        target_type="membership",
        target_id=m.id,
        tenant_id=t.id,
        diff={"user_id": str(user_id), "tenant_name": t.name, "role": str(body.role)},
    )
    return {
        "membership_id": str(m.id),
        "tenant_id": str(t.id),
        "tenant_name": t.name,
        "role": str(body.role),
    }


@router.delete("/users/{user_id}/tenants/{tenant_id}", status_code=204)
async def remove_user_tenant(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    m = await session.scalar(
        select(UserTenantMembership).where(
            UserTenantMembership.user_id == user_id,
            UserTenantMembership.tenant_id == tenant_id,
        )
    )
    if m is not None:
        await audit.log(
            session,
            user_id=admin.id,
            action="membership.remove",
            target_type="membership",
            target_id=m.id,
            tenant_id=tenant_id,
            diff={"user_id": str(user_id)},
        )
        await session.delete(m)


# ── Webhook sources ─────────────────────────────────────────────────────
@router.get("/webhook-sources")
async def list_webhook_sources(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[dict]:
    rows = (await session.scalars(select(WebhookSource))).all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "customer_default": r.customer_default,
            "source_product": r.source_product,
            "enabled": r.enabled,
            "ip_allowlist": [str(x) for x in (r.ip_allowlist or [])],
            "last_seen_at": r.last_seen_at,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.post("/webhook-sources", status_code=status.HTTP_201_CREATED)
async def create_webhook_source(
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Returns the HMAC secret ONCE; it can't be retrieved later."""
    secret = secrets.token_urlsafe(48)
    src = WebhookSource(
        name=body["name"],
        hmac_secret_hash=secret,  # see note in webhooks.py — this column stores the raw HMAC secret
        customer_default=body.get("customer_default"),
        source_product=body.get("source_product"),
        ip_allowlist=body.get("ip_allowlist"),
        enabled=True,
    )
    session.add(src)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="webhook.create",
        target_type="webhook_source",
        target_id=src.id,
        diff={
            "name": src.name,
            "source_product": src.source_product,
            "customer_default": src.customer_default,
        },
    )
    return {
        "id": str(src.id),
        "name": src.name,
        "hmac_secret_shown_once": secret,
    }


@router.patch("/webhook-sources/{source_id}")
async def patch_webhook_source(
    source_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Allowed updates: enabled, customer_default, source_product, ip_allowlist."""
    src = await session.get(WebhookSource, source_id)
    if not src:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook source not found")
    changes: dict = {}
    for k in ("enabled", "customer_default", "source_product", "ip_allowlist"):
        if k in body:
            changes[k] = {"from": getattr(src, k), "to": body[k]}
            setattr(src, k, body[k])
    await audit.log(
        session,
        user_id=admin.id,
        action="webhook.patch",
        target_type="webhook_source",
        target_id=src.id,
        diff={"name": src.name, "changes": changes},
    )
    return {"id": str(src.id), "enabled": src.enabled}


@router.delete("/webhook-sources/{source_id}", status_code=204)
async def delete_webhook_source(
    source_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    src = await session.get(WebhookSource, source_id)
    if not src:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook source not found")
    await audit.log(
        session,
        user_id=admin.id,
        action="webhook.delete",
        target_type="webhook_source",
        target_id=src.id,
        diff={"name": src.name},
    )
    await session.delete(src)


# ── Auto-close rules (UI-editable mirror) ───────────────────────────────
@router.get("/auto-close-rules")
async def list_autoclose(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[dict]:
    rows = (await session.scalars(select(AutoCloseRule))).all()
    return [
        {
            "id": str(r.id),
            "rule_id": r.rule_id,
            "customer": r.customer,
            "match": r.match,
            "verdict": r.verdict,
            "reason": r.reason,
            "enabled": r.enabled,
            "source": r.source,
        }
        for r in rows
    ]


@router.post("/auto-close-rules", status_code=status.HTTP_201_CREATED)
async def create_autoclose(
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    rule = AutoCloseRule(
        rule_id=body["rule_id"],
        customer=body.get("customer"),
        match=body["match"],
        verdict=body["verdict"],
        reason=body["reason"],
        enabled=body.get("enabled", True),
    )
    session.add(rule)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="autoclose.create",
        target_type="autoclose_rule",
        target_id=rule.id,
        diff={
            "rule_id": rule.rule_id,
            "customer": rule.customer,
            "verdict": str(rule.verdict),
            "match": rule.match,
        },
    )
    return {"id": str(rule.id), "rule_id": rule.rule_id}


@router.patch("/auto-close-rules/{rule_pk}")
async def patch_autoclose(
    rule_pk: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    rule = await session.get(AutoCloseRule, rule_pk)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    changes: dict = {}
    for k in ("customer", "match", "verdict", "reason", "enabled"):
        if k in body:
            changes[k] = {"from": getattr(rule, k), "to": body[k]}
            setattr(rule, k, body[k])
    await audit.log(
        session,
        user_id=admin.id,
        action="autoclose.patch",
        target_type="autoclose_rule",
        target_id=rule.id,
        diff={"rule_id": rule.rule_id, "changes": changes},
    )
    return {"id": str(rule.id), "rule_id": rule.rule_id, "enabled": rule.enabled}


@router.delete("/auto-close-rules/{rule_pk}", status_code=204)
async def delete_autoclose(
    rule_pk: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    rule = await session.get(AutoCloseRule, rule_pk)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    await audit.log(
        session,
        user_id=admin.id,
        action="autoclose.delete",
        target_type="autoclose_rule",
        target_id=rule.id,
        diff={"rule_id": rule.rule_id},
    )
    await session.delete(rule)


# ── Tenants ─────────────────────────────────────────────────────────────


async def _unique_slug(session: AsyncSession, base: str) -> str:
    slug = base
    n = 1
    while await session.scalar(select(Tenant.id).where(Tenant.slug == slug)):
        n += 1
        slug = f"{base}-{n}"
    return slug


async def _would_create_cycle(
    session: AsyncSession, tenant_id: uuid.UUID, new_parent_id: uuid.UUID | None
) -> bool:
    """True if setting tenant_id.parent_id = new_parent_id would create a cycle."""
    if new_parent_id is None:
        return False
    if new_parent_id == tenant_id:
        return True
    cur: uuid.UUID | None = new_parent_id
    seen: set[uuid.UUID] = set()
    while cur:
        if cur in seen:
            return True  # pre-existing cycle, treat as conflict
        seen.add(cur)
        if cur == tenant_id:
            return True
        cur = await session.scalar(select(Tenant.parent_id).where(Tenant.id == cur))
    return False


@router.get("/tenants")
async def list_tenants(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[dict]:
    """List all tenants with parent name, child count, member count, incident count."""
    parent = Tenant.__table__.alias("parent")

    inc_count_subq = (
        select(Incident.tenant_id, func.count(Incident.id).label("c"))
        .group_by(Incident.tenant_id)
        .subquery()
    )
    mem_count_subq = (
        select(UserTenantMembership.tenant_id, func.count(UserTenantMembership.id).label("c"))
        .group_by(UserTenantMembership.tenant_id)
        .subquery()
    )
    child_count_subq = (
        select(Tenant.parent_id.label("pid"), func.count(Tenant.id).label("c"))
        .where(Tenant.parent_id.is_not(None))
        .group_by(Tenant.parent_id)
        .subquery()
    )

    stmt = (
        select(
            Tenant,
            parent.c.name.label("parent_name"),
            func.coalesce(inc_count_subq.c.c, 0).label("incident_count"),
            func.coalesce(mem_count_subq.c.c, 0).label("member_count"),
            func.coalesce(child_count_subq.c.c, 0).label("child_count"),
        )
        .join(parent, parent.c.id == Tenant.parent_id, isouter=True)
        .join(inc_count_subq, inc_count_subq.c.tenant_id == Tenant.id, isouter=True)
        .join(mem_count_subq, mem_count_subq.c.tenant_id == Tenant.id, isouter=True)
        .join(child_count_subq, child_count_subq.c.pid == Tenant.id, isouter=True)
        .order_by(Tenant.tier, Tenant.name)
    )
    rows = (await session.execute(stmt)).all()
    return [
        {
            "id": str(row.Tenant.id),
            "name": row.Tenant.name,
            "slug": row.Tenant.slug,
            "tier": row.Tenant.tier,
            "tier_label": row.Tenant.tier_label,
            "parent_id": str(row.Tenant.parent_id) if row.Tenant.parent_id else None,
            "parent_name": row.parent_name,
            "incident_count": int(row.incident_count),
            "member_count": int(row.member_count),
            "child_count": int(row.child_count),
            "notification_email": row.Tenant.notification_email,
            "notification_email_cc": row.Tenant.notification_email_cc,
            "locale": row.Tenant.locale,
            "created_at": row.Tenant.created_at.isoformat() if row.Tenant.created_at else None,
        }
        for row in rows
    ]


@router.post("/tenants", status_code=status.HTTP_201_CREATED)
async def create_tenant(
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Create a tenant. Body: { name, tier, parent_id?, tier_label? }"""
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    if await session.scalar(select(Tenant.id).where(Tenant.name == name)):
        raise HTTPException(409, f"tenant '{name}' already exists")

    tier_raw = body.get("tier") or TenantTier.CLIENT.value
    try:
        tier = TenantTier(tier_raw)
    except ValueError:
        raise HTTPException(400, f"invalid tier: {tier_raw}")

    parent_id = body.get("parent_id")
    if parent_id:
        parent_id = uuid.UUID(parent_id)
        if not await session.scalar(select(Tenant.id).where(Tenant.id == parent_id)):
            raise HTTPException(400, "parent_id does not exist")

    slug = await _unique_slug(session, slugify(name))
    t = Tenant(
        name=name,
        slug=slug,
        tier=tier,
        parent_id=parent_id,
        tier_label=body.get("tier_label"),
    )
    session.add(t)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="tenant.create",
        target_type="tenant",
        target_id=t.id,
        tenant_id=t.id,
        diff={"name": name, "tier": str(tier), "parent_id": str(parent_id) if parent_id else None},
    )
    return {"id": str(t.id), "name": t.name, "slug": t.slug, "tier": t.tier}


@router.patch("/tenants/{tenant_id}")
async def patch_tenant(
    tenant_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Update a tenant. Allowed: name, tier, parent_id, tier_label."""
    t = await session.get(Tenant, tenant_id)
    if not t:
        raise HTTPException(404, "tenant not found")

    changes: dict = {}

    # Routing fields for customer notifications (Phase-CC1)
    for k in ("notification_email", "notification_email_cc", "locale"):
        if k in body:
            new_val = body[k] or None
            if new_val != getattr(t, k):
                changes[k] = {"from": getattr(t, k), "to": new_val}
                setattr(t, k, new_val)

    if "name" in body:
        new_name = (body["name"] or "").strip()
        if not new_name:
            raise HTTPException(400, "name cannot be empty")
        if new_name != t.name and await session.scalar(
            select(Tenant.id).where(Tenant.name == new_name)
        ):
            raise HTTPException(409, f"tenant '{new_name}' already exists")
        changes["name"] = {"from": t.name, "to": new_name}
        t.name = new_name

    if "tier" in body:
        try:
            new_tier = TenantTier(body["tier"])
        except ValueError:
            raise HTTPException(400, f"invalid tier: {body['tier']}")
        changes["tier"] = {"from": str(t.tier), "to": str(new_tier)}
        t.tier = new_tier

    if "tier_label" in body:
        changes["tier_label"] = {"from": t.tier_label, "to": body["tier_label"]}
        t.tier_label = body["tier_label"]

    if "parent_id" in body:
        raw = body["parent_id"]
        new_parent = uuid.UUID(raw) if raw else None
        if new_parent and not await session.scalar(
            select(Tenant.id).where(Tenant.id == new_parent)
        ):
            raise HTTPException(400, "parent_id does not exist")
        if await _would_create_cycle(session, tenant_id, new_parent):
            raise HTTPException(400, "parent_id would create a cycle")
        changes["parent_id"] = {
            "from": str(t.parent_id) if t.parent_id else None,
            "to": str(new_parent) if new_parent else None,
        }
        t.parent_id = new_parent

    await audit.log(
        session,
        user_id=admin.id,
        action="tenant.patch",
        target_type="tenant",
        target_id=t.id,
        tenant_id=t.id,
        diff={"name": t.name, "changes": changes},
    )
    return {"id": str(t.id), "name": t.name, "tier": str(t.tier)}


@router.delete("/tenants/{tenant_id}", status_code=204)
async def delete_tenant(
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    t = await session.get(Tenant, tenant_id)
    if not t:
        raise HTTPException(404, "tenant not found")

    child_count = await session.scalar(
        select(func.count(Tenant.id)).where(Tenant.parent_id == tenant_id)
    )
    if child_count:
        raise HTTPException(
            409, f"cannot delete: {child_count} child tenant(s) still reference this one"
        )

    await audit.log(
        session,
        user_id=admin.id,
        action="tenant.delete",
        target_type="tenant",
        target_id=t.id,
        tenant_id=t.id,
        diff={"name": t.name, "tier": str(t.tier)},
    )
    await session.delete(t)


# ── Memberships (users ↔ tenants) ───────────────────────────────────────


@router.get("/tenants/{tenant_id}/members")
async def list_tenant_members(
    tenant_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[dict]:
    t = await session.get(Tenant, tenant_id)
    if not t:
        raise HTTPException(404, "tenant not found")

    rows = (
        await session.execute(
            select(User, UserTenantMembership.role, UserTenantMembership.id)
            .join(UserTenantMembership, UserTenantMembership.user_id == User.id)
            .where(UserTenantMembership.tenant_id == tenant_id)
            .order_by(User.email)
        )
    ).all()
    return [
        {
            "membership_id": str(mid),
            "user_id": str(u.id),
            "email": u.email,
            "full_name": u.full_name,
            "status": str(u.status),
            "tenant_role": str(role),
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u, role, mid in rows
    ]


@router.post("/tenants/{tenant_id}/members", status_code=status.HTTP_201_CREATED)
async def add_tenant_member(
    tenant_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Add a user (creating them if needed) and bind them to this tenant.
    Body: { email, role?, full_name?, password? }
    If password is omitted, one is generated and returned ONCE in
    `temp_password_shown_once` (like the webhook secret pattern)."""
    t = await session.get(Tenant, tenant_id)
    if not t:
        raise HTTPException(404, "tenant not found")

    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "valid email is required")

    role_raw = body.get("role") or Role.ANALYST.value
    try:
        role = Role(role_raw)
    except ValueError:
        raise HTTPException(400, f"invalid role: {role_raw}")

    # Find or create user
    user = await session.scalar(select(User).where(User.email == email))
    temp_password: str | None = None
    if user is None:
        pw = body.get("password") or secrets.token_urlsafe(12)
        temp_password = pw if not body.get("password") else None
        user = User(
            email=email,
            password_hash=hash_password(pw),
            role=Role.ANALYST,  # GLOBAL role stays as ANALYST — tenant role is what matters
            full_name=body.get("full_name"),
        )
        session.add(user)
        await session.flush()
        await audit.log(
            session,
            user_id=admin.id,
            action="user.create",
            target_type="user",
            target_id=user.id,
            diff={"email": email, "via": "tenant_invite"},
        )

    # Add membership (reject duplicate)
    existing = await session.scalar(
        select(UserTenantMembership.id).where(
            UserTenantMembership.user_id == user.id,
            UserTenantMembership.tenant_id == tenant_id,
        )
    )
    if existing:
        raise HTTPException(409, "user is already a member of this tenant")

    m = UserTenantMembership(user_id=user.id, tenant_id=tenant_id, role=role)
    session.add(m)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="membership.create",
        target_type="membership",
        target_id=m.id,
        tenant_id=t.id,
        diff={"user_email": email, "tenant_name": t.name, "role": str(role)},
    )

    return {
        "membership_id": str(m.id),
        "user_id": str(user.id),
        "email": user.email,
        "tenant_role": str(role),
        "temp_password_shown_once": temp_password,
    }


@router.patch("/tenants/{tenant_id}/members/{membership_id}")
async def patch_tenant_member(
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    body: dict,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Currently only role is mutable."""
    m = await session.get(UserTenantMembership, membership_id)
    if not m or m.tenant_id != tenant_id:
        raise HTTPException(404, "membership not found")

    if "role" not in body:
        raise HTTPException(400, "only `role` is mutable")
    try:
        new_role = Role(body["role"])
    except ValueError:
        raise HTTPException(400, f"invalid role: {body['role']}")

    old_role = m.role
    m.role = new_role
    await audit.log(
        session,
        user_id=admin.id,
        action="membership.patch",
        target_type="membership",
        target_id=m.id,
        tenant_id=m.tenant_id,
        diff={"role": {"from": str(old_role), "to": str(new_role)}},
    )
    return {"membership_id": str(m.id), "role": str(new_role)}


@router.delete("/tenants/{tenant_id}/members/{membership_id}", status_code=204)
async def remove_tenant_member(
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    m = await session.get(UserTenantMembership, membership_id)
    if not m or m.tenant_id != tenant_id:
        raise HTTPException(404, "membership not found")
    await audit.log(
        session,
        user_id=admin.id,
        action="membership.delete",
        target_type="membership",
        target_id=m.id,
        tenant_id=m.tenant_id,
        diff={"user_id": str(m.user_id), "tenant_id": str(m.tenant_id)},
    )
    await session.delete(m)


# ── LLM Settings ────────────────────────────────────────────────────────────


class LLMConfigIn(BaseModel):
    endpoint_url: str = Field(..., min_length=1, max_length=500)
    api_key: str | None = Field(None, description="Omit or null to keep the existing key.")
    model_name: str = Field(..., min_length=1, max_length=200)
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(4096, ge=1, le=65536)


class LLMConfigOut(BaseModel):
    has_config: bool
    endpoint_url: str
    api_key_masked: str
    model_name: str
    temperature: float
    max_tokens: int
    updated_at: str | None
    updated_by_email: str | None


def _row_to_out(row: LLMConfig, email: str | None) -> LLMConfigOut:
    plaintext: str = ""
    if row.api_key_encrypted:
        try:
            plaintext = decrypt_secret(row.api_key_encrypted)
        except Exception:
            plaintext = ""
    return LLMConfigOut(
        has_config=True,
        endpoint_url=row.endpoint_url,
        api_key_masked=mask_key(plaintext) if plaintext else "—",
        model_name=row.model_name,
        temperature=float(row.temperature),
        max_tokens=row.max_tokens,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        updated_by_email=email,
    )


@router.get("/settings/llm", response_model=LLMConfigOut)
async def get_llm_settings(
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> LLMConfigOut:
    """Return current LLM configuration (API key masked)."""
    row: LLMConfig | None = (await session.execute(select(LLMConfig).limit(1))).scalar_one_or_none()

    if row is None:
        from ..settings import settings as _s

        return LLMConfigOut(
            has_config=False,
            endpoint_url=_s.litellm_base_url,
            api_key_masked="(env var)",
            model_name=_s.isoc_model_deep,
            temperature=0.2,
            max_tokens=4096,
            updated_at=None,
            updated_by_email=None,
        )

    email: str | None = None
    if row.updated_by_id:
        updater = await session.get(User, row.updated_by_id)
        email = updater.email if updater else None

    return _row_to_out(row, email)


@router.put("/settings/llm", response_model=LLMConfigOut)
async def put_llm_settings(
    body: LLMConfigIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> LLMConfigOut:
    """Create or update the platform LLM configuration."""
    await _guard_endpoint_url(body.endpoint_url)
    existing: LLMConfig | None = (
        await session.execute(select(LLMConfig).limit(1))
    ).scalar_one_or_none()

    # Resolve the key to store
    if body.api_key is not None:
        encrypted = encrypt_secret(body.api_key)
    elif existing is not None:
        encrypted = existing.api_key_encrypted  # keep the existing key
    else:
        encrypted = None

    if existing is None:
        row = LLMConfig(
            id=1,
            endpoint_url=body.endpoint_url,
            api_key_encrypted=encrypted,
            model_name=body.model_name,
            temperature=body.temperature,
            max_tokens=body.max_tokens,
            updated_by_id=admin.id,
        )
        session.add(row)
    else:
        existing.endpoint_url = body.endpoint_url
        existing.api_key_encrypted = encrypted
        existing.model_name = body.model_name
        existing.temperature = body.temperature
        existing.max_tokens = body.max_tokens
        existing.updated_by_id = admin.id
        row = existing

    await audit.log(
        session,
        user_id=admin.id,
        action="llm_config.update",
        target_type="llm_config",
        target_id=None,
        tenant_id=None,
        diff={
            "endpoint_url": body.endpoint_url,
            "model_name": body.model_name,
            "temperature": body.temperature,
            "max_tokens": body.max_tokens,
            "api_key_changed": body.api_key is not None,
        },
    )

    await session.flush()
    await session.refresh(row)
    await session.commit()

    # Invalidate the in-process cache so the next LLM call picks up the change.
    invalidate_cache()

    return _row_to_out(row, admin.email)


class LLMTestIn(BaseModel):
    """Optional form-value overrides — lets the UI test before saving."""

    endpoint_url: str | None = None
    api_key: str | None = None
    model_name: str | None = None


@router.post("/settings/llm/test")
async def test_llm_settings(
    body: LLMTestIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Fire a minimal LLM ping.

    If the body contains endpoint_url / api_key / model_name, those values are
    used directly (test-before-save).  Otherwise falls back to the saved DB
    config or env-var defaults — same precedence as the live pipeline.
    """
    import time

    from openai import AsyncOpenAI

    from ..llm.config_store import get_llm_config
    from ..settings import settings as _s

    # Build a transient client from form values (if supplied) or saved config.
    if body.endpoint_url:
        _base = body.endpoint_url.rstrip("/")
        if not _base.endswith("/v1"):
            _base = f"{_base}/v1"
        _key = body.api_key or "sk-placeholder"
        _model = body.model_name or "test"
    else:
        dyn = await get_llm_config()
        if dyn:
            _base = dyn.endpoint_url.rstrip("/")
            if not _base.endswith("/v1"):
                _base = f"{_base}/v1"
            _key = dyn.api_key or "sk-placeholder"
            _model = dyn.model_name
        else:
            _base = f"{_s.litellm_base_url}/v1"
            _key = _s.litellm_master_key.get_secret_value()
            _model = _s.isoc_model_deep

    test_client = AsyncOpenAI(
        base_url=_base,
        api_key=_key,
        timeout=30,
        max_retries=0,
    )

    started = time.perf_counter()
    try:
        resp = await test_client.chat.completions.create(
            model=_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a connectivity test bot. Reply with exactly one word.",
                },
                {"role": "user", "content": "Reply with the word: ok"},
            ],
            max_tokens=8,
            temperature=0.0,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        text = resp.choices[0].message.content or ""
    except Exception as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        raise HTTPException(status_code=502, detail=f"LLM test failed: {exc}") from exc

    return {
        "success": True,
        "model": _model,
        "latency_ms": latency_ms,
        "response_preview": text[:120],
    }


@router.delete("/settings/llm", status_code=204)
async def reset_llm_settings(
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    """Delete the admin LLM override so the system falls back to env-var defaults.

    With the row gone, complete() routes through the LiteLLM proxy again — which
    preserves the tiered isoc-fast / isoc-deep routing (e.g. Haiku for the fast
    classifier, Sonnet for deep synthesis).
    """
    row: LLMConfig | None = (await session.execute(select(LLMConfig).limit(1))).scalar_one_or_none()
    if row is None:
        return  # already on env-var defaults — nothing to do

    await audit.log(
        session,
        user_id=admin.id,
        action="llm_config.reset",
        target_type="llm_config",
        target_id=None,
        tenant_id=None,
        diff={"reverted_to": "environment defaults (LiteLLM)"},
    )
    await session.delete(row)
    await session.commit()
    invalidate_cache()


# ── Integration credentials (EDR/XDR API keys — ADR-0003/0005) ──────────────
# Admin-only CRUD over the `integrations` table. Keys are Fernet-encrypted at
# rest and never returned in full (masked on read). Mirrors the webhook-source
# list-CRUD + the LLM "omit api_key to keep the existing one" semantics.

# Providers whose per-customer/global credentials live in the `integrations`
# table (Fernet-encrypted). EDR/XDR connectors + TI/recon feeds (F2 seam —
# resolved via integration_store.get_creds). All providers are DB-only.
# Single source of truth: the connectors catalogue (3.11). Keeps the admin
# provider allow-list in sync with the connector specs the UI renders.
_INTEGRATION_PROVIDERS = _connector_registry.connector_keys()


class IntegrationIn(BaseModel):
    provider: str = Field(..., description=f"one of: {', '.join(_INTEGRATION_PROVIDERS)}")
    identifier: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="customer / console host scope; 'default' = global (applies when no specific match)",
    )
    label: str | None = Field(None, max_length=200)
    enabled: bool = True
    region: str | None = Field(None, max_length=16, description="V1 region: us|eu|jp|au|sg|in|mea")
    base_url: str | None = Field(
        None,
        max_length=256,
        description="console host / API endpoint (e.g. S1 console, CrowdStrike cloud)",
    )
    api_key: str | None = Field(None, description="Omit/null on PATCH to keep the existing key.")
    # OAuth client credentials (crowdstrike / microsoft_defender).
    client_id: str | None = Field(None, max_length=256)
    client_secret: str | None = Field(
        None, description="Omit/null on PATCH to keep the existing secret."
    )
    oauth_tenant_id: str | None = Field(
        None, max_length=128, description="Azure AD tenant id (microsoft_defender)"
    )


class IntegrationOut(BaseModel):
    id: str
    provider: str
    identifier: str
    label: str | None
    enabled: bool
    region: str | None
    base_url: str | None
    api_key_masked: str
    has_key: bool
    client_id: str | None
    oauth_tenant_id: str | None
    has_client_secret: bool  # never the secret itself
    updated_at: str | None
    updated_by_email: str | None


def _integration_out(row: Integration, email: str | None) -> IntegrationOut:
    plaintext = ""
    if row.api_key_encrypted:
        try:
            plaintext = decrypt_secret(row.api_key_encrypted)
        except Exception:
            plaintext = ""
    return IntegrationOut(
        id=str(row.id),
        provider=row.provider,
        identifier=row.identifier,
        label=row.label,
        enabled=row.enabled,
        region=row.region,
        base_url=row.base_url,
        api_key_masked=mask_key(plaintext) if plaintext else "—",
        has_key=bool(row.api_key_encrypted),
        client_id=row.client_id,
        oauth_tenant_id=row.oauth_tenant_id,
        has_client_secret=bool(row.client_secret_encrypted),
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        updated_by_email=email,
    )


@router.get("/settings/integrations", response_model=list[IntegrationOut])
async def list_integrations(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[IntegrationOut]:
    rows = (
        await session.scalars(
            select(Integration).order_by(Integration.provider, Integration.identifier)
        )
    ).all()
    out: list[IntegrationOut] = []
    for r in rows:
        email = None
        if r.updated_by_id:
            u = await session.get(User, r.updated_by_id)
            email = u.email if u else None
        out.append(_integration_out(r, email))
    return out


@router.post(
    "/settings/integrations", response_model=IntegrationOut, status_code=status.HTTP_201_CREATED
)
async def create_integration(
    body: IntegrationIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> IntegrationOut:
    if body.provider not in _INTEGRATION_PROVIDERS:
        raise HTTPException(400, f"provider must be one of {_INTEGRATION_PROVIDERS}")
    if body.provider == "vision_one" and not body.region:
        raise HTTPException(400, "region is required for vision_one")
    await _guard_console_url(body.base_url)
    if await session.scalar(
        select(Integration.id).where(
            Integration.provider == body.provider, Integration.identifier == body.identifier
        )
    ):
        raise HTTPException(409, f"{body.provider} integration '{body.identifier}' already exists")

    row = Integration(
        provider=body.provider,
        identifier=body.identifier,
        label=body.label,
        enabled=body.enabled,
        region=body.region,
        base_url=body.base_url,
        api_key_encrypted=encrypt_secret(body.api_key) if body.api_key else None,
        client_id=body.client_id,
        client_secret_encrypted=encrypt_secret(body.client_secret) if body.client_secret else None,
        oauth_tenant_id=body.oauth_tenant_id,
        updated_by_id=admin.id,
    )
    session.add(row)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="integration.create",
        target_type="integration",
        target_id=row.id,
        diff={
            "provider": row.provider,
            "identifier": row.identifier,
            "region": row.region,
            "api_key_set": bool(body.api_key),
        },
    )
    return _integration_out(row, admin.email)


@router.patch("/settings/integrations/{integration_id}", response_model=IntegrationOut)
async def patch_integration(
    integration_id: uuid.UUID,
    body: IntegrationIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> IntegrationOut:
    row = await session.get(Integration, integration_id)
    if not row:
        raise HTTPException(404, "integration not found")
    if body.provider not in _INTEGRATION_PROVIDERS:
        raise HTTPException(400, f"provider must be one of {_INTEGRATION_PROVIDERS}")
    await _guard_console_url(body.base_url)

    row.provider = body.provider
    row.identifier = body.identifier
    row.label = body.label
    row.enabled = body.enabled
    row.region = body.region
    row.base_url = body.base_url
    if body.api_key is not None:  # omit/null → keep the existing key
        row.api_key_encrypted = encrypt_secret(body.api_key)
    row.client_id = body.client_id
    row.oauth_tenant_id = body.oauth_tenant_id
    if body.client_secret is not None:  # omit/null → keep the existing secret
        row.client_secret_encrypted = encrypt_secret(body.client_secret)
    row.updated_by_id = admin.id

    await audit.log(
        session,
        user_id=admin.id,
        action="integration.patch",
        target_type="integration",
        target_id=row.id,
        diff={
            "provider": row.provider,
            "identifier": row.identifier,
            "enabled": row.enabled,
            "api_key_changed": body.api_key is not None,
        },
    )
    await session.flush()
    return _integration_out(row, admin.email)


@router.delete("/settings/integrations/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
):
    row = await session.get(Integration, integration_id)
    if not row:
        raise HTTPException(404, "integration not found")
    await audit.log(
        session,
        user_id=admin.id,
        action="integration.delete",
        target_type="integration",
        target_id=row.id,
        diff={"provider": row.provider, "identifier": row.identifier},
    )
    await session.delete(row)
