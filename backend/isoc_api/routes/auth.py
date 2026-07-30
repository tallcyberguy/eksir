"""Login / MFA / logout / me."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..auth.deps import current_user
from ..auth.mfa import generate_secret, provisioning_uri, qr_data_uri, verify_code
from ..auth.security import (
    decode_token,
    hash_password,
    issue_mfa_challenge,
    issue_token,
    verify_password,
)
from ..auth.tenancy import resolve_tenant_scope
from ..db.enums import UserStatus
from ..db.models import Tenant, User
from ..db.session import get_session
from ..llm.config_store import decrypt_secret, encrypt_secret
from ..rate_limit import limiter
from ..schemas import (
    LoginRequest,
    LoginResult,
    MfaCodeRequest,
    MfaEnrollResponse,
    MfaLoginRequest,
    PasswordChange,
    TokenResponse,
    UserOut,
)

router = APIRouter()


def _issue_full_login(user: User) -> TokenResponse:
    """Mint a full access token for a user (embeds their current token_version)."""
    return TokenResponse(
        token=issue_token(user.id, user.role, user.token_version),
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=LoginResult)
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LoginResult:
    email = body.email.lower()
    user = await session.scalar(select(User).where(User.email == email))
    if user is None or user.status != UserStatus.ACTIVE:
        await audit.log(
            session,
            action="auth.login_failed",
            target_type="user",
            diff={"email": email, "reason": "unknown_or_inactive"},
        )
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not verify_password(body.password, user.password_hash):
        await audit.log(
            session,
            action="auth.login_failed",
            target_type="user",
            target_id=user.id,
            diff={"email": email, "reason": "bad_password"},
        )
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    # Password OK. If MFA is active, issue only a short-lived challenge — the
    # full token comes from /login/mfa after TOTP verification.
    if user.mfa_enabled and user.totp_secret:
        await audit.log(
            session,
            user_id=user.id,
            action="auth.mfa_challenge",
            target_type="user",
            target_id=user.id,
            diff={"email": email},
        )
        return LoginResult(mfa_required=True, mfa_token=issue_mfa_challenge(user.id))

    user.last_login_at = datetime.now(timezone.utc)
    await audit.log(
        session,
        user_id=user.id,
        action="auth.login_ok",
        target_type="user",
        target_id=user.id,
        diff={"email": email},
    )
    full = _issue_full_login(user)
    return LoginResult(token=full.token, user=full.user)


@router.post("/login/mfa", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_mfa(
    request: Request,
    body: MfaLoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TokenResponse:
    """Second step of an MFA login: exchange the challenge token + TOTP code for
    a full access token."""
    try:
        payload = decode_token(body.mfa_token)
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired challenge") from None
    if payload.get("purpose") != "mfa":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid challenge token")

    user = await session.get(User, uuid.UUID(payload["sub"]))
    if (
        user is None
        or user.status != UserStatus.ACTIVE
        or not user.mfa_enabled
        or not user.totp_secret
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if not verify_code(decrypt_secret(user.totp_secret), body.code):
        await audit.log(
            session,
            user_id=user.id,
            action="auth.mfa_login_failed",
            target_type="user",
            target_id=user.id,
            diff={"email": user.email},
        )
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    user.last_login_at = datetime.now(timezone.utc)
    await audit.log(
        session,
        user_id=user.id,
        action="auth.login_ok",
        target_type="user",
        target_id=user.id,
        diff={"email": user.email, "mfa": True},
    )
    return _issue_full_login(user)


# ── MFA enrollment (authenticated) ────────────────────────────────────────
@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> MfaEnrollResponse:
    """Begin enrollment: generate + store (encrypted) a fresh secret and return
    it for the authenticator app. MFA stays OFF until /mfa/activate confirms a
    code, so an abandoned enrollment can't lock the user out."""
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled — disable it first")
    secret = generate_secret()
    user.totp_secret = encrypt_secret(secret)
    await audit.log(
        session,
        user_id=user.id,
        action="auth.mfa_enroll_start",
        target_type="user",
        target_id=user.id,
    )
    uri = provisioning_uri(secret, user.email)
    return MfaEnrollResponse(secret=secret, otpauth_uri=uri, qr_data_uri=qr_data_uri(uri))


@router.post("/mfa/activate", response_model=UserOut)
async def mfa_activate(
    body: MfaCodeRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> UserOut:
    """Confirm the first code and switch MFA on."""
    if user.mfa_enabled:
        return UserOut.model_validate(user)  # idempotent
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no enrollment in progress")
    if not verify_code(decrypt_secret(user.totp_secret), body.code):
        await audit.log(
            session,
            user_id=user.id,
            action="auth.mfa_activate_failed",
            target_type="user",
            target_id=user.id,
        )
        await session.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = True
    await audit.log(
        session,
        user_id=user.id,
        action="auth.mfa_enabled",
        target_type="user",
        target_id=user.id,
    )
    return UserOut.model_validate(user)


@router.post("/mfa/disable", response_model=UserOut)
async def mfa_disable(
    body: MfaCodeRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> UserOut:
    """Turn MFA off. Requires a valid current code so a hijacked session that
    lacks the device can't strip the second factor."""
    if not user.mfa_enabled or not user.totp_secret:
        user.mfa_enabled = False
        user.totp_secret = None
        return UserOut.model_validate(user)
    if not verify_code(decrypt_secret(user.totp_secret), body.code):
        await audit.log(
            session,
            user_id=user.id,
            action="auth.mfa_disable_failed",
            target_type="user",
            target_id=user.id,
        )
        await session.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = False
    user.totp_secret = None
    await audit.log(
        session,
        user_id=user.id,
        action="auth.mfa_disabled",
        target_type="user",
        target_id=user.id,
    )
    return UserOut.model_validate(user)


@router.get("/me", response_model=UserOut)
async def me(user: Annotated[User, Depends(current_user)]) -> UserOut:
    return UserOut.model_validate(user)


@router.post("/change-password", response_model=TokenResponse)
async def change_password(
    body: PasswordChange,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> TokenResponse:
    """Self-service password change. Verifies the current password, sets the new
    one, and bumps token_version to revoke every OTHER outstanding session, then
    re-issues a fresh token so THIS session keeps working."""
    if not verify_password(body.current_password, user.password_hash):
        await audit.log(
            session,
            user_id=user.id,
            action="auth.password_change_failed",
            target_type="user",
            target_id=user.id,
        )
        await session.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is incorrect")
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "new password must differ from the current one"
        )
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    await audit.log(
        session,
        user_id=user.id,
        action="auth.password_changed",
        target_type="user",
        target_id=user.id,
    )
    return _issue_full_login(user)


@router.post("/logout")
async def logout(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, str]:
    """Real logout: bump token_version so every outstanding token for this user
    (including the one making this call) is rejected on its next use. The client
    also drops its stored token."""
    user.token_version += 1
    await audit.log(
        session,
        user_id=user.id,
        action="auth.logout",
        target_type="user",
        target_id=user.id,
    )
    return {"status": "ok"}


@router.get("/scope")
async def get_scope(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> dict:
    """Return what the Topbar tenant switcher needs:
    • is_unlimited: True for admins / HOST members (can see all tenants)
    • tenants: the list the user may switch into (own + descendants for MSSP,
               all tenants for admin/HOST). Each row: {id, name, tier, slug}.
    The Topbar hides the switcher unless `tenants` has more than one entry.
    """
    natural = await resolve_tenant_scope(user, session)
    is_unlimited = natural is None

    if is_unlimited:
        rows = (
            await session.execute(
                select(Tenant.id, Tenant.name, Tenant.tier, Tenant.slug).order_by(
                    Tenant.tier, Tenant.name
                )
            )
        ).all()
    elif not natural:
        rows = []
    else:
        rows = (
            await session.execute(
                select(Tenant.id, Tenant.name, Tenant.tier, Tenant.slug)
                .where(Tenant.id.in_(natural))
                .order_by(Tenant.tier, Tenant.name)
            )
        ).all()

    return {
        "is_unlimited": is_unlimited,
        "tenants": [
            {"id": str(r.id), "name": r.name, "tier": str(r.tier), "slug": r.slug} for r in rows
        ],
    }
