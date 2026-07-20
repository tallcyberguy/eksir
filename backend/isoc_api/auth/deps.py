"""FastAPI dependencies — `current_user`, RBAC guards."""

from __future__ import annotations

import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.enums import Role, UserStatus
from ..db.models import User
from ..db.session import get_session
from .security import decode_token, is_access_token, token_version_ok

_bearer = HTTPBearer(auto_error=False)


async def current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    if not creds or not creds.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        payload = decode_token(creds.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token expired") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from None

    # An interim MFA-challenge token (purpose="mfa") may never authenticate a
    # normal request — it is only exchangeable at /auth/login/mfa.
    if not is_access_token(payload):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mfa challenge token not accepted")

    user_id = uuid.UUID(payload["sub"])
    user = await session.get(User, user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or disabled")
    # Fail-closed revocation: the token's `ver` must match the user's current
    # token_version. Logout / revoke bumps the version, instantly invalidating
    # every outstanding token for that user.
    if not token_version_ok(payload, user.token_version):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token revoked") from None
    return user


def require_role(*allowed: Role):
    async def _guard(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in allowed and user.role != Role.ADMIN:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user

    return _guard


require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_viewer = require_role(Role.VIEWER, Role.ANALYST)
