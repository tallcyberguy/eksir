"""Password hashing + JWT helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from ..settings import settings

# bcrypt has a hard 72-byte limit on the input. We truncate at hash + verify
# time so users can set arbitrarily long passwords without surprise failures.
_BCRYPT_MAX = 72


def _clip(password: str) -> bytes:
    b = password.encode("utf-8")
    return b[:_BCRYPT_MAX]


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(_clip(password), salt).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_clip(password), password_hash.encode("ascii"))
    except Exception:
        return False


# Interim MFA-challenge token TTL: issued after a correct password, exchanged
# for a full token once the TOTP code is verified. Short enough to bound the
# window, long enough for the user to fetch a code.
MFA_CHALLENGE_TTL_SECONDS = 300


def issue_token(user_id: uuid.UUID, role: str, token_version: int = 0) -> str:
    """A full access token. Carries `ver` (must equal users.token_version — the
    revocation check in current_user) and a random `jti` (session id for audit /
    a future per-token denylist)."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.jwt_ttl_minutes)
    payload = {
        "sub": str(user_id),
        "role": role,
        "purpose": "access",
        "ver": token_version,
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": "isoc",
    }
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def issue_mfa_challenge(user_id: uuid.UUID) -> str:
    """Short-lived token proving the password step succeeded. `purpose="mfa"`
    so current_user refuses it for normal requests — it can ONLY be exchanged at
    /auth/login/mfa for a full token after TOTP verification."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=MFA_CHALLENGE_TTL_SECONDS)
    payload = {
        "sub": str(user_id),
        "purpose": "mfa",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": "isoc",
    }
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        issuer="isoc",
    )


def is_access_token(payload: dict) -> bool:
    """False for the interim MFA-challenge token (purpose='mfa'), which must
    never authenticate a normal request."""
    return payload.get("purpose") != "mfa"


def token_version_ok(payload: dict, current_version: int) -> bool:
    """Revocation check: a token is valid only while its `ver` claim matches the
    user's current token_version. A missing `ver` (a token minted before this
    feature) counts as 0, so existing sessions survive the deploy that adds the
    default-0 column. A malformed `ver` fails closed."""
    try:
        return int(payload.get("ver", 0)) == current_version
    except (TypeError, ValueError):
        return False
