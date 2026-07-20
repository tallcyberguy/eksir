"""LLM dynamic configuration — DB-backed with a 60-second in-memory cache.

The admin can override the LLM endpoint, API key, model and generation
parameters via the UI.  Changes take effect within one cache TTL (~60 s)
without any restart.

Encryption
----------
The API key is stored encrypted with Fernet symmetric encryption.  The key is
sourced from SETTINGS_ENCRYPTION_KEY env var.  If that var is absent the
system derives a Fernet-compatible key from JWT_SECRET using SHA-256 (fine for
dev/single-node; set the explicit var in any real deployment).

Cache design
------------
Pure in-process dict protected by an asyncio.Lock.  Two workers in the same
process share one cache.  Cross-process coherency isn't needed: the worst case
is a 60-second lag on a second worker before it picks up the change, which is
acceptable for an admin-only setting.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.llm.config_store")

# ── Encryption helpers ───────────────────────────────────────────────────────


def _fernet() -> Fernet:
    raw = settings.settings_encryption_key
    if raw is not None:
        key_bytes = raw.get_secret_value().encode()
    else:
        # Derive a deterministic Fernet key from JWT_SECRET.  Warn once.
        logger.warning(
            "llm_config.no_encryption_key",
            msg="SETTINGS_ENCRYPTION_KEY not set — deriving from JWT_SECRET. "
            "Set an explicit key in production.",
        )
        digest = hashlib.sha256(settings.jwt_secret.get_secret_value().encode()).digest()
        key_bytes = base64.urlsafe_b64encode(digest)
    return Fernet(key_bytes)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


def mask_key(plaintext: str) -> str:
    """Return a safe display string — never the full key."""
    if not plaintext:
        return "—"
    if len(plaintext) <= 8:
        return "***"
    prefix = plaintext[:3] if plaintext.startswith("sk-") else plaintext[:2]
    return f"{prefix}-***...{plaintext[-4:]}"


# ── Cached config dataclass ──────────────────────────────────────────────────


@dataclass(slots=True)
class LLMDynConfig:
    endpoint_url: str
    api_key: str | None  # decrypted plaintext; None if absent/unreadable
    model_name: str
    temperature: float
    max_tokens: int


# ── In-memory cache ──────────────────────────────────────────────────────────

_CACHE_TTL = 60.0  # seconds
_cache_lock = asyncio.Lock()
_cache_ts: float = 0.0
_cache_val: LLMDynConfig | None = None  # None = table is empty


def invalidate_cache() -> None:
    """Called after a successful save so the next request re-reads the DB."""
    global _cache_ts
    _cache_ts = 0.0


async def get_llm_config() -> LLMDynConfig | None:
    """Return the DB-stored LLM config, or None if the table is empty.

    Creates its own short-lived DB session to avoid coupling to the request
    context — callers (including llm/client.py) don't need to pass a session.
    Uses an asyncio.Lock for double-checked locking so concurrent requests
    don't all hit the DB on cache miss.
    """
    global _cache_ts, _cache_val

    # Fast path — no lock
    if time.monotonic() - _cache_ts < _CACHE_TTL:
        return _cache_val

    async with _cache_lock:
        # Re-check after acquiring the lock
        if time.monotonic() - _cache_ts < _CACHE_TTL:
            return _cache_val

        _cache_val = await _fetch_from_db()
        _cache_ts = time.monotonic()
        return _cache_val


async def _fetch_from_db() -> LLMDynConfig | None:
    from sqlalchemy import select

    from ..db.models import LLMConfig
    from ..db.session import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as session:
            row: LLMConfig | None = (
                await session.execute(select(LLMConfig).limit(1))
            ).scalar_one_or_none()

        if row is None:
            return None

        api_key: str | None = None
        if row.api_key_encrypted:
            try:
                api_key = decrypt_secret(row.api_key_encrypted)
            except (InvalidToken, Exception) as exc:
                logger.warning("llm_config.decrypt_failed", error=str(exc))

        return LLMDynConfig(
            endpoint_url=row.endpoint_url,
            api_key=api_key,
            model_name=row.model_name,
            temperature=float(row.temperature),
            max_tokens=row.max_tokens,
        )
    except Exception as exc:
        logger.error("llm_config.fetch_failed", error=str(exc))
        return None
