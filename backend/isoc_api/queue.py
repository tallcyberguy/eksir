"""ARQ Redis queue — single connection pool, FastAPI dependency."""

from __future__ import annotations

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from .settings import settings

_pool: ArqRedis | None = None


def redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(settings.redis_url)


async def get_arq() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(redis_settings())
    return _pool


async def close_arq() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
