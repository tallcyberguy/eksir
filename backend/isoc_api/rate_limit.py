"""Rate limiter — shared across main.py and route modules.

Lives in its own module so route modules can import the limiter without
creating a circular import on main.py (main imports routes; routes can't
import from main).

Per-route limits live on the individual route decorators. Examples:

    from ..rate_limit import limiter

    @router.post("/login")
    @limiter.limit("10/minute")                 # 10 attempts/min per IP
    async def login(request: Request, ...): ...

    @router.post("/paste")
    @limiter.limit("60/minute", key_func=user_key)   # 60/min per user
    async def paste(request: Request, ...): ...

The route MUST take `request: Request` as a parameter — slowapi needs it
to derive the rate-key.
"""

from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

# IP-keyed limiter (the default). Routes that want per-user limits pass a
# `key_func=user_key` override to the decorator.
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def user_key(request: Request) -> str:
    """Key the rate-limit by authenticated user when available, else IP.

    Used by endpoints where 'one analyst pasting a lot' is fine but
    'one shared IP behind NAT pasting a lot' is not. Falls back to IP for
    unauthenticated requests so it can't be bypassed by skipping auth.
    """
    # current_user dep stashes the user on request.state. If absent (anon),
    # degrade to IP-based limiting.
    user = getattr(request.state, "user", None)
    if user is not None:
        return f"user:{user.id}"
    return get_remote_address(request)
