"""ISOC FastAPI entrypoint.

Mounts versioned API routers, websocket handlers, and the OpenAPI spec.
Route module imports are lazy (inside `lifespan`) so that scaffold builds
without the route files existing yet.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from .logging_config import configure_logging, get_logger
from .settings import settings

logger = get_logger("isoc.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("isoc.startup", domain=settings.isoc_domain, version=app.version)

    # Lazy imports keep this module loadable before later modules exist.
    from .auth.bootstrap import ensure_bootstrap_admin
    from .db.session import dispose_db, init_db
    from .hardening import assert_secrets_hardened

    # Fail-closed: refuse to boot in a production posture with weak secrets
    # (warns only in dev). Runs before anything touches the DB.
    assert_secrets_hardened(settings, logger)

    await init_db()
    await ensure_bootstrap_admin()
    yield
    await dispose_db()
    logger.info("isoc.shutdown")


app = FastAPI(
    title="EKSIR API",
    version="0.1.0",
    description="EKSIR — Security Operations Platform.",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

# ── Rate limiting (slowapi) ─────────────────────────────────────────────
# The Limiter instance lives in rate_limit.py so route modules can import
# it without circular dependency on this file. We just wire it onto the app
# here.
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402
from slowapi.middleware import SlowAPIMiddleware  # noqa: E402

from .rate_limit import limiter  # noqa: E402

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS: always allow the configured public origin; allow localhost origins only
# in a non-production posture (dev). Tightening the deployed origin is Stage 3a
# of the security-hardening feature.
_cors_common = dict(
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
_public_origin = settings.isoc_public_url.rstrip("/")
if settings.is_production:
    app.add_middleware(CORSMiddleware, allow_origins=[_public_origin], **_cors_common)
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[_public_origin],
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
        **_cors_common,
    )


# Defence-in-depth security headers on every API response. The edge Caddyfile
# sets the same set on the frontend + proxied API; this covers direct backend
# hits and keeps the headers unit-testable. setdefault() never clobbers a header
# a route set deliberately.
from .hardening import SECURITY_HEADERS  # noqa: E402


@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    return response


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe — the process is up. Cheap; called frequently by Docker."""
    return {"status": "ok", "service": "isoc-api", "version": app.version}


@app.get("/health/deep", tags=["meta"])
async def health_deep():
    """Readiness probe — verifies the backend can talk to every dependency.

    Returns 200 with per-dependency `{ok, latency_ms, error?}` if everything
    responds; returns 503 if any dependency is unreachable. Suitable for:
      • post-deploy smoke tests
      • external uptime monitors (Better Stack, UptimeRobot, Grafana synthetics)
      • a load-balancer readiness gate (don't route traffic until deps are up)

    More expensive than /health — don't call it every 5s.
    """
    import asyncio
    import time

    from fastapi.responses import JSONResponse

    results: dict[str, dict] = {}

    async def check_postgres() -> dict:
        from sqlalchemy import text

        from .db.session import _engine

        t0 = time.perf_counter()
        try:
            async with _engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return {"ok": True, "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}

    async def check_redis() -> dict:
        from arq.connections import create_pool

        from .queue import redis_settings

        t0 = time.perf_counter()
        try:
            pool = await create_pool(redis_settings())
            await pool.ping()
            await pool.aclose()
            return {"ok": True, "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}

    async def check_qdrant() -> dict:
        import httpx

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(f"{settings.qdrant_url}/healthz")
                r.raise_for_status()
            return {"ok": True, "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}

    # Run all three checks concurrently — total latency = slowest dep, not sum.
    pg, rd, qd = await asyncio.gather(check_postgres(), check_redis(), check_qdrant())
    results["postgres"] = pg
    results["redis"] = rd
    results["qdrant"] = qd

    all_ok = all(r["ok"] for r in results.values())
    payload = {
        "status": "ok" if all_ok else "degraded",
        "service": "isoc-api",
        "version": app.version,
        "checks": results,
    }
    return JSONResponse(payload, status_code=200 if all_ok else 503)


# Route registration happens here as modules are added in Pass 2.5.
def register_routes() -> None:
    from .routes import (
        admin,
        alerts,
        analytics,
        attack_graph,
        audit,
        auth,
        autonomy,
        batch_import,
        byok,
        cases,
        connectors,
        copilot,
        costs,
        customer_cases,
        dashboard,
        dashboard_layout,
        defenderactions,
        defenderops,
        easm,
        entities,
        exclusions,
        forensics,
        hunt,
        knowledge_base,
        mitre,
        mssp,
        notifications,
        performance,
        queue,
        rbac,
        reports,
        shifts,
        sla,
        threat_intel,
        v1actions,
        v1ops,
        webhooks,
    )

    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
    app.include_router(cases.router, prefix="/api/v1/incidents", tags=["incidents"])
    app.include_router(
        customer_cases.router, prefix="/api/v1/customer-cases", tags=["customer-cases"]
    )
    app.include_router(forensics.router, prefix="/api/v1/forensics", tags=["forensics"])
    app.include_router(threat_intel.router, prefix="/api/v1/threat-intel", tags=["threat-intel"])
    app.include_router(exclusions.router, prefix="/api/v1/exclusions", tags=["exclusions"])
    app.include_router(entities.router, prefix="/api/v1/entities", tags=["entities"])
    app.include_router(
        knowledge_base.router, prefix="/api/v1/knowledge-base", tags=["knowledge-base"]
    )
    app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])
    # /me/dashboard-layout + /admin/tenants/{id}/dashboard-layout — both kinds of
    # endpoint live in the same module to keep the C-option hierarchy in one place.
    app.include_router(dashboard_layout.router, prefix="/api/v1", tags=["dashboard"])
    app.include_router(mitre.router, prefix="/api/v1/mitre", tags=["mitre"])
    app.include_router(attack_graph.router, prefix="/api/v1/attack-graph", tags=["attack-graph"])
    app.include_router(mssp.router, prefix="/api/v1/mssp", tags=["mssp"])
    app.include_router(queue.router, prefix="/api/v1/queue", tags=["queue"])
    app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["analytics"])
    app.include_router(copilot.router, prefix="/api/v1/copilot", tags=["copilot"])
    app.include_router(autonomy.router, prefix="/api/v1/autonomy", tags=["autonomy"])
    app.include_router(rbac.router, prefix="/api/v1/rbac", tags=["rbac"])
    app.include_router(connectors.router, prefix="/api/v1/connectors", tags=["connectors"])
    app.include_router(batch_import.router, prefix="/api/v1/ingest", tags=["ingest"])
    app.include_router(hunt.router, prefix="/api/v1/hunt", tags=["hunt"])
    app.include_router(easm.router, prefix="/api/v1/easm", tags=["easm"])
    app.include_router(shifts.router, prefix="/api/v1/shifts", tags=["shifts"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
    app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["notifications"])
    app.include_router(sla.router, prefix="/api/v1/sla", tags=["sla"])
    app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])
    app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
    app.include_router(byok.router, prefix="/api/v1/admin/byok", tags=["byok"])
    app.include_router(costs.router, prefix="/api/v1/costs", tags=["costs"])
    app.include_router(performance.router, prefix="/api/v1/performance", tags=["performance"])
    app.include_router(v1actions.router, prefix="/api/v1/v1actions", tags=["v1actions"])
    app.include_router(v1ops.router, prefix="/api/v1/v1ops", tags=["v1ops"])
    app.include_router(
        defenderactions.router, prefix="/api/v1/defenderactions", tags=["defenderactions"]
    )
    app.include_router(defenderops.router, prefix="/api/v1/defenderops", tags=["defenderops"])
    # /v1/ingest is NOT under /api — webhook senders use a stable, version-stamped path.
    app.include_router(webhooks.router, prefix="/v1/ingest", tags=["ingest"])


# Routes register at import time in production; tests can call register_routes() lazily.
try:
    register_routes()
except ImportError as e:  # pragma: no cover
    logger.warning("routes.deferred", reason=str(e))
