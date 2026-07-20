"""Connectors framework (3.11) — register-only catalog + status + test.

Builds on the existing per-customer credential store (`Integration` table +
`integration_store`). Adds the framework layer: a self-describing catalog (drives
dynamic forms + capability badges) and a test-connection action. Credential
create/edit/delete stays in the admin integrations endpoints; this exposes the
catalog, the configured connectors enriched with capability metadata, and a test.
Admin-only. No response action fires here — test-connection is read-only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters import integration_store, parser_adapter
from ..adapters.connectors import health, registry
from ..adapters.ingest import get_adapter as get_ingest_adapter
from ..auth.deps import require_admin
from ..db.models import IngestSourceConfig, Integration, User
from ..db.session import get_session
from ..pipeline import ingest_sources as ingest_helper
from ..queue import get_arq
from ..settings import settings

router = APIRouter()

_SEVERITY_WORDS = {"low", "medium", "high", "critical"}


def build_connector_list(integrations: list[dict]) -> dict[str, Any]:
    """Pure: merge configured integration rows with their catalog spec (label,
    category, capabilities, adapter_status). Sorted by category then provider."""
    cat = {c["key"]: c for c in registry.catalog()}
    rows = []
    for it in integrations:
        spec = cat.get(it["provider"], {})
        rows.append(
            {
                **it,
                "label_catalog": spec.get("label", it["provider"]),
                "category": spec.get("category"),
                "capabilities": spec.get("capabilities", []),
                "adapter_status": spec.get("adapter_status", "planned"),
            }
        )
    rows.sort(key=lambda r: (r.get("category") or "zzz", r["provider"], r["identifier"]))
    return {"connectors": rows, "catalog": registry.catalog()}


@router.get("/catalog")
async def catalog(_admin: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    return {"connectors": registry.catalog()}


@router.get("")
async def list_connectors(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    rows = (await session.scalars(select(Integration))).all()
    integrations = [
        {
            "id": str(r.id),
            "provider": r.provider,
            "identifier": r.identifier,
            "label": r.label,
            "enabled": r.enabled,
            "region": r.region,
            "base_url": r.base_url,
            "has_key": bool(r.api_key_encrypted),
        }
        for r in rows
    ]
    return build_connector_list(integrations)


@router.post("/{integration_id}/test")
async def test_connector(
    integration_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    inc = await session.get(Integration, integration_id)
    if inc is None:
        raise HTTPException(404, "connector not found")
    creds = await integration_store.get_creds(inc.provider, inc.identifier)
    if creds is None:
        raise HTTPException(400, "no usable credentials for this connector")
    result = await health.test_connection(inc.provider, creds)
    await audit.log(
        session,
        user_id=admin.id,
        action="connector.test",
        target_type="integration",
        target_id=integration_id,
        diff={"provider": inc.provider, "status": result.get("status")},
    )
    return result


# ── Pull ingestion sources (scheduled console poll) ─────────────────────
class SourceCreate(BaseModel):
    provider: str
    identifier: str = "default"
    customer: str | None = None
    interval_seconds: int = Field(300, ge=30, le=86400)
    min_severity: str | None = None
    max_items: int = Field(100, ge=1, le=1000)
    enabled: bool = False
    # Config-driven mapping for sources without a bespoke parser:
    # {normalized_field: dotted.path.into.raw}. None = use the bespoke parser.
    field_map: dict[str, str] | None = None


class SourceUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(None, ge=30, le=86400)
    min_severity: str | None = None
    max_items: int | None = Field(None, ge=1, le=1000)
    customer: str | None = None
    field_map: dict[str, str] | None = None


class PreviewRequest(BaseModel):
    raw: Any  # a pasted alert — text or a JSON object
    customer: str | None = None
    field_map: dict[str, str] | None = None  # test a mapping before saving it


def pullable_catalog() -> list[dict]:
    """Pure: catalog entries that have a live pull-ingestion adapter registered."""
    return [c for c in registry.catalog() if get_ingest_adapter(c["key"]) is not None]


def source_dict(row: IngestSourceConfig, *, now: datetime | None = None) -> dict[str, Any]:
    """Serialize an ingest source row (incl. metrics + computed health) for the UI."""
    spec = registry.get_spec(row.provider)
    now = now or datetime.now(timezone.utc)
    health = ingest_helper.source_health(
        enabled=row.enabled,
        interval_seconds=row.interval_seconds,
        consecutive_errors=row.consecutive_errors,
        last_success_at=row.last_success_at,
        now=now,
    )
    return {
        "id": str(row.id),
        "provider": row.provider,
        "label": spec.label if spec else row.provider,
        "identifier": row.identifier,
        "customer": row.customer,
        "enabled": row.enabled,
        "interval_seconds": row.interval_seconds,
        "min_severity": row.min_severity,
        "max_items": row.max_items,
        "consecutive_errors": row.consecutive_errors,
        "last_error": row.last_error,
        "field_map": row.field_map,
        "health": health,
        "stale": health == "stale",
        "last_poll_ms": row.last_poll_ms,
        "last_poll_count": row.last_poll_count,
        "total_ingested": row.total_ingested,
        "last_poll_at": row.last_poll_at.isoformat() if row.last_poll_at else None,
        "last_success_at": row.last_success_at.isoformat() if row.last_success_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _validate_source_provider(provider: str) -> None:
    if get_ingest_adapter(provider) is None:
        raise HTTPException(400, f"provider '{provider}' has no pull-ingestion adapter")


def _validate_min_severity(min_severity: str | None) -> None:
    if min_severity is not None and min_severity.lower() not in _SEVERITY_WORDS:
        raise HTTPException(400, f"min_severity must be one of {sorted(_SEVERITY_WORDS)}")


async def _creds_present(provider: str, identifier: str) -> bool:
    """True if usable credentials resolve for (provider, identifier) — a saved
    Connectors row or (Vision One) the env fallback. Mirrors the cron's lookup."""
    if provider == "vision_one":
        return await integration_store.get_creds_v1(identifier) is not None
    return await integration_store.get_creds(provider, identifier) is not None


@router.get("/sources/providers")
async def source_providers(_admin: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    """Catalog entries selectable as a pull source (those with a live adapter)."""
    return {"providers": pullable_catalog()}


@router.get("/sources")
async def list_sources(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    rows = (
        await session.scalars(
            select(IngestSourceConfig).order_by(
                IngestSourceConfig.provider, IngestSourceConfig.identifier
            )
        )
    ).all()
    # `polling_enabled` reflects the server-side master switch so the UI can warn
    # when sources are configured but the cron won't actually poll.
    return {
        "sources": [source_dict(r) for r in rows],
        "polling_enabled": settings.pull_ingest_enabled,
    }


@router.post("/sources", status_code=201)
async def create_source(
    body: SourceCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    _validate_source_provider(body.provider)
    _validate_min_severity(body.min_severity)

    existing = await session.scalar(
        select(IngestSourceConfig).where(
            IngestSourceConfig.provider == body.provider,
            IngestSourceConfig.identifier == body.identifier,
        )
    )
    if existing is not None:
        raise HTTPException(409, "a source for this provider + identifier already exists")

    row = IngestSourceConfig(
        provider=body.provider,
        identifier=body.identifier,
        customer=body.customer,
        interval_seconds=body.interval_seconds,
        min_severity=(body.min_severity.lower() if body.min_severity else None),
        max_items=body.max_items,
        enabled=body.enabled,
        field_map=body.field_map,
    )
    session.add(row)
    await session.flush()
    await audit.log(
        session,
        user_id=admin.id,
        action="ingest_source.create",
        target_type="ingest_source",
        target_id=row.id,
        diff={"provider": row.provider, "identifier": row.identifier, "enabled": row.enabled},
    )
    await session.commit()
    # Immediate feedback: does this source actually have credentials to use?
    result = source_dict(row)
    result["credentials_found"] = await _creds_present(body.provider, body.identifier)
    return result


@router.patch("/sources/{source_id}")
async def update_source(
    source_id: uuid.UUID,
    body: SourceUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    row = await session.get(IngestSourceConfig, source_id)
    if row is None:
        raise HTTPException(404, "source not found")
    _validate_min_severity(body.min_severity)

    fields = body.model_dump(exclude_unset=True)
    if "min_severity" in fields and fields["min_severity"]:
        fields["min_severity"] = fields["min_severity"].lower()
    for key, value in fields.items():
        setattr(row, key, value)
    await audit.log(
        session,
        user_id=admin.id,
        action="ingest_source.update",
        target_type="ingest_source",
        target_id=row.id,
        diff=fields,
    )
    await session.commit()
    return source_dict(row)


@router.delete("/sources/{source_id}", status_code=204)
async def delete_source(
    source_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> None:
    row = await session.get(IngestSourceConfig, source_id)
    if row is None:
        raise HTTPException(404, "source not found")
    await audit.log(
        session,
        user_id=admin.id,
        action="ingest_source.delete",
        target_type="ingest_source",
        target_id=row.id,
        diff={"provider": row.provider, "identifier": row.identifier},
    )
    await session.delete(row)
    await session.commit()


@router.post("/sources/{source_id}/poll-now")
async def poll_source_now(
    source_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    arq: Annotated[ArqRedis, Depends(get_arq)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Force one immediate poll of a source on the next cron tick (within ~60s).

    Sets a short-lived Redis flag the `pull_ingest` cron consumes; does not
    ingest inline, so the analyst gate and the deterministic path are unchanged.
    """
    row = await session.get(IngestSourceConfig, source_id)
    if row is None:
        raise HTTPException(404, "source not found")
    if not row.enabled:
        raise HTTPException(400, "source is disabled — enable it before polling")
    await arq.set(ingest_helper.pollnow_key(source_id), "1", ex=300)
    await audit.log(
        session,
        user_id=admin.id,
        action="ingest_source.poll_now",
        target_type="ingest_source",
        target_id=source_id,
        diff={"provider": row.provider},
    )
    await session.commit()
    return {"queued": True}


@router.post("/sources/preview")
async def preview_source(
    body: PreviewRequest,
    _admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Read-only: normalize a pasted sample alert without creating an incident.

    Lets an admin verify a source's parser/field mapping before enabling it live.
    """
    detected = parser_adapter.detect_source(body.raw)
    normalized = parser_adapter.parse_to_normalized(
        body.raw, customer=body.customer, field_map=body.field_map
    )
    return {"detected_source": detected, "normalized": normalized}
