"""Knowledge-base management — runbooks, allowlists, asset inventory, incident
reports that the RAG pipeline retrieves at enrichment time (store_adapter.search_kb).

Reads are open to any authenticated user. Mutations are admin-only — KB content
is platform knowledge that shapes every customer's analysis.

Entries live in the Qdrant `knowledge_base_v2` collection (bge-m3 dense + sparse).
This is the first feeder for that collection; previously it could only be read.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..adapters import store_adapter
from ..auth.deps import current_user, require_admin
from ..db.models import User
from ..db.session import get_session

router = APIRouter()

_VALID_TYPES = ("runbook", "allowlist", "asset_inventory", "incident_report")


class KBEntryCreate(BaseModel):
    type: str
    title: str
    content: str
    customer: str | None = None
    rule_name: str | None = None
    tags: list[str] | None = None


def _validate(body: KBEntryCreate) -> None:
    if body.type not in _VALID_TYPES:
        raise HTTPException(400, f"type must be one of: {', '.join(_VALID_TYPES)}")
    if not (body.title or "").strip():
        raise HTTPException(400, "title cannot be empty")
    if not (body.content or "").strip():
        raise HTTPException(400, "content cannot be empty")


@router.get("")
async def list_entries(
    _user: Annotated[User, Depends(current_user)],
    customer: str | None = Query(None),
    type: str | None = Query(None, description="filter by entry type"),
    limit: int = Query(200, ge=1, le=1000),
) -> dict:
    try:
        items = await store_adapter.list_kb(customer=customer, kb_type=type, limit=limit)
    except Exception as e:
        raise HTTPException(503, f"knowledge base unavailable: {str(e)[:200]}")
    return {"total": len(items), "items": items}


@router.get("/search")
async def search_entries(
    _user: Annotated[User, Depends(current_user)],
    q: str = Query(..., min_length=2, description="semantic query (tests retrieval)"),
    customer: str | None = Query(None),
    rule_name: str | None = Query(None),
    top_k: int = Query(5, ge=1, le=20),
) -> dict:
    """Preview what the pipeline would retrieve for a query — handy for testing
    that a freshly-added runbook is findable."""
    try:
        hits = await store_adapter.search_kb(q, customer, rule_name, top_k=top_k)
    except Exception as e:
        raise HTTPException(503, f"knowledge base search failed: {str(e)[:200]}")
    return {"total": len(hits), "items": hits}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_entry(
    body: KBEntryCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> dict:
    _validate(body)
    entry = {
        "type": body.type,
        "title": body.title.strip(),
        "content": body.content.strip(),
        "customer": (body.customer or None),
        "rule_name": (body.rule_name or None),
        "tags": [t.strip() for t in (body.tags or []) if t.strip()],
    }
    try:
        kb_id = await store_adapter.index_kb_entry(entry)
    except Exception as e:
        raise HTTPException(503, f"failed to index KB entry: {str(e)[:200]}")
    await audit.log(
        session,
        user_id=user.id,
        action="kb.create",
        target_type="knowledge_base",
        diff={"kb_id": kb_id, "type": body.type, "title": body.title, "customer": body.customer},
    )
    return {"status": "created", "kb_id": kb_id, **entry}


@router.delete("/{kb_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_entry(
    kb_id: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_admin)],
) -> None:
    try:
        await store_adapter.delete_kb(kb_id)
    except Exception as e:
        raise HTTPException(503, f"failed to delete KB entry: {str(e)[:200]}")
    await audit.log(
        session,
        user_id=user.id,
        action="kb.delete",
        target_type="knowledge_base",
        diff={"kb_id": kb_id},
    )
