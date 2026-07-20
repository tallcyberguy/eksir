"""AI Copilot (3.8) — read-only contextual assistant endpoints.

`/ask` runs a single-shot, read-only LLM action (summarize / next-steps /
explain). It NEVER writes a verdict, proposal, or response action — the analyst
gate stays the sole commit point. The F3 egress contract runs inside
`complete()`, so a blocked response surfaces as `status="blocked"`.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, require_in_scope
from ..db.models import Incident, User
from ..db.session import get_session
from ..llm import contextual
from ..llm.client import complete, request_tenant
from ..llm.config_store import get_llm_config

router = APIRouter()


@router.get("/status")
async def status(_user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
    """Demo-mode badge: is an LLM configured in the admin DB config? (The call
    itself still falls back to env defaults — this only drives the honest badge.)"""
    cfg = await get_llm_config()
    return {"configured": cfg is not None}


@router.get("/actions")
async def actions(_user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
    return {"actions": contextual.available_actions()}


class AskIn(BaseModel):
    action: str
    incident_id: uuid.UUID | None = None
    question: str | None = None


def _proposed_action_kinds(enrichment: dict) -> list[str]:
    out: list[str] = []
    for a in (enrichment.get("proposed_actions") or [])[:8]:
        if isinstance(a, dict):
            out.append(str(a.get("kind") or a.get("type") or a.get("label") or "action"))
        else:
            out.append(str(a))
    return out


@router.post("/ask")
async def ask(
    body: AskIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    inc: Incident | None = None
    incident_ctx: str | None = None
    if body.incident_id is not None:
        inc = await session.get(Incident, body.incident_id)
        if inc is None or inc.deleted_at is not None:
            raise HTTPException(404, "incident not found")
        require_in_scope(inc.tenant_id, scope)
        enr = inc.enrichment or {}
        l2 = (enr.get("stages") or {}).get("l2") or {}
        incident_ctx = contextual.incident_context(
            case_number=inc.case_number,
            title=inc.title,
            severity=inc.severity,
            verdict=inc.verdict,
            report=inc.llm_report_markdown,
            proposed_actions=_proposed_action_kinds(enr),
            ti_band=(enr.get("threat_intel_score") or {}).get("band"),
            mitre=l2.get("mitre_techniques"),
        )

    try:
        system, user = contextual.build_prompt(
            body.action, incident_ctx=incident_ctx, question=body.question
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    # Bind tenant for BYOK key resolution when the action is incident-scoped.
    tok = request_tenant.set(inc.tenant_id) if inc is not None else None
    try:
        result = await complete(system=system, user=user, max_tokens=900, temperature=0.2)
    finally:
        if tok is not None:
            request_tenant.reset(tok)

    session.add(contextual.copilot_call_row(result, incident_id=inc.id if inc else None))
    return {
        "answer": result.text,
        "model": result.model,
        "status": result.status,
        "blocked": result.status == "blocked",
    }
