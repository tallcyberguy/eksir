"""Attack Graph (3.15) — per-incident Attack Path tab.

A read-only reconstruction of one incident's kill chain, left→right, from the
already-committed L2 synthesis (`enrichment.stages.l2`). No schema, no LLM, no
graph DB — it reuses F4's `pipeline/mitre_map.py` for technique→tactic ordering
and names. (The aggregate MITRE coverage heatmap already ships at `/mitre`; this
adds only the per-incident path.) Pure `build_attack_path` is the test boundary.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, require_in_scope
from ..db.models import Incident, User
from ..db.session import get_session
from ..pipeline import mitre_map

router = APIRouter()


def build_attack_path(enrichment: dict | None) -> dict[str, Any]:
    """Enrichment blob → kill-chain path grouped by tactic, ordered by
    `mitre_map.TACTIC_ORDER`. Prefers the L2 `attack_chain` (carries per-step
    evidence); falls back to bare `mitre_techniques`. A technique is placed once,
    at its EARLIEST tactic; unknown techniques land in `unmapped`. `synthesized`
    is False (empty path) for short-circuited / auto-closed incidents."""
    l2 = ((enrichment or {}).get("stages") or {}).get("l2") or {}
    synthesized = bool(l2)

    chain = l2.get("attack_chain") or []
    if chain:
        raw = [
            (str(e.get("technique", "")).strip(), str(e.get("evidence", "") or ""))
            for e in chain
            if isinstance(e, dict)
        ]
    else:
        raw = [(str(t).strip(), "") for t in (l2.get("mitre_techniques") or [])]

    seen: set[str] = set()
    buckets: dict[str, list[dict]] = {}
    unmapped: list[dict] = []
    step = 0
    for tech, evidence in raw:
        if not tech:
            continue
        tid = mitre_map.parent_of(tech)
        if tid in seen:
            continue
        seen.add(tid)
        step += 1
        node = {
            "id": tid,
            "name": mitre_map.technique_name(tid) or tid,
            "evidence": evidence,
            "step": step,
        }
        tactics = mitre_map.tactics_for(tid)
        if not tactics:
            unmapped.append({"id": tid, "evidence": evidence})
            continue
        earliest = min(tactics, key=lambda ta: mitre_map.TACTIC_ORDER.get(ta, 99))
        buckets.setdefault(earliest, []).append(node)

    stages = [
        {
            "tactic_id": ta,
            "name": mitre_map.TACTIC_NAME.get(ta, ta),
            "order": mitre_map.TACTIC_ORDER.get(ta, 99),
            "techniques": buckets[ta],
        }
        for ta in sorted(buckets, key=lambda x: mitre_map.TACTIC_ORDER.get(x, 99))
    ]

    return {
        "synthesized": synthesized,
        "technique_count": len(seen),
        "tactic_count": len(stages),
        "stages": stages,
        "unmapped": unmapped,
    }


@router.get("/incident/{incident_id}")
async def incident_attack_path(
    incident_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
) -> dict[str, Any]:
    inc = await session.get(Incident, incident_id)
    if inc is None or inc.deleted_at is not None:
        raise HTTPException(404, "incident not found")
    require_in_scope(inc.tenant_id, scope)
    out = build_attack_path(inc.enrichment)
    out["incident_id"] = str(inc.id)
    return out
