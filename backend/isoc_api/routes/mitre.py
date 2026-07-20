"""MITRE ATT&CK Coverage — tactic × technique density derived from incident verdicts.

The L2 persona emits `mitre_techniques` per incident; F4's `pipeline/mitre_map.py`
buckets those raw IDs into the 14 Enterprise tactics (sub-techniques roll up to
their parent). This endpoint runs the scoped query and feeds the per-incident
technique lists into the pure, unit-tested `aggregate_coverage` — no new schema.

Coverage answers "which ATT&CK techniques has our SOC actually encountered". The
default counts only **true-positive** incidents (real findings); `confirmed_only=
false` widens to every analyzed incident except those adjudicated FP/benign.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..auth.tenancy import TenantScope, current_tenant_scope, scope_clause_for_incidents
from ..db.enums import Verdict
from ..db.models import Incident, User
from ..db.session import get_session
from ..pipeline import mitre_map

router = APIRouter()


def build_coverage(
    enrichments: list[dict | None], *, window_days: int, confirmed_only: bool
) -> dict[str, Any]:
    """Pure: per-incident enrichment blobs → F4 coverage structure + view meta.

    `enrichments` is one incident's `enrichment` JSON per element; the verdict
    filtering happens in the query, so every blob passed here already counts.
    """
    incident_techniques = [mitre_map.extract_techniques(e) for e in enrichments]
    out = mitre_map.aggregate_coverage(incident_techniques)
    out["window_days"] = window_days
    out["confirmed_only"] = confirmed_only
    out["tactic_count"] = len(mitre_map.TACTICS)
    out["covered_tactic_count"] = sum(1 for t in out["tactics"] if t["technique_count"] > 0)
    return out


@router.get("/coverage")
async def mitre_coverage(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(current_user)],
    scope: Annotated[TenantScope, Depends(current_tenant_scope)],
    window_days: int = Query(default=90, ge=1, le=365),
    confirmed_only: bool = Query(default=True),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)
    scope_w = scope_clause_for_incidents(scope)

    conds = [
        Incident.created_at >= cutoff,
        Incident.deleted_at.is_(None),
        Incident.enrichment.is_not(None),
        scope_w,
    ]
    if confirmed_only:
        # Coverage = techniques confirmed in true-positive incidents.
        conds.append(Incident.verdict == Verdict.TP)
    else:
        # Everything analyzed except proven-not-a-threat (FP / benign).
        conds.append(Incident.verdict.notin_([Verdict.FP, Verdict.BENIGN]))

    rows = (await session.execute(select(Incident.enrichment).where(*conds))).all()

    out = build_coverage(
        [r.enrichment for r in rows], window_days=window_days, confirmed_only=confirmed_only
    )
    out["generated_at"] = now.isoformat()
    return out
