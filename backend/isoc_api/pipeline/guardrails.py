"""Autonomy guardrails (3.9) — graduated *recommendation* per proposed action.

v1 is recommendation-ONLY. We annotate each `proposed_action` the manager built
with `{blast_radius, autonomy, autonomy_reason}` derived from a blast-radius
taxonomy crossed with the verdict confidence. Nothing here executes anything —
the analyst Approve gate stays the sole commit point. Effect/containment kinds
are HARD-clamped to `escalate` regardless of confidence or admin policy (defense
in depth); only read-only / no-effect kinds can ever be `auto`-eligible.

The pure core (`recommend` / `apply`) is the unit-test boundary; `load_policy`
is the only impure part (code-default ← YAML ← global-DB ← tenant-DB).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Code-default blast radius per action kind. Unknown kind → fail-safe `high`.
BLAST_RADIUS: dict[str, str] = {
    "blocklist_ioc": "high",
    "isolate_host": "critical",
    "disable_user": "critical",  # locks a person out of everything — high impact
    "scan_endpoint": "med",  # Defender AV scan — an endpoint action, but non-destructive
    "collect_file": "med",
    "tag": "read",
    "enrich": "read",
    "lookup": "read",
    "search": "read",
    "close_alert": "low",
}
DEFAULT_BLAST_RADIUS = "high"

# Containment/effect kinds — NEVER `auto`; always `escalate`, no matter the math.
EFFECT_KINDS = frozenset(
    {"blocklist_ioc", "isolate_host", "disable_user", "scan_endpoint", "collect_file"}
)

# Per-blast-radius confidence ladder: (auto, review, escalation) score floors.
# score ≥ auto → auto · ≥ review → review · else escalate. `auto = 1.01` makes
# auto unreachable (max confidence score is 0.9) — review/escalate only.
_DEFAULT_THRESHOLDS: dict[str, tuple[float, float, float]] = {
    "read": (0.0, 0.0, 0.0),  # read-only always auto-eligible
    "low": (0.6, 0.3, 0.0),
    "med": (0.9, 0.5, 0.0),
    "high": (1.01, 0.6, 0.0),
    "critical": (1.01, 0.8, 0.0),
}

PolicyMap = dict[str, dict[str, Any]]  # kind -> {blast_radius?, auto?, review?, escalation?, ...}


def confidence_to_score(c: str) -> float:
    """Coarse `AnalysisVerdict.confidence` → a score. Deliberately bucketed — no
    calibrated scorer is implied."""
    return {"high": 0.9, "medium": 0.6, "low": 0.3}.get(str(c or "").lower(), 0.3)


def classify_action(kind: str, policy: PolicyMap | None) -> str:
    pa = (policy or {}).get(kind)
    if pa and pa.get("blast_radius"):
        return str(pa["blast_radius"])
    return BLAST_RADIUS.get(kind, DEFAULT_BLAST_RADIUS)


def _thresholds_for(
    kind: str, blast_radius: str, policy: PolicyMap | None
) -> tuple[float, float, float]:
    pa = (policy or {}).get(kind)
    if pa and all(k in pa and pa[k] is not None for k in ("auto", "review", "escalation")):
        return float(pa["auto"]), float(pa["review"]), float(pa["escalation"])
    return _DEFAULT_THRESHOLDS.get(blast_radius, _DEFAULT_THRESHOLDS["high"])


def recommend(kind: str, confidence: str, policy: PolicyMap | None = None) -> dict[str, str]:
    """`{blast_radius, autonomy, reason}` for one action kind + verdict confidence."""
    br = classify_action(kind, policy)
    score = confidence_to_score(confidence)
    auto, review, _esc = _thresholds_for(kind, br, policy)

    if score >= auto:
        decision = "auto"
    elif score >= review:
        decision = "review"
    else:
        decision = "escalate"

    # Hard invariant: containment is always analyst-gated.
    if kind in EFFECT_KINDS:
        decision = "escalate"
        reason = f"containment ({br}) — always analyst-gated"
    elif decision == "auto":
        reason = f"{br} · confidence {confidence} → auto-eligible"
    elif decision == "review":
        reason = f"{br} · confidence {confidence} → review"
    else:
        reason = f"{br} · confidence {confidence} → escalate"

    return {"blast_radius": br, "autonomy": decision, "reason": reason}


def apply(actions: list[dict], confidence: str, policy: PolicyMap | None = None) -> list[dict]:
    """Annotate each proposed-action dict with blast_radius / autonomy /
    autonomy_reason. Pure — copies each dict, never mutates the input, preserves
    all existing keys."""
    out = []
    for a in actions or []:
        rec = recommend(str(a.get("kind", "")), confidence, policy)
        out.append(
            {
                **a,
                "blast_radius": rec["blast_radius"],
                "autonomy": rec["autonomy"],
                "autonomy_reason": rec["reason"],
            }
        )
    return out


# ── Effective-policy view (pure builder for the admin editor) ────────────────

KNOWN_KINDS = list(BLAST_RADIUS.keys())


def _row_override(row: dict) -> dict:
    return {
        "blast_radius": row.get("blast_radius"),
        "auto": row.get("auto_confidence"),
        "review": row.get("review_confidence"),
        "escalation": row.get("escalation_confidence"),
        "reason": row.get("reason"),
        "source": row.get("source"),  # 'default' (seeded) | 'db' (edited)
    }


def build_effective_policy(
    *,
    yaml_map: dict[str, dict] | None = None,
    global_rows: list[dict] | None = None,
    tenant_rows: list[dict] | None = None,
) -> dict[str, Any]:
    """Merge code ← YAML ← global-DB ← tenant-DB into a per-kind display view.
    Pure + unit-tested; the route supplies the DB rows."""
    yaml_map = yaml_map or {}
    g = {r["action_kind"]: r for r in (global_rows or [])}
    t = {r["action_kind"]: r for r in (tenant_rows or [])}

    actions: dict[str, dict] = {}
    for kind in KNOWN_KINDS:
        br = BLAST_RADIUS[kind]
        auto, review, esc = _DEFAULT_THRESHOLDS[br]
        eff = {
            "blast_radius": br,
            "auto": auto,
            "review": review,
            "escalation": esc,
            "source": "code",
            "reason": None,
            "is_effect": kind in EFFECT_KINDS,
        }
        for src, layer in (
            ("yaml", yaml_map.get(kind)),
            ("global", g.get(kind)),
            ("tenant", t.get(kind)),
        ):
            if not layer:
                continue
            ov = _row_override(layer) if src != "yaml" else layer
            if not ov:
                continue
            for k in ("blast_radius", "auto", "review", "escalation", "reason"):
                if ov.get(k) is not None:
                    eff[k] = ov[k]
            # DB layers carry their own source label ('default' seeded vs 'db' edited);
            # YAML/global/tenant otherwise use the layer name.
            eff["source"] = ov.get("source") or src if src != "yaml" else "yaml"
        actions[kind] = eff

    return {"actions": actions, "defaults": {br: list(v) for br, v in _DEFAULT_THRESHOLDS.items()}}


# ── Impure: 3-layer policy loader for the orchestrator ───────────────────────


def _load_yaml_policy(path: str) -> dict[str, dict]:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        import yaml  # lazy — optional dep path

        data = yaml.safe_load(p.read_text()) or {}
        actions = data.get("actions") if isinstance(data, dict) else None
        return actions if isinstance(actions, dict) else {}
    except Exception:
        return {}


async def load_policy(session: Any, tenant_id: Any) -> PolicyMap:
    """code-default (implicit) ← YAML ← global-DB ← tenant-DB. Returns only the
    OVERRIDES; `recommend` falls back to code defaults for unlisted kinds."""
    from ..settings import settings

    policy: PolicyMap = {}
    policy.update(_load_yaml_policy(getattr(settings, "isoc_autonomy_policy", "") or ""))

    try:
        from sqlalchemy import or_, select

        from ..db.models import AutonomyThreshold

        rows = (
            (
                await session.execute(
                    select(AutonomyThreshold).where(
                        or_(
                            AutonomyThreshold.tenant_id.is_(None),
                            AutonomyThreshold.tenant_id == tenant_id,
                        )
                    )
                )
            )
            .scalars()
            .all()
        )
        # Global first, tenant-specific second so the tenant override wins.
        for r in sorted(rows, key=lambda x: x.tenant_id is not None):
            policy[r.action_kind] = {
                "blast_radius": r.blast_radius,
                "auto": r.auto_confidence,
                "review": r.review_confidence,
                "escalation": r.escalation_confidence,
            }
    except Exception:
        pass  # DB unavailable / table missing → fall back to code+YAML defaults

    return policy
