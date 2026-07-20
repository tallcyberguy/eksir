"""Auto-tuning of exclusions (feature F8).

Learns candidate suppression rules from repeated analyst FP/Benign verdicts on
the SAME IOC for the SAME customer, and records them as `ExclusionSuggestion`
rows for human review. Nothing is ever auto-applied — an analyst approves a
suggestion into a real scoped `Exclusion` (see routes/exclusions.py).

Guardrails (so the system can never learn to silence a real threat):
  * Only IOCs of an exclusion-eligible type (ip / domain / hash) are tracked.
  * An IOC that EVER appeared in a TP incident is skipped (and any existing
    suggestion for it is retired).
  * An IOC that threat intel flagged malicious on THIS incident is skipped.

Promotion (surfacing in the review queue) requires corroboration:
  fp_count >= PROMOTE_MIN_FP across >= PROMOTE_MIN_RULES distinct rules.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.enums import Verdict
from ..db.models import ExclusionSuggestion, Incident, IOCRecord
from ..logging_config import get_logger

logger = get_logger("isoc.exclusions.autotune")

PROMOTE_MIN_FP = 3
PROMOTE_MIN_RULES = 2

# IOCRecord.ioc_type (IOCType value) → exclusion type. url/email collapse to
# their host/domain so a single domain rule covers them.
_TYPE_MAP = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "domain",
    "url": "domain",
    "email": "domain",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
}


def _host_of_url(url: str) -> str | None:
    try:
        after = url.split("://", 1)[1] if "://" in url else url
        host = after.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return host.split("@", 1)[-1].split(":", 1)[0].lower() or None
    except (IndexError, AttributeError):
        return None


def _eligible_value(ioc_type: str, value: str) -> tuple[str, str] | None:
    """Map an IOCRecord to (exclusion_type, normalized_value), or None if the
    type is not exclusion-eligible."""
    ex_type = _TYPE_MAP.get(ioc_type)
    if not ex_type or not value:
        return None
    if ioc_type == "url":
        host = _host_of_url(value)
        return ("domain", host) if host else None
    if ioc_type == "email":
        host = value.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in value else None
        return ("domain", host) if host else None
    return (ex_type, value.strip().lower() if ex_type == "hash" else value.strip())


def _malicious_values(enrichment: dict | None) -> set[str]:
    """Values this incident's enrichment flagged malicious — never suggest these."""
    out: set[str] = set()
    enrichment = enrichment or {}
    for m in enrichment.get("threat_intel_matches") or []:
        v = m.get("value")
        if v:
            out.add(str(v).lower())
    for r in enrichment.get("triage") or []:
        if str(r.get("verdict", "")).lower() == "malicious":
            for key in ("ioc", "value", "indicator"):
                v = r.get(key)
                if v:
                    out.add(str(v).lower())
    return out


def _confidence(fp_count: int, distinct_rules: int) -> int:
    """0–100 heuristic; saturates so a single noisy rule can't max it out."""
    return min(100, fp_count * 15 + distinct_rules * 15)


async def record_fp_verdict(session: AsyncSession, inc: Incident) -> None:
    """Hook: called when an analyst sets an FP/Benign verdict on `inc`.

    Best-effort and fully isolated — any failure is logged and swallowed so it
    can never block the verdict write.
    """
    try:
        if inc.verdict not in (Verdict.FP, Verdict.BENIGN):
            return

        rows = (
            await session.scalars(select(IOCRecord).where(IOCRecord.incident_id == inc.id))
        ).all()
        if not rows:
            return

        mal = _malicious_values(inc.enrichment)
        customer = inc.customer
        rule_name = inc.rule_name or "(unknown rule)"
        now = datetime.now(timezone.utc)

        # Dedupe eligible IOCs for this incident.
        eligible: dict[tuple[str, str], None] = {}
        for r in rows:
            mapped = _eligible_value(str(r.ioc_type), r.value)
            if not mapped:
                continue
            ex_type, val = mapped
            if val.lower() in mal:
                continue  # TI-malicious guardrail
            eligible[(ex_type, val)] = None

        for ex_type, val in eligible:
            # TP-history guardrail: if this value ever rode a TP, retire any
            # suggestion and skip.
            tp_count = await session.scalar(
                select(func.count())
                .select_from(IOCRecord)
                .join(Incident, Incident.id == IOCRecord.incident_id)
                .where(func.lower(IOCRecord.value) == val.lower())
                .where(Incident.verdict == Verdict.TP)
            )
            if tp_count and tp_count > 0:
                continue

            sug = await session.scalar(
                select(ExclusionSuggestion).where(
                    ExclusionSuggestion.value == val,
                    ExclusionSuggestion.ioc_type == ex_type,
                    ExclusionSuggestion.customer.is_(customer)
                    if customer is None
                    else ExclusionSuggestion.customer == customer,
                )
            )
            if sug is None:
                sug = ExclusionSuggestion(
                    value=val,
                    ioc_type=ex_type,
                    customer=customer,
                    fp_count=0,
                    seen_rules=[],
                    seen_incidents=[],
                    first_seen_at=now,
                    status="pending",
                )
                session.add(sug)
            elif sug.status == "dismissed":
                # Respect the analyst's prior dismissal — don't resurrect it.
                continue

            inc_id = str(inc.id)
            seen_incidents = list(sug.seen_incidents or [])
            if inc_id in seen_incidents:
                continue  # already counted this incident
            seen_incidents.append(inc_id)
            seen_rules = list(sug.seen_rules or [])
            if rule_name not in seen_rules:
                seen_rules.append(rule_name)

            sug.seen_incidents = seen_incidents
            sug.seen_rules = seen_rules
            sug.fp_count = (sug.fp_count or 0) + 1
            sug.last_rule_name = rule_name
            sug.last_seen_at = now
            sug.confidence = _confidence(sug.fp_count, len(seen_rules))

        logger.info(
            "autotune.recorded",
            incident_id=str(inc.id),
            customer=customer,
            eligible=len(eligible),
        )
    except Exception as e:  # never block the verdict write
        logger.warning("autotune.failed", incident_id=str(inc.id), error=str(e))


def is_promotable(sug: ExclusionSuggestion) -> bool:
    """Whether a suggestion has enough corroboration to surface for review."""
    return (
        sug.status == "pending"
        and (sug.fp_count or 0) >= PROMOTE_MIN_FP
        and len(sug.seen_rules or []) >= PROMOTE_MIN_RULES
    )
