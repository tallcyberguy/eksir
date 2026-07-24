"""Deterministic routing for the agent-persona pipeline.

Ports config/routing.yaml from agentic-soc: LLMs decide verdicts, CODE decides
flow. These are pure functions over the typed stage contracts so they're trivial
to unit-test. Tune thresholds here without touching persona prompts.

Source of truth mirrored: agentic-soc/config/routing.yaml (escalate_to_l2_if_any,
hunt_if, forensics_if_any).
"""

from __future__ import annotations

from typing import Any

from .contracts import AnalysisVerdict, HuntDecision, HuntResult, ProposedAction, TriageResult

# escalate_to_l2_if_any → threat_category in [...]
ESCALATE_THREAT_CATEGORIES = {
    "ransomware",
    "c2",
    "lateral",
    "exploit",
    "malware",
    "execution",
    "defense_evasion",
}

# isoc IOCType value → Trend Micro Vision One blocklist ioc_type
_V1_IOC_TYPE = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "sha256": "fileSha256",
    "sha1": "fileSha1",
    "email": "senderMailAddress",
}


def _triage_rows(enrichment: dict[str, Any]) -> list[dict]:
    return list(enrichment.get("triage") or [])


# Hash-type IOCs whose triage came back with one of these verdicts are UNKNOWN to
# threat intel — no source (VT/MalwareBazaar/ThreatFox) has ever seen the file.
# (`clean_or_unknown` = found in NO source; a benign file VT has seen returns
# `suspicious`.) That's the signal to collect the actual binary for analysis.
_UNKNOWN_HASH_VERDICTS = {"clean_or_unknown", "unknown"}
_HASH_TYPES = {"sha256", "sha1", "md5"}


def _row_ioc_type(r: dict) -> str:
    q = r.get("query") or {}
    raw = (q.get("type") if isinstance(q, dict) else None) or r.get("type")
    return str(raw or "").lower()


def has_unknown_file_hash(enrichment: dict[str, Any]) -> bool:
    """True if any file-hash IOC is unknown to threat intel (candidate to collect).

    A hash TI already knows — malicious or otherwise — is NOT a collect candidate:
    if it's malicious we block it; if TI has ever seen it we already know what it
    is. Only a genuinely-unknown file is worth pulling off the endpoint.
    """
    for r in _triage_rows(enrichment):
        if _row_ioc_type(r) not in _HASH_TYPES:
            continue
        if str(r.get("verdict", "")).lower() in _UNKNOWN_HASH_VERDICTS:
            return True
    return False


def _v1_host_guid(enrichment: dict[str, Any]) -> str | None:
    """The affected host's agentGuid from the V1 workbench enrichment, if present.
    Preferred over the hostname for collect_file (required on FedRAMP tenants)."""
    wb = (enrichment.get("v1") or {}).get("workbench") or {}
    for e in (wb.get("impactScope") or {}).get("entities") or []:
        if e.get("type") == "host":
            v = e.get("value")
            if isinstance(v, dict) and v.get("guid"):
                return str(v["guid"])
    return None


def any_malicious_ioc(enrichment: dict[str, Any]) -> bool:
    """True if deterministic enrichment flagged any indicator malicious."""
    for r in _triage_rows(enrichment):
        if str(r.get("verdict", "")).lower() == "malicious":
            return True
    # A local threat-intel feed match is also a malicious signal.
    return bool(enrichment.get("threat_intel_matches"))


def should_escalate_to_l2(
    triage: TriageResult,
    enrichment: dict[str, Any],
    severity_label: str | None,
    threat_category: str | None,
) -> bool:
    """routing.yaml: escalate_to_l2_if_any."""
    if triage.obvious_disposition != "likely_fp":
        return True
    if any_malicious_ioc(enrichment):
        return True
    if (severity_label or "").lower() in ("high", "critical"):
        return True
    if (threat_category or "").lower() in ESCALATE_THREAT_CATEGORIES:
        return True
    return False


def should_hunt(l2: AnalysisVerdict) -> bool:
    """routing.yaml: hunt_if (l2_verdict == true_positive AND hunt_recommended).

    Back-compat shim retained during migration; new call sites use `decide_hunt`.
    """
    return l2.verdict == "true_positive" and bool(l2.hunt_recommended)


# Endpoint criticality / user-risk levels that, on a confirmed TP, warrant a hunt
# even when L2 did not tick hunt_recommended (ADR-0009 D5: the model cannot veto a
# hunt on a confirmed-critical asset). These come from the pre-L2 Microsoft
# enrichment (BUILD-PLAN-ADR-0009 PR-1/2/3 -> enrichment["ms"]); until that lands
# the keys are absent and decide_hunt degrades to L2's recommendation plus the
# malicious-IOC corroboration already computed by deterministic enrichment.
_HUNT_CRITICALITY = {"high", "critical"}
_HUNT_USER_RISK = {"high"}


def _ms_endpoint_criticality(enrichment: dict[str, Any]) -> str | None:
    ep = (enrichment.get("ms") or {}).get("endpoint") or {}
    val = ep.get("criticality")
    return str(val).lower() if val else None


def _ms_user_risk(enrichment: dict[str, Any]) -> str | None:
    ident = (enrichment.get("ms") or {}).get("identity") or {}
    val = ident.get("risk_level")
    return str(val).lower() if val else None


def decide_hunt(l2: AnalysisVerdict, enrichment: dict[str, Any]) -> HuntDecision:
    """Manager-owned hunt decision (ADR-0009 D5). On a confirmed true positive a
    hunt is warranted when L2 recommends it OR a hard signal demands it (a
    malicious indicator, a high-criticality host, or a high-risk user), so the
    model cannot veto a hunt on a confirmed critical. Returns run/focus/reason;
    the operator runs the live hunt at the gate. Supersedes `should_hunt`.
    """
    if (l2.verdict or "").lower() != "true_positive":
        return HuntDecision(run=False, focus=l2.hunt_focus, reason="verdict is not a true positive")

    reasons: list[str] = []
    if l2.hunt_recommended:
        reasons.append("L2 recommended a hunt")
    if any_malicious_ioc(enrichment):
        reasons.append("enrichment flagged a malicious indicator")
    crit = _ms_endpoint_criticality(enrichment)
    if crit in _HUNT_CRITICALITY:
        reasons.append(f"impacted host criticality is {crit}")
    if _ms_user_risk(enrichment) in _HUNT_USER_RISK:
        reasons.append("impacted user is flagged high-risk")

    return HuntDecision(
        run=bool(reasons),
        focus=l2.hunt_focus,
        reason="; ".join(reasons) if reasons else "confirmed TP but no hunt signal",
    )


def should_run_forensics(l2: AnalysisVerdict, hunt: HuntResult | None) -> bool:
    """routing.yaml: forensics_if_any (L2 inconclusive OR hunt found lateral spread)."""
    if l2.verdict == "inconclusive":
        return True
    if hunt is not None and hunt.spread_assessment == "lateral_confirmed":
        return True
    return False


def map_verdict_to_isoc(l2_verdict: str) -> str:
    """agentic-soc persona verdict → isoc Verdict value (TP/FP/benign/inconclusive)."""
    return {
        "true_positive": "TP",
        "false_positive": "FP",
        "benign": "benign",
        "inconclusive": "inconclusive",
    }.get((l2_verdict or "").lower(), "pending")


def propose_response_actions(
    l2: AnalysisVerdict,
    enrichment: dict[str, Any],
    normalized: dict[str, Any],
) -> list[ProposedAction]:
    """Build PROPOSED response actions (never executed here). Only on a TP.

    Provider-routed: a microsoft_defender incident gets Defender containment
    proposals; every other source keeps the Vision One proposals.
    """
    if l2.verdict != "true_positive":
        return []
    if normalized.get("source_product") == "microsoft_defender":
        return _propose_defender_actions(l2, enrichment, normalized)
    return _propose_v1_actions(l2, enrichment, normalized)


# raw IOC type -> Defender custom-indicator type (Ti.ReadWrite blocklist).
_DEFENDER_IOC_TYPE = {
    "ipv4": "IpAddress",
    "ipv6": "IpAddress",
    "ip": "IpAddress",
    "domain": "DomainName",
    "url": "Url",
    "sha256": "FileSha256",
    "sha1": "FileSha1",
}


def _propose_defender_actions(
    l2: AnalysisVerdict, enrichment: dict[str, Any], normalized: dict[str, Any]
) -> list[ProposedAction]:
    """Defender for Endpoint proposals. Scan/isolate need the MDE device id, which only
    endpoint alerts carry (deviceEvidence); blocklist works off malicious IOCs. An email/MDO
    alert with no device and no malicious IOC yields nothing."""
    from ..adapters import ocsf_defender

    actions: list[ProposedAction] = []
    idx = 0
    machine_id = ocsf_defender.mde_device_id(normalized.get("raw"))
    if machine_id:
        # AV scan — low-risk, useful for any confirmed-TP endpoint.
        actions.append(
            ProposedAction(
                id=f"act{idx}",
                kind="scan_endpoint",
                provider="microsoft_defender",
                params={"machine_id": machine_id},
                justification=f"Confirmed TP on device {machine_id}; run an antivirus scan",
            )
        )
        idx += 1
        # Isolate — stronger containment, only for spread/persistence/c2 signals.
        if l2.hunt_focus in ("lateral_movement", "persistence", "c2"):
            actions.append(
                ProposedAction(
                    id=f"act{idx}",
                    kind="isolate_host",
                    provider="microsoft_defender",
                    params={"machine_id": machine_id},
                    justification=(
                        f"Confirmed TP on device {machine_id} with {l2.hunt_focus} signal; "
                        "isolate to contain"
                    ),
                )
            )
            idx += 1
    # Disable a compromised Entra user (identity containment) — needs a Graph-addressable
    # user id + a strong active-compromise signal.
    user_id = ocsf_defender.entra_user_id(normalized.get("raw"))
    if user_id and l2.hunt_focus in ("lateral_movement", "persistence", "c2"):
        actions.append(
            ProposedAction(
                id=f"act{idx}",
                kind="disable_user",
                provider="microsoft_defender",
                params={"user_id": user_id},
                justification=(
                    f"Confirmed TP with {l2.hunt_focus} signal; disable compromised user {user_id}"
                ),
            )
        )
        idx += 1
    # Blocklist each malicious IOC as a custom Defender indicator (Ti.ReadWrite).
    for r in _triage_rows(enrichment):
        if str(r.get("verdict", "")).lower() != "malicious":
            continue
        q = r.get("query") or {}
        value = q.get("ioc") if isinstance(q, dict) else q
        raw_type = (q.get("type") if isinstance(q, dict) else None) or r.get("type")
        ind_type = _DEFENDER_IOC_TYPE.get(str(raw_type or "").lower())
        if not value or not ind_type:
            continue
        actions.append(
            ProposedAction(
                id=f"act{idx}",
                kind="blocklist_ioc",
                provider="microsoft_defender",
                params={"indicator_type": ind_type, "value": str(value)},
                justification=f"{raw_type} {value} assessed malicious during enrichment",
            )
        )
        idx += 1
    return actions


def _propose_v1_actions(
    l2: AnalysisVerdict,
    enrichment: dict[str, Any],
    normalized: dict[str, Any],
) -> list[ProposedAction]:
    """Vision One response proposals (blocklist / isolate / collect)."""
    actions: list[ProposedAction] = []
    idx = 0
    for r in _triage_rows(enrichment):
        if str(r.get("verdict", "")).lower() != "malicious":
            continue
        q = r.get("query") or {}
        value = q.get("ioc") if isinstance(q, dict) else q
        raw_type = (q.get("type") if isinstance(q, dict) else None) or r.get("type")
        v1_type = _V1_IOC_TYPE.get(str(raw_type or "").lower())
        if not value or not v1_type:
            continue
        actions.append(
            ProposedAction(
                id=f"act{idx}",
                kind="blocklist_ioc",
                params={"ioc_type": v1_type, "value": str(value), "scan_action": "block"},
                justification=f"{raw_type} {value} assessed malicious during enrichment",
            )
        )
        idx += 1

    host = normalized.get("hostname")
    if host and l2.hunt_focus in ("lateral_movement", "persistence", "c2"):
        actions.append(
            ProposedAction(
                id=f"act{idx}",
                kind="isolate_host",
                params={"endpoint_name": str(host)},
                justification=f"Confirmed TP on {host} with {l2.hunt_focus} signal; isolate to contain",
            )
        )
        idx += 1

    # Collect the file for analysis ONLY when its hash is unknown to threat intel
    # (there's nothing to learn from pulling a file TI already recognises) and we
    # have both a concrete path and a target endpoint so the action is runnable.
    # Human-gated like every proposal — never fires without analyst approval.
    fpath = normalized.get("file_path")
    guid = _v1_host_guid(enrichment)
    if fpath and (guid or host) and has_unknown_file_hash(enrichment):
        params: dict[str, Any] = {"file_path": str(fpath)}
        if guid:
            params["agent_guid"] = guid
        if host:
            params["endpoint_name"] = str(host)
        target = host or guid
        actions.append(
            ProposedAction(
                id=f"act{idx}",
                kind="collect_file",
                params=params,
                justification=(
                    f"File hash unknown to threat intel; collect {fpath} from {target} for analysis"
                ),
            )
        )
        idx += 1
    return actions


def create_case_action(idx: int) -> ProposedAction:
    """A workflow nudge added to EVERY gate proposal: open a customer case so the
    customer notification isn't forgotten. Internal, no external effect — pinned
    to `autonomy='review'` so it is always PRE-CHECKED at the gate (the analyst
    can still uncheck it for, e.g., a confirmed false positive). Created
    idempotently on approval, never auto-run."""
    return ProposedAction(
        id=f"act{idx}",
        kind="create_case",
        params={},
        justification="Open a customer case so the customer notification isn't missed",
        blast_radius="low",
        autonomy="review",
        autonomy_reason="Workflow step — opens a draft customer case on approval",
    )
