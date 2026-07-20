"""Deterministic fusion of pipeline signals into two orthogonal scores.

  confidence_score [0,100] — how sure we are of the VERDICT (any verdict)
  threat_score     [0,100] — EFFECTIVE threat: inherent impact × P(malicious),
                             so a confidently-benign alert sinks toward 0

Design stance (agreed 2026-07):
  1. The LLM band is a PRIOR, not the driver. The model alone tops out at 0.75
     confidence; exceeding that requires hard corroboration (exact match /
     n-way agreement / IOC track record). Mirrors the prompt hard-rule
     "cap confidence at MEDIUM when no priors" (llm/prompts.py).
  2. Corroboration is ADDITIVE with penalties, consistent with rerank.py's
     idiom (base signal + additive bonuses, clamped). Contradicting evidence
     REDUCES confidence.
  3. Threat displayed is EFFECTIVE = inherent × P(malicious). `threat_inherent`
     is kept for explainability ("would be 85 if real"). Verdict/confidence
     modulate the displayed number so FPs sink.
  4. Every term is recorded in `contributions` so the analyst sees WHY and we
     can calibrate the weights against gate outcomes later.

Pure functions, no stack deps — unit-testable on the host (like rerank/decision).
Weights live as module constants precisely so they are easy to tune.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── CONFIDENCE weights (in [0,1] space; ×100 at the end) ─────────────────────
_BAND_PRIOR = {"high": 0.75, "medium": 0.55, "low": 0.30}
_INCONCLUSIVE_CAP = 0.40  # verdict inconclusive/pending can't be "confident"
_NO_PRIORS_CAP = 0.60  # no exact/n_way/similar at all -> cap at ~MEDIUM
_SENSITIVE_DISMISS_CAP = 0.70  # sensitive rule + FP/benign -> never HIGH-confident
# Dismissing one member of a correlated burst deserves the same caution as a
# sensitive rule: FP/benign on a >=3 cluster can't be HIGH-confident (agreed 2026-07).
_CLUSTER_DISMISS_CAP = 0.70
_CLUSTER_DISMISS_MIN = 3  # cluster size at which the dismiss cap kicks in

_W_EXACT_MAX = 0.20  # exact-match cosine agreeing, scaled over [0.7,0.9]
_W_NWAY_MAX = 0.15  # n-way agreeing fraction
_W_IOC_MAX = 0.10  # IOC track-record consistency agreeing with verdict
_W_TI_MAX = 0.08  # independent TI sources corroborating
_W_SIMILAR_MAX = 0.05  # neighbourhood quality (verified priors)

_P_EXACT_CONTRA = -0.15
_P_NWAY_CONTRA = -0.10
_P_IOC_CONTRA = -0.10
_P_TI_CONTRA = -0.10

# ── THREAT weights (in [0,100] space) ────────────────────────────────────────
_SEV_BASE = {"low": 25.0, "medium": 50.0, "high": 72.0, "critical": 90.0}
_T_TI_MAX = 25.0  # VT malicious count + AbuseIPDB% + ThreatFox
_T_ATTACK_MAX = 15.0  # attack-chain depth + high-impact tactic
_T_ASSET_MAX = 15.0  # crown-jewel / server (needs KB; opt-in)
# Correlation cluster: a coordinated multi-incident pattern (same-tenant strong-
# entity overlap) means bigger blast radius IF real. Bounded below the direct-
# evidence terms; a confident FP still sinks because effective = inherent × P(mal).
_T_CLUSTER_MAX = 10.0  # scaled over cluster sizes 2..5+
# The vendor's own 0-100 risk score (e.g. Trend V1 score) is an independent inherent-threat
# signal. Bounded like the other terms so it corroborates severity rather than dominating it.
_T_VENDOR_MAX = 12.0

_HIGH_IMPACT_FOCUS = {"lateral_movement", "exfil", "c2", "persistence"}


# ── Inputs ───────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class SignalBundle:
    proposed_verdict: str  # "TP" | "FP" | "benign" | "inconclusive"
    llm_band: str = "low"  # AnalysisVerdict.confidence
    severity: str = "medium"  # incident.severity

    # retrieval corroboration
    exact_cosine: float | None = None
    exact_verdict: str | None = None
    nway_agreed: int = 0
    nway_total: int = 0
    nway_verdict: str | None = None
    similar_top_adjusted: float | None = None
    similar_verified_count: int = 0

    # IOC track record (optional; not populated in enrichment by default)
    ioc_dominant_verdict: str | None = None
    ioc_consistency: float = 0.0
    ioc_seen: int = 0

    # threat intel magnitude (max across triage results)
    vt_malicious: int = 0
    abuseipdb_pct: int = 0
    threatfox_hit: bool = False
    ti_malicious_sources: int = 0

    # attack shape (from AnalysisVerdict)
    attack_chain_len: int = 0
    hunt_focus: str | None = None

    # optional asset context (KB lookup; default neutral)
    asset_tier: str | None = None  # "crown_jewel" | "server" | "workstation"

    sensitive_rule: bool = False
    # correlation cluster size (member_count incl. self; 0/1 = unclustered)
    cluster_size: int = 0
    # the vendor's own 0-100 risk score (e.g. Trend V1 score); 0 = none
    vendor_score: int = 0


@dataclass
class ScoreResult:
    confidence_score: int  # 0-100 (displayed)
    threat_score: int  # 0-100 EFFECTIVE (displayed)
    threat_inherent: int  # 0-100 "if real, how bad"
    p_malicious: float  # 0-1, the modulator
    confidence_band: str  # low|medium|high (back-compat w/ enum)
    contributions: dict = field(default_factory=dict)

    def as_payload(self) -> dict:
        """Flat dict for enrichment['scores'] / API."""
        return {
            "confidence": self.confidence_score,
            "threat": self.threat_score,
            "threat_inherent": self.threat_inherent,
            "p_malicious": round(self.p_malicious, 3),
            "confidence_band": self.confidence_band,
            "contributions": self.contributions,
        }


# ── helpers ──────────────────────────────────────────────────────────────────
def _agrees(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and str(a).upper() == str(b).upper()


def _int(v: object) -> int:
    try:
        if isinstance(v, str):
            v = v.strip().rstrip("%")
        return int(float(v))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


# ── CONFIDENCE ───────────────────────────────────────────────────────────────
def score_confidence(b: SignalBundle) -> tuple[float, dict]:
    contrib: dict[str, float] = {}
    v = (b.proposed_verdict or "").upper()

    base = _BAND_PRIOR.get((b.llm_band or "low").lower(), 0.30)
    contrib["llm_band_prior"] = base
    score = base

    # exact match — strongest corroborator; scaled over the [0.7,0.9] cosine band
    if b.exact_cosine is not None and b.exact_verdict:
        scaled = max(0.0, min(1.0, (b.exact_cosine - 0.70) / 0.20))
        d = (_W_EXACT_MAX if _agrees(b.exact_verdict, v) else _P_EXACT_CONTRA) * scaled
        contrib["exact_match"] = round(d, 4)
        score += d

    # n-way agreement — agreeing fraction
    if b.nway_total > 0:
        frac = b.nway_agreed / b.nway_total
        d = (_W_NWAY_MAX if _agrees(b.nway_verdict, v) else _P_NWAY_CONTRA) * frac
        contrib["n_way"] = round(d, 4)
        score += d

    # IOC track record
    if b.ioc_seen > 0 and b.ioc_dominant_verdict:
        d = (
            _W_IOC_MAX if _agrees(b.ioc_dominant_verdict, v) else _P_IOC_CONTRA
        ) * b.ioc_consistency
        contrib["ioc_history"] = round(d, 4)
        score += d

    # TI corroboration — direction depends on verdict
    if v == "TP" and b.ti_malicious_sources >= 1:
        d = min(_W_TI_MAX, 0.04 * b.ti_malicious_sources)
        contrib["ti_agreement"] = round(d, 4)
        score += d
    elif v in ("FP", "BENIGN"):
        if b.ti_malicious_sources >= 2:  # TI says malicious, we say benign
            contrib["ti_contradiction"] = _P_TI_CONTRA
            score += _P_TI_CONTRA
        elif b.ti_malicious_sources == 0 and (b.vt_malicious or b.abuseipdb_pct):
            contrib["ti_clean"] = 0.05  # checked-and-clean lightly supports benign
            score += 0.05

    # neighbourhood quality (small; avoids double-counting exact/n_way)
    if b.similar_top_adjusted and b.similar_verified_count > 0:
        d = min(_W_SIMILAR_MAX, 0.02 * b.similar_verified_count)
        contrib["similar_support"] = round(d, 4)
        score += d

    # ── caps / hard rules (mirror the prompt) ──
    no_priors = b.exact_cosine is None and b.nway_total == 0 and b.similar_top_adjusted is None
    if no_priors and score > _NO_PRIORS_CAP:
        score = _NO_PRIORS_CAP
        contrib["_cap_no_priors"] = _NO_PRIORS_CAP
    if v in ("INCONCLUSIVE", "PENDING") and score > _INCONCLUSIVE_CAP:
        score = _INCONCLUSIVE_CAP
        contrib["_cap_inconclusive"] = _INCONCLUSIVE_CAP
    if b.sensitive_rule and v in ("FP", "BENIGN") and score > _SENSITIVE_DISMISS_CAP:
        score = _SENSITIVE_DISMISS_CAP
        contrib["_cap_sensitive_dismiss"] = _SENSITIVE_DISMISS_CAP
    # Dismiss caution: waving away one member of a correlated burst is exactly
    # the sensitive-rule situation — the coordinated pattern warrants a human
    # double-take, so the system can't be HIGH-confident about the dismissal.
    if (
        b.cluster_size >= _CLUSTER_DISMISS_MIN
        and v in ("FP", "BENIGN")
        and score > _CLUSTER_DISMISS_CAP
    ):
        score = _CLUSTER_DISMISS_CAP
        contrib["_cap_cluster_dismiss"] = _CLUSTER_DISMISS_CAP

    return max(0.0, min(1.0, score)), contrib


# ── THREAT (inherent) ────────────────────────────────────────────────────────
def score_threat_inherent(b: SignalBundle) -> tuple[float, dict]:
    contrib: dict[str, float] = {}
    base = _SEV_BASE.get((b.severity or "medium").lower(), 50.0)
    contrib["severity_base"] = base
    score = base

    ti = min(b.vt_malicious, 10) / 10 * 18.0
    ti += min(b.abuseipdb_pct, 100) / 100 * 10.0
    if b.threatfox_hit:
        ti += 8.0
    ti = min(ti, _T_TI_MAX)
    if ti:
        contrib["ti_reputation"] = round(ti, 2)
        score += ti

    atk = min(b.attack_chain_len, 4) / 4 * 8.0
    if (b.hunt_focus or "").lower() in _HIGH_IMPACT_FOCUS:
        atk += 7.0
    atk = min(atk, _T_ATTACK_MAX)
    if atk:
        contrib["attack_shape"] = round(atk, 2)
        score += atk

    asset = {"crown_jewel": _T_ASSET_MAX, "server": 8.0, "workstation": 0.0}.get(
        b.asset_tier or "", 0.0
    )
    if asset:
        contrib["asset_criticality"] = asset
        score += asset

    # correlation cluster — size 2 -> +2.5 … size 5+ -> +10 (bounded)
    if b.cluster_size >= 2:
        clu = min(b.cluster_size - 1, 4) / 4 * _T_CLUSTER_MAX
        contrib["cluster_corroboration"] = round(clu, 2)
        score += clu

    # vendor's own risk score (0-100) — a bounded corroborating nudge.
    if b.vendor_score > 0:
        vs = min(b.vendor_score, 100) / 100 * _T_VENDOR_MAX
        contrib["vendor_score"] = round(vs, 2)
        score += vs

    return max(0.0, min(100.0, score)), contrib


# ── TOP-LEVEL ─────────────────────────────────────────────────────────────────
def _band_of(conf01: float) -> str:
    if conf01 >= 0.75:
        return "high"
    if conf01 >= 0.50:
        return "medium"
    return "low"


def _p_malicious(verdict: str, conf01: float) -> float:
    """Probability the alert is genuinely malicious, given the proposed verdict
    and our confidence in it. Drives the EFFECTIVE threat number."""
    v = (verdict or "").upper()
    if v == "TP":
        return conf01
    if v in ("FP", "BENIGN"):
        return 1.0 - conf01
    return 0.5  # inconclusive / pending


def compute_scores(b: SignalBundle) -> ScoreResult:
    conf01, c_contrib = score_confidence(b)
    inherent, t_contrib = score_threat_inherent(b)
    pmal = _p_malicious(b.proposed_verdict, conf01)
    effective = inherent * pmal
    t_contrib["p_malicious"] = round(pmal, 3)
    t_contrib["effective_threat"] = round(effective, 2)
    return ScoreResult(
        confidence_score=round(conf01 * 100),
        threat_score=round(effective),
        threat_inherent=round(inherent),
        p_malicious=pmal,
        confidence_band=_band_of(conf01),
        contributions={"confidence": c_contrib, "threat": t_contrib},
    )


# ── enrichment → SignalBundle (pure; knows the enrichment key layout) ────────
def build_bundle(
    enrichment: dict,
    *,
    proposed_verdict: str,
    llm_band: str,
    severity: str,
    attack_chain_len: int = 0,
    hunt_focus: str | None = None,
    vendor_score: object = 0,
) -> SignalBundle:
    """Extract a SignalBundle from the pipeline's `enrichment` dict. Tolerant of
    missing keys (short-circuit cases have no L2 analysis → attack fields 0)."""
    exact = enrichment.get("exact_match") or {}
    nway = enrichment.get("n_way") or {}
    similar = enrichment.get("similar_top5") or []
    triage = enrichment.get("triage") or []

    nway_agreed = nway_total = 0
    agreement = nway.get("agreement")
    if isinstance(agreement, str) and "/" in agreement:
        a, _, t = agreement.partition("/")
        nway_agreed, nway_total = _int(a), _int(t)

    similar_top_adjusted = None
    verified_count = 0
    if similar:
        similar_top_adjusted = similar[0].get("adjusted_score") or similar[0].get("cosine")
        verified_count = sum(1 for s in similar if s.get("human_verified"))

    vt_malicious = abuseipdb_pct = ti_malicious_sources = 0
    threatfox_hit = False
    for r in triage:
        summary = r.get("summary") or {}
        vt = max(_int(summary.get("vt_malicious")), _int(summary.get("virustotal_malicious")))
        ab = _int(summary.get("abuseipdb"))
        vt_malicious = max(vt_malicious, vt)
        abuseipdb_pct = max(abuseipdb_pct, ab)
        if summary.get("threatfox") or summary.get("threatfox_family"):
            threatfox_hit = True
        # count this indicator as a malicious source if it flags dirty
        if (r.get("verdict") or "").lower() in ("malicious", "high") or vt > 3 or ab > 25:
            ti_malicious_sources += 1

    return SignalBundle(
        proposed_verdict=proposed_verdict,
        llm_band=(llm_band or "low"),
        severity=str(getattr(severity, "value", severity) or "medium"),
        exact_cosine=exact.get("score") if exact else None,
        exact_verdict=exact.get("verdict") if exact else None,
        nway_agreed=nway_agreed,
        nway_total=nway_total,
        nway_verdict=nway.get("verdict") if nway else None,
        similar_top_adjusted=similar_top_adjusted,
        similar_verified_count=verified_count,
        vt_malicious=vt_malicious,
        abuseipdb_pct=abuseipdb_pct,
        threatfox_hit=threatfox_hit,
        ti_malicious_sources=ti_malicious_sources,
        attack_chain_len=attack_chain_len,
        hunt_focus=hunt_focus,
        sensitive_rule=bool((enrichment.get("sensitive_rule") or {}).get("matched")),
        cluster_size=_int((enrichment.get("cluster") or {}).get("member_count")),
        vendor_score=_int(vendor_score),
    )
