"""OCSF severity mapping (ADR-0006 decision #5).

OCSF `severity_id` is the open, cross-vendor severity scale (0-6). We adopt it as the canonical
normalized severity so every connector's mapper aims at a documented target instead of the
Wazuh 1-15 convention, which maps to nothing outside Wazuh. The Wazuh helpers stay only as a
legacy display/compat bridge during the migration.

    0 Unknown · 1 Informational · 2 Low · 3 Medium · 4 High · 5 Critical · 6 Fatal

Pure — no I/O.
"""

from __future__ import annotations

from typing import Any

SEVERITY_ID_LABEL: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}

# Vendor severity words -> OCSF severity_id. Covers the common ladders (5-tier, syslog words,
# Trend/CrowdStrike/GuardDuty phrasings).
_WORDS: dict[str, int] = {
    "unknown": 0,
    "info": 1,
    "informational": 1,
    "debug": 1,
    "notice": 1,
    "low": 2,
    "warning": 3,
    "warn": 3,
    "moderate": 3,
    "medium": 3,
    "med": 3,
    "high": 4,
    "error": 4,
    "important": 4,
    "critical": 5,
    "crit": 5,
    "severe": 5,
    "emergency": 6,
    "fatal": 6,
}

# Wazuh 1-15 rule level -> OCSF severity_id. Bands mirror the vendored normalizer's word bands
# (low 1-3, medium 4-6, high 7-12, critical 13-15; 0/none -> Unknown) so severity_id stays
# monotonic with the analyst-visible severity_label.


def to_ocsf_severity(value: Any) -> int:
    """Coerce an arbitrary vendor severity (word, 0-100 score, 1-15 level) to OCSF 0-6.

    Numeric handling: <= 6 is treated as an OCSF ordinal already; 7-15 as a Wazuh level;
    > 15 as a 0-100 score band. Anything unrecognized falls back to 3 (Medium) rather than 0,
    so an unmapped alert is not silently downgraded to noise.
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        return 3
    if isinstance(value, (int, float)):
        n = float(value)
        if n <= 6:
            return max(0, min(6, int(round(n))))
        if n <= 15:  # a Wazuh 1-15 rule level
            return wazuh_to_ocsf(int(round(n)))
        # 0-100 style score
        if n >= 90:
            return 5
        if n >= 70:
            return 4
        if n >= 40:
            return 3
        if n >= 20:
            return 2
        return 1
    return _WORDS.get(str(value).strip().lower(), 3)


def wazuh_to_ocsf(level: int) -> int:
    """Wazuh 1-15 rule level -> OCSF severity_id, matching the normalizer's word bands."""
    if level >= 13:
        return 5  # critical
    if level >= 7:
        return 4  # high
    if level >= 4:
        return 3  # medium
    if level >= 1:
        return 2  # low
    return 0  # unknown


def severity_id_from_alert(severity_label: str | None, severity_level: int | None = None) -> int:
    """OCSF severity_id for a NormalizedAlert (ADR-0006 P1c).

    Prefer the severity WORD (low/medium/high/critical) because that is ISOC's canonical,
    analyst-visible band; fall back to the Wazuh 1-15 level. Kept monotonic with the word so
    severity_id never disagrees with the label the analyst sees. `unknown`/absent -> 0.
    """
    word = (severity_label or "").strip().lower()
    if word and word != "unknown":
        return to_ocsf_severity(word)
    if severity_level:
        return wazuh_to_ocsf(int(severity_level))
    return 0


def ocsf_to_wazuh(severity_id: int) -> int:
    """OCSF severity_id -> a representative Wazuh 1-15 level, for legacy display only."""
    return {0: 1, 1: 1, 2: 3, 3: 6, 4: 9, 5: 13, 6: 15}.get(severity_id, 6)


def label(severity_id: int) -> str:
    return SEVERITY_ID_LABEL.get(severity_id, "Unknown")


# OCSF severity_id -> ISOC `Severity` enum word (low|medium|high|critical). The enum has no
# unknown/info/fatal, so: Unknown (0) -> medium (the safe triage baseline), Informational/Low
# -> low, Fatal -> critical. Used to drive incident.severity from the alert (ADR-0006 P1c).
_OCSF_TO_WORD = {
    0: "medium",
    1: "low",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
    6: "critical",
}


def ocsf_to_severity_word(severity_id: int) -> str:
    """OCSF severity_id (0-6) -> ISOC Severity enum word (low|medium|high|critical)."""
    return _OCSF_TO_WORD.get(severity_id, "medium")
