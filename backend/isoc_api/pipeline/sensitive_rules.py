"""Rule-pattern allowlist — alerts that must always reach the deep LLM.

Some alert classes have very low base rates of being benign (admin login,
privilege escalation, credential dumping, ransomware indicators, etc.).
When one fires, even a HIGH-confidence fast-tier "FP/benign" verdict should
*not* be allowed to short-circuit — these need an analyst-grade report and
human review every time.

Matching is case-insensitive substring across rule_name + event_name +
event_description.
"""

from __future__ import annotations

# Keywords that mark an alert as "must-analyse." Conservative — better to
# burn an extra LLM call than auto-close a real incident.
SENSITIVE_KEYWORDS: tuple[str, ...] = (
    # AuthN / privileged access
    "admin login",
    "administrator login",
    "root login",
    "privileged login",
    "privilege escalation",
    "elevation of privilege",
    "suspicious login",
    "anomalous login",
    "after-hours login",
    "off-hours login",
    "brute force",
    # Credential theft
    "credential dump",
    "credential theft",
    "credential harvest",
    "lsass",
    "mimikatz",
    "secretsdump",
    # Lateral movement
    "lateral movement",
    "psexec",
    "wmic exec",
    "wmi exec",
    "pass the hash",
    "pass-the-hash",
    "pass the ticket",
    "pass-the-ticket",
    "golden ticket",
    "silver ticket",
    "kerberoast",
    # Data exfiltration
    "exfiltration",
    "data leak",
    "dlp violation",
    # Ransomware / destructive
    "ransomware",
    "shadow copy delet",
    "vssadmin delete",
    "wiper",
    "destructive",
    # Persistence
    "persistence",
    "scheduled task creation",
    "service install",
    "registry persistence",
    "startup folder",
    # Detection evasion / disabling defenses
    "disable defender",
    "disable av",
    "amsi bypass",
    "etw bypass",
    "tamper protection",
    # C2
    "command and control",
    "c2 beacon",
    # Web attacks that are commonly FP-prone but high-impact when real
    "sql injection",
    "command injection",
    "rce",
    "remote code execution",
    "deserializ",  # deserialization attacks (vary in spelling)
    # Webshell
    "webshell",
    "web shell",
)


def is_sensitive(*texts: str | None) -> tuple[bool, str | None]:
    """Return (matched?, matching_keyword?).

    Pass any subset of (rule_name, event_name, event_description). First match
    wins — caller gets the keyword so it can be surfaced in the timeline /
    audit log.
    """
    haystack = " ".join(t.lower() for t in texts if isinstance(t, str)).strip()
    if not haystack:
        return False, None
    for kw in SENSITIVE_KEYWORDS:
        if kw in haystack:
            return True, kw
    return False, None
