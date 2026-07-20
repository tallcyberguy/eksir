"""F4 — MITRE ATT&CK technique→tactic map + coverage aggregation.

Two consumers need the same thing: "tactic × technique density derived from our
incident verdicts" — the MITRE Coverage view and the Attack-Graph heatmap. The
L2 persona already emits `mitre_techniques: list[str]` per incident
(`enrichment["stages"]["l2"]["mitre_techniques"]`); this module turns those raw
IDs into a tactic-bucketed coverage structure.

The technique→tactic table is a **curated seed**, not the full ATT&CK catalog —
it covers the techniques most likely to show up in isoc verdicts. Unknown IDs
degrade gracefully into an "unmapped" bucket rather than being dropped, so the
aggregation stays correct as the seed grows. To get full coverage, drop a JSON
file at `data/attack_enterprise.json` (shape: `{"version": str, "techniques":
{"Txxxx": {"name": str, "tactics": ["TAxxxx", ...]}}}`) — `load_techniques()`
prefers it over the seed; no code change needed. Regenerate it from the official
ATT&CK STIX bundle or via the `analysing-attack` skill.

Sub-techniques (e.g. `T1059.001`) inherit their parent's tactics via rollup, so
the seed only lists parent techniques.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

# ATT&CK release the seed below was curated against.
SEED_ATTACK_VERSION = "v15.1"

# The 14 Enterprise tactics, in kill-chain order.
TACTICS: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
TACTIC_NAME: dict[str, str] = dict(TACTICS)
TACTIC_ORDER: dict[str, int] = {tid: i for i, (tid, _) in enumerate(TACTICS)}

# Curated seed: parent technique_id -> (name, [tactic_id, ...]).
_SEED_TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    # Reconnaissance
    "T1595": ("Active Scanning", ["TA0043"]),
    "T1592": ("Gather Victim Host Information", ["TA0043"]),
    "T1589": ("Gather Victim Identity Information", ["TA0043"]),
    "T1598": ("Phishing for Information", ["TA0043"]),
    # Resource Development
    "T1583": ("Acquire Infrastructure", ["TA0042"]),
    "T1587": ("Develop Capabilities", ["TA0042"]),
    "T1588": ("Obtain Capabilities", ["TA0042"]),
    # Initial Access
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1133": ("External Remote Services", ["TA0001", "TA0003"]),
    "T1566": ("Phishing", ["TA0001"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1199": ("Trusted Relationship", ["TA0001"]),
    "T1195": ("Supply Chain Compromise", ["TA0001"]),
    "T1189": ("Drive-by Compromise", ["TA0001"]),
    # Execution
    "T1059": ("Command and Scripting Interpreter", ["TA0002"]),
    "T1204": ("User Execution", ["TA0002"]),
    "T1203": ("Exploitation for Client Execution", ["TA0002"]),
    "T1053": ("Scheduled Task/Job", ["TA0002", "TA0003", "TA0004"]),
    "T1569": ("System Services", ["TA0002"]),
    "T1047": ("Windows Management Instrumentation", ["TA0002"]),
    "T1106": ("Native API", ["TA0002"]),
    # Persistence
    "T1547": ("Boot or Logon Autostart Execution", ["TA0003", "TA0004"]),
    "T1543": ("Create or Modify System Process", ["TA0003", "TA0004"]),
    "T1136": ("Create Account", ["TA0003"]),
    "T1505": ("Server Software Component", ["TA0003"]),
    "T1098": ("Account Manipulation", ["TA0003", "TA0004"]),
    # Privilege Escalation
    "T1548": ("Abuse Elevation Control Mechanism", ["TA0004", "TA0005"]),
    "T1068": ("Exploitation for Privilege Escalation", ["TA0004"]),
    "T1055": ("Process Injection", ["TA0004", "TA0005"]),
    # Defense Evasion
    "T1070": ("Indicator Removal", ["TA0005"]),
    "T1027": ("Obfuscated Files or Information", ["TA0005"]),
    "T1036": ("Masquerading", ["TA0005"]),
    "T1112": ("Modify Registry", ["TA0005"]),
    "T1562": ("Impair Defenses", ["TA0005"]),
    "T1218": ("System Binary Proxy Execution", ["TA0005"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["TA0005"]),
    "T1497": ("Virtualization/Sandbox Evasion", ["TA0005", "TA0007"]),
    # Credential Access
    "T1110": ("Brute Force", ["TA0006"]),
    "T1003": ("OS Credential Dumping", ["TA0006"]),
    "T1555": ("Credentials from Password Stores", ["TA0006"]),
    "T1552": ("Unsecured Credentials", ["TA0006"]),
    "T1558": ("Steal or Forge Kerberos Tickets", ["TA0006"]),
    "T1556": ("Modify Authentication Process", ["TA0006", "TA0003", "TA0005"]),
    # Discovery
    "T1087": ("Account Discovery", ["TA0007"]),
    "T1082": ("System Information Discovery", ["TA0007"]),
    "T1083": ("File and Directory Discovery", ["TA0007"]),
    "T1057": ("Process Discovery", ["TA0007"]),
    "T1018": ("Remote System Discovery", ["TA0007"]),
    "T1046": ("Network Service Discovery", ["TA0007"]),
    "T1069": ("Permission Groups Discovery", ["TA0007"]),
    # Lateral Movement
    "T1021": ("Remote Services", ["TA0008"]),
    "T1570": ("Lateral Tool Transfer", ["TA0008"]),
    "T1210": ("Exploitation of Remote Services", ["TA0008"]),
    # Collection
    "T1005": ("Data from Local System", ["TA0009"]),
    "T1114": ("Email Collection", ["TA0009"]),
    "T1056": ("Input Capture", ["TA0009", "TA0006"]),
    "T1560": ("Archive Collected Data", ["TA0009"]),
    # Command and Control
    "T1071": ("Application Layer Protocol", ["TA0011"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1572": ("Protocol Tunneling", ["TA0011"]),
    "T1090": ("Proxy", ["TA0011"]),
    "T1219": ("Remote Access Software", ["TA0011"]),
    "T1573": ("Encrypted Channel", ["TA0011"]),
    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", ["TA0010"]),
    "T1567": ("Exfiltration Over Web Service", ["TA0010"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["TA0010"]),
    # Impact
    "T1486": ("Data Encrypted for Impact", ["TA0040"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1489": ("Service Stop", ["TA0040"]),
    "T1485": ("Data Destruction", ["TA0040"]),
    "T1496": ("Resource Hijacking", ["TA0040"]),
    "T1498": ("Network Denial of Service", ["TA0040"]),
}


def parent_of(technique_id: str) -> str:
    """`T1059.001` → `T1059`; a parent ID is returned unchanged."""
    return (technique_id or "").strip().split(".", 1)[0].upper()


@lru_cache(maxsize=1)
def load_techniques() -> tuple[str, dict[str, tuple[str, list[str]]]]:
    """(version, {technique_id: (name, [tactic_id,...])}).

    Prefers a bundled `data/attack_enterprise.json` if present; otherwise the
    curated seed. Cached — call `load_techniques.cache_clear()` after dropping
    the JSON file in a long-lived process.
    """
    data_path = Path(__file__).resolve().parent.parent / "data" / "attack_enterprise.json"
    if data_path.is_file():
        try:
            blob = json.loads(data_path.read_text())
            techs = {
                tid.upper(): (meta.get("name", tid), [t.upper() for t in meta.get("tactics", [])])
                for tid, meta in (blob.get("techniques") or {}).items()
            }
            if techs:
                return str(blob.get("version") or "custom"), techs
        except Exception:
            pass  # fall back to the seed on any parse error
    return SEED_ATTACK_VERSION, _SEED_TECHNIQUES


def tactics_for(technique_id: str) -> list[str]:
    """Tactic IDs for a technique (sub-techniques resolve via their parent).
    Empty list when the technique is not in the map."""
    _, techs = load_techniques()
    entry = techs.get(parent_of(technique_id))
    return list(entry[1]) if entry else []


def technique_name(technique_id: str) -> str | None:
    _, techs = load_techniques()
    entry = techs.get(parent_of(technique_id))
    return entry[0] if entry else None


def extract_techniques(enrichment: dict | None) -> list[str]:
    """Pull the L2 persona's technique IDs from an incident's enrichment blob.

    Tolerant of the cases where synthesis didn't run or emitted nothing.
    """
    if not isinstance(enrichment, dict):
        return []
    l2 = ((enrichment.get("stages") or {}).get("l2")) or {}
    techs = l2.get("mitre_techniques") or []
    return [str(t).strip().upper() for t in techs if str(t).strip()]


def aggregate_coverage(incident_techniques: Iterable[Iterable[str]]) -> dict:
    """Bucket techniques (across many incidents) by tactic.

    `incident_techniques`: one iterable of technique IDs per incident.

    Returns a JSON-serializable coverage structure:
        {
          "attack_version": str,
          "incident_count": int,
          "technique_count": int,        # distinct techniques seen (mapped+unmapped)
          "occurrence_count": int,       # total technique mentions
          "tactics": [ { tactic_id, name, order,
                         technique_count, occurrence_count,
                         techniques: [ {id, name, count} ... ] } ],   # all 14, sorted
          "unmapped": [ {id, count} ... ],   # techniques whose parent isn't in the map
        }
    Each technique is attributed to EVERY tactic the map lists for it (techniques
    like Valid Accounts span several), so per-tactic counts can exceed the global
    occurrence_count — that is correct for a coverage view.
    """
    version, _ = load_techniques()
    per_technique: dict[str, int] = {}
    incident_count = 0
    for techs in incident_techniques:
        incident_count += 1
        for raw in techs or []:
            tid = str(raw).strip().upper()
            if tid:
                per_technique[tid] = per_technique.get(tid, 0) + 1

    occurrence_count = sum(per_technique.values())
    tactic_buckets: dict[str, dict[str, int]] = {tid: {} for tid, _ in TACTICS}
    unmapped: dict[str, int] = {}

    for tid, count in per_technique.items():
        tactic_ids = tactics_for(tid)
        if not tactic_ids:
            unmapped[tid] = count
            continue
        for ta in tactic_ids:
            if ta in tactic_buckets:
                tactic_buckets[ta][tid] = tactic_buckets[ta].get(tid, 0) + count

    tactics_out = []
    for tid, name in TACTICS:
        techs = tactic_buckets[tid]
        techs_out = sorted(
            ({"id": t, "name": technique_name(t) or t, "count": c} for t, c in techs.items()),
            key=lambda d: (-d["count"], d["id"]),
        )
        tactics_out.append(
            {
                "tactic_id": tid,
                "name": name,
                "order": TACTIC_ORDER[tid],
                "technique_count": len(techs),
                "occurrence_count": sum(techs.values()),
                "techniques": techs_out,
            }
        )

    return {
        "attack_version": version,
        "incident_count": incident_count,
        "technique_count": len(per_technique),
        "occurrence_count": occurrence_count,
        "tactics": tactics_out,
        "unmapped": sorted(
            ({"id": t, "count": c} for t, c in unmapped.items()),
            key=lambda d: (-d["count"], d["id"]),
        ),
    }
