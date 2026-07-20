"""
Normalized alert schema and embed text builder.
All parsers produce this common structure.
"""

import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime


# Threat category inference keywords
CATEGORY_KEYWORDS = {
    "exploit":      ["exploit", "cve-", "injection", "overflow", "rce", "command injection",
                     "sql injection", "shellcode", "webshell"],
    "brute_force":  ["brute force", "logon failure", "authentication failure", "multiple failure",
                     "password spray", "credential"],
    "recon":        ["scan", "enumeration", "recon", "discovery", "404", "not found",
                     "sweep", "probe"],
    "phishing":     ["phishing", "fraud", "malicious file", "email detection", "spam"],
    "ransomware":   ["ransomware", "encrypt", "cryptography", "ransom"],
    "lateral":      ["lateral", "pass-the-hash", "pass-the-ticket", "kerberos", "silver ticket",
                     "golden ticket", "dcsync", "mimikatz"],
    "persistence":  ["persistence", "account created", "account enabled", "scheduled task",
                     "registry", "startup", "service installed"],
    "c2":           ["command and control", "c2", "beacon", "callback", "reverse shell"],
    "malware":      ["malware", "trojan", "rat", "backdoor", "dropper", "loader"],
}

SEVERITY_LABELS = {
    range(1, 4):   "low",
    range(4, 7):   "medium",
    range(7, 10):  "high",
    range(10, 13): "high",
    range(13, 16): "critical",
}


def infer_category(text: str) -> str:
    import re as _re
    text_lower = text.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            # Short keywords (<=4 chars) must match whole words to avoid substring hits
            # e.g. "rce" inside "resource", "rat" inside "grateful"
            if len(kw) <= 4:
                if _re.search(rf'\b{_re.escape(kw)}\b', text_lower):
                    return category
            else:
                if kw in text_lower:
                    return category
    return "unknown"


def severity_label(level: int) -> str:
    for r, label in SEVERITY_LABELS.items():
        if level in r:
            return label
    return "unknown"


@dataclass
class NormalizedAlert:
    # Identity
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None
    customer: Optional[str] = None

    # Source product
    source_product: str = "unknown"   # wazuh | qradar | trendmicro | bitdefender
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: int = 0                 # Wazuh 1-15 scale
    severity_label: str = "unknown"   # low | medium | high | critical
    vendor_score: Optional[int] = None  # vendor's own 0-100 risk score (e.g. V1 score) if any

    # Network
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    src_zone: Optional[str] = None       # DMZ-1 / LAN / WAN — PAN-OS zone names
    dst_zone: Optional[str] = None
    action: Optional[str] = None         # allow / deny / drop / alert
    application: Optional[str] = None    # PAN-OS App-ID: stun, ssl, web-browsing, …

    # Identity
    username: Optional[str] = None
    hostname: Optional[str] = None
    agent_ip: Optional[str] = None

    # Email / messaging context (e.g. Exchange message-tracking inside QRadar).
    # sender/recipient are the TRUE mail directions — do not infer them from
    # QRadar's "Source/Destination Username", which mis-map for Exchange logs.
    sender: Optional[str] = None        # envelope/sender-address
    recipient: Optional[str] = None     # recipient-address (may be ;-separated)
    subject: Optional[str] = None       # message-subject

    # Web / HTTP context
    url: Optional[str] = None
    url_category: Optional[str] = None   # PAN-OS / Forcepoint URL categorization
    http_method: Optional[str] = None    # GET / POST / HEAD
    http_status: Optional[int] = None
    user_agent: Optional[str] = None

    # Threat
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    threat_category: str = "unknown"
    cve: Optional[str] = None

    # File (for endpoint alerts)
    file_path: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_hash_sha1: Optional[str] = None

    # Trend Micro Vision One (Workbench) — carried from the email parser so the
    # backend can fetch alert detail / OAT and target the right region+console.
    # Not embedded (ids aren't semantic); ride to_dict() via asdict.
    v1_workbench_id: Optional[str] = None    # e.g. WB-18364-20260621-00001
    v1_console_host: Optional[str] = None    # e.g. portal.eu.xdr.trendmicro.com
    v1_region: Optional[str] = None          # e.g. eu (derived from the console host)

    # Decision (filled by analyst later)
    verdict: Optional[str] = None       # TP | FP | benign
    verdict_reason: Optional[str] = None
    analyst: Optional[str] = None

    # Feedback provenance (Tier-1 upgrade)
    # human_verified=True gates exact-match short-circuit in the skill.
    # feedback_source separates seeds from analyst decisions from overrides.
    human_verified: bool = False
    feedback_source: str = "seed"       # seed | analyst_decision | analyst_override

    # Event context (added Phase-RAG-B). All optional; consumers that don't
    # populate these keep the previous embedding behavior. When populated, the
    # event text is included in build_embed_text so semantically-different
    # alerts stop colliding on shared rule_name boilerplate.
    event_name:        Optional[str] = None    # e.g. "HTTP 302 - Object Moved"
    event_description: Optional[str] = None    # one paragraph
    event_category:    Optional[str] = None    # vendor's own category label

    # Storage
    embed_text: str = ""
    raw: str = ""

    def build_embed_text(self) -> str:
        """
        Construct a clean semantic text for embedding.
        Product-agnostic — focuses on WHAT happened, not HOW it was reported.
        """
        parts = []

        if self.rule_name:
            parts.append(f"Rule: {self.rule_name}")

        if self.threat_category != "unknown":
            parts.append(f"Threat category: {self.threat_category}")

        if self.cve:
            parts.append(f"CVE: {self.cve}")

        if self.src_ip:
            dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
            parts.append(f"Source IP: {self.src_ip} -> Target: {dst}")

        if self.username:
            parts.append(f"User: {self.username}")

        if self.hostname:
            parts.append(f"Host: {self.hostname}")

        if self.mitre_tactic and self.mitre_technique:
            parts.append(f"MITRE: {self.mitre_tactic} / {self.mitre_technique}")
        elif self.mitre_technique:
            parts.append(f"MITRE technique: {self.mitre_technique}")

        if self.file_path:
            parts.append(f"File: {self.file_path}")

        # Event context — the strongest discriminator for SIEM alerts that
        # share rule_name templates but describe different behaviors.
        if self.event_name:
            parts.append(f"Event: {self.event_name}")
        if self.event_category:
            parts.append(f"Event category: {self.event_category}")
        if self.event_description:
            # Cap at ~400 chars — embedders saturate quickly; the lede carries
            # the signal and longer descriptions just add noise tokens.
            desc = self.event_description.strip()[:400]
            parts.append(f"Description: {desc}")

        # HTTP / URL context — discriminative for web-app alerts.
        if self.url:
            parts.append(f"URL: {self.url}")
        if self.http_method or self.http_status:
            http_bits = []
            if self.http_method:
                http_bits.append(self.http_method)
            if self.http_status:
                http_bits.append(f"status {self.http_status}")
            parts.append("HTTP: " + " ".join(http_bits))

        parts.append(f"Severity: {self.severity} ({self.severity_label})")
        parts.append(f"Source: {self.source_product}")

        # Low-signal-alert weighting: when an alert has very few discriminating
        # fields (e.g. "Wazuh agent started" with no IOCs, no user, no CVE),
        # the generic boilerplate ("Severity: 12 (high)", "Source: wazuh")
        # dominates the embedding and similarity collapses onto shared SOC
        # vocabulary — a Cryptolocker FP can hit 0.87 against an agent-started
        # event because they both have "Severity: high" and "Source:" prefixes.
        #
        # Fix: when fewer than 6 content parts were collected, repeat the
        # rule_name twice at the top so it dominates the embedding. Doesn't
        # change behavior for normal alerts (they already have enough signal).
        if self.rule_name and len(parts) < 6:
            parts = [f"Rule: {self.rule_name}", f"Rule: {self.rule_name}"] + parts

        # Verdict is deliberately NOT embedded — keeps the vector stable across
        # FP/TP variants of the same alert pattern. Verdict lives in payload only.

        return "\n".join(parts)

    def finalize(self) -> "NormalizedAlert":
        """Call after setting all fields to compute derived fields."""
        self.severity_label = severity_label(self.severity)
        if self.threat_category == "unknown":
            combined = f"{self.rule_name or ''} {self.cve or ''}"
            self.threat_category = infer_category(combined)
        self.embed_text = self.build_embed_text()
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    def to_qdrant_payload(self) -> dict:
        """Returns metadata dict for Qdrant point payload (includes embed_text for verdict re-embedding)."""
        return self.to_dict()
