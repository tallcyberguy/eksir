"""EASM recon — the PURE scoring/grading layer (no network).

AiSOC's EASM screen is static mock data. isoc computes a real one: an asset
register the analyst manages, plus on-demand recon (DNS records, SPF/DKIM/DMARC
posture, TLS cert expiry, WHOIS). The *network* lives in `adapters/recon_adapter.py`;
everything here is pure — it grades and scores the raw results so it can be unit
tested without DNS. Recon is read-only; nothing here changes external state.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from xml.etree import ElementTree as ET

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$", re.I)


def classify_asset(value: str) -> str:
    """Best-effort asset-type guess: ip / url / domain / subdomain."""
    v = (value or "").strip()
    if "://" in v:
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(v):
        # >2 labels (and not a bare 2-label apex) → treat as subdomain
        labels = v.split(".")
        return "subdomain" if len(labels) > 2 else "domain"
    return "domain"


def normalize_host(value: str) -> str:
    """Strip scheme/path/port so a domain or URL becomes a bare host for DNS/TLS."""
    v = (value or "").strip()
    v = re.sub(r"^[a-z0-9+.-]+://", "", v, flags=re.I)  # scheme
    v = v.split("/", 1)[0]  # path
    v = v.split("@")[-1]  # userinfo
    v = v.split(":", 1)[0]  # port
    return v.strip(".").lower()


# ── TLS certificate ──────────────────────────────────────────────────────────
def cert_status(days_remaining: int | None) -> str:
    if days_remaining is None:
        return "unknown"
    if days_remaining < 0:
        return "expired"
    if days_remaining <= 30:
        return "expiring"
    return "valid"


# ── DNS / email authentication posture ───────────────────────────────────────
def _spf_record(txt: list[str]) -> str | None:
    for r in txt or []:
        if r.lower().startswith("v=spf1"):
            return r
    return None


def _dmarc_policy(dmarc_txt: list[str]) -> str | None:
    for r in dmarc_txt or []:
        if r.lower().startswith("v=dmarc1"):
            m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", r, re.I)
            return m.group(1).lower() if m else "none"
    return None


def grade_dns_posture(
    txt: list[str] | None,
    dmarc_txt: list[str] | None,
    mx: list[str] | None,
) -> dict[str, Any]:
    """Grade SPF/DMARC/MX. 'posture' ∈ strong/moderate/weak/none with findings.

    strong  = SPF + DMARC enforcing (quarantine|reject)
    moderate= SPF + DMARC p=none  (monitoring only)
    weak    = SPF or DMARC, not both / not enforcing
    none    = neither
    """
    spf = _spf_record(txt or [])
    dmarc_policy = _dmarc_policy(dmarc_txt or [])
    has_spf = spf is not None
    has_dmarc = dmarc_policy is not None
    has_mx = bool(mx)

    findings: list[str] = []
    if not has_spf:
        findings.append("No SPF record — sender forgery is easier.")
    if not has_dmarc:
        findings.append("No DMARC record — no alignment policy published.")
    elif dmarc_policy == "none":
        findings.append("DMARC p=none — monitoring only, not enforcing.")
    if has_mx and not (has_spf and has_dmarc):
        findings.append("Mail-receiving domain without full SPF+DMARC.")

    if has_spf and has_dmarc and dmarc_policy in ("quarantine", "reject"):
        posture = "strong"
    elif has_spf and has_dmarc:
        posture = "moderate"
    elif has_spf or has_dmarc:
        posture = "weak"
    else:
        posture = "none"

    return {
        "spf": has_spf,
        "dmarc": has_dmarc,
        "dmarc_policy": dmarc_policy,
        "mx": has_mx,
        "posture": posture,
        "findings": findings,
    }


# ── Port / technology scan (nmap) ────────────────────────────────────────────
# Services that are notable when exposed to the public internet — admin planes,
# file shares, databases, and cleartext protocols. Keyed by both port and the
# nmap-reported service name (catches non-standard ports).
_RISKY_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet (cleartext)",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    3389: "RDP",
    5900: "VNC",
    161: "SNMP",
    389: "LDAP",
    2049: "NFS",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    5985: "WinRM",
    5986: "WinRM",
}
_RISKY_SERVICES: dict[str, str] = {
    "telnet": "Telnet (cleartext)",
    "ftp": "FTP",
    "microsoft-ds": "SMB",
    "netbios-ssn": "NetBIOS",
    "ms-wbt-server": "RDP",
    "vnc": "VNC",
    "mysql": "MySQL",
    "ms-sql-s": "MSSQL",
    "postgresql": "PostgreSQL",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "memcached": "Memcached",
    "snmp": "SNMP",
    "ldap": "LDAP",
    "rpcbind": "RPCbind",
    "nfs": "NFS",
}


def parse_nmap_xml(xml: str) -> list[dict[str, Any]]:
    """Parse nmap `-oX` output → list of OPEN ports with service/version. Pure +
    tolerant — malformed/empty XML yields []. Each entry: port, proto, service,
    product, version, tunnel."""
    out: list[dict[str, Any]] = []
    if not xml or not xml.strip():
        return out
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        try:
            portid = int(port.get("portid", "0"))
        except ValueError:
            portid = 0
        out.append(
            {
                "port": portid,
                "proto": port.get("protocol", "tcp"),
                "service": (svc.get("name") if svc is not None else None),
                "product": (svc.get("product") if svc is not None else None),
                "version": (svc.get("version") if svc is not None else None),
                "tunnel": (svc.get("tunnel") if svc is not None else None),
            }
        )
    out.sort(key=lambda p: p["port"])
    return out


def port_risk(ports: list[dict]) -> dict[str, Any]:
    """Score exposed ports. Risky admin/db/cleartext services raise risk; many
    open ports add a little. Pure + explainable (`reasons` is the audit trail)."""
    risky: list[str] = []
    seen: set[str] = set()
    for p in ports or []:
        label = _RISKY_PORTS.get(p.get("port")) or _RISKY_SERVICES.get(
            str(p.get("service") or "").lower()
        )
        if label and label not in seen:
            seen.add(label)
            risky.append(f"{label} exposed (port {p.get('port')})")
    score = min(50, 14 * len(risky))
    open_n = len(ports or [])
    if open_n > 10:
        score = min(60, score + 8)
    reasons = list(risky)
    if open_n > 10:
        reasons.append(f"{open_n} open ports (broad exposure)")
    return {"open_count": open_n, "risky_count": len(risky), "score": score, "reasons": reasons}


# ── Risk score ───────────────────────────────────────────────────────────────
_POSTURE_PENALTY = {"strong": 0, "moderate": 12, "weak": 28, "none": 40, None: 10}


def risk_score(result: dict[str, Any]) -> dict[str, Any]:
    """Deterministic 0-100 risk from a scan result. Higher = worse.

    Inputs used: tls.days_remaining, posture, dns presence. Pure + explainable —
    the `reasons` list is the audit trail.
    """
    score = 0
    reasons: list[str] = []

    tls = result.get("tls") or {}
    days = tls.get("days_remaining")
    st = cert_status(days)
    if st == "expired":
        score += 45
        reasons.append("TLS certificate expired")
    elif st == "expiring":
        score += 22
        reasons.append(f"TLS certificate expires in {days}d")

    posture = (result.get("posture") or {}).get("posture")
    pen = _POSTURE_PENALTY.get(posture, 10)
    if pen:
        score += pen
        reasons.append(f"Email auth posture: {posture or 'unknown'}")

    dns = result.get("dns") or {}
    if not (dns.get("a") or dns.get("aaaa")) and result.get("asset_type") in (
        "domain",
        "subdomain",
        "url",
    ):
        score += 15
        reasons.append("No A/AAAA record resolved")

    ports = result.get("ports")
    if ports:
        pr = port_risk(ports)
        score += pr["score"]
        reasons.extend(pr["reasons"])

    for e in result.get("errors") or []:
        reasons.append(e)

    score = max(0, min(100, score))
    level = (
        "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
    )
    return {"score": score, "level": level, "reasons": reasons}


# ── Register-wide summary ────────────────────────────────────────────────────
def summarize(assets: list[dict]) -> dict[str, Any]:
    """KPI rollup over the asset register. Each asset carries its last `result`
    (may be None if never scanned)."""
    total = len(assets)
    by_type: dict[str, int] = {}
    cert_issues = weak_posture = scanned = 0
    open_ports = risky_ports = 0
    risk_sum = 0
    risk_max = 0
    for a in assets:
        by_type[a.get("asset_type", "domain")] = by_type.get(a.get("asset_type", "domain"), 0) + 1
        res = a.get("last_result") or {}
        if not res:
            continue
        scanned += 1
        st = cert_status((res.get("tls") or {}).get("days_remaining"))
        if st in ("expired", "expiring"):
            cert_issues += 1
        if (res.get("posture") or {}).get("posture") in ("weak", "none"):
            weak_posture += 1
        ports = res.get("ports") or []
        open_ports += len(ports)
        risky_ports += port_risk(ports)["risky_count"] if ports else 0
        rs = (res.get("risk") or {}).get("score", 0)
        risk_sum += rs
        risk_max = max(risk_max, rs)
    return {
        "total_assets": total,
        "scanned": scanned,
        "by_type": by_type,
        "cert_issues": cert_issues,
        "weak_posture": weak_posture,
        "open_ports": open_ports,
        "risky_ports": risky_ports,
        "avg_risk": round(risk_sum / scanned) if scanned else 0,
        "max_risk": risk_max,
    }
