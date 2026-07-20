"""EASM recon adapter — the impure, network-touching layer.

On-demand, read-only reconnaissance of a single asset: DNS records (A/AAAA/MX/NS/
TXT), the email-auth posture (SPF/DMARC), TLS certificate expiry, and a WHOIS
summary. All lookups are best-effort and time-bounded; failures degrade to empty
results + an `errors` note rather than raising. Nothing here changes external
state — it only observes. The pure grading/scoring lives in `easm/recon.py`.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any

from ..easm import recon
from ..logging_config import get_logger

logger = get_logger("isoc.adapter.recon")

_DNS_TIMEOUT = 5.0
_TLS_TIMEOUT = 5.0
_NMAP_TIMEOUT = 120.0


def _resolve(name: str, rdtype: str) -> list[str]:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT
        resolver.timeout = _DNS_TIMEOUT
        ans = resolver.resolve(name, rdtype)
        out = []
        for r in ans:
            txt = r.to_text()
            # TXT records arrive quoted and possibly split — join + unquote.
            if rdtype == "TXT":
                txt = "".join(part.strip('"') for part in txt.split('" "'))
                txt = txt.strip('"')
            out.append(txt.strip())
        return out
    except Exception:
        return []


def _tls_expiry(host: str, port: int = 443) -> dict[str, Any] | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []) if x)
        return {
            "expires_at": expires.isoformat(),
            "days_remaining": days,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "status": recon.cert_status(days),
        }
    except Exception as e:
        logger.info("recon.tls_failed", host=host, error=str(e))
        return None


def _whois(domain: str) -> dict[str, Any] | None:
    try:
        import whois

        w = whois.whois(domain)

        def _one(v):
            if isinstance(v, list):
                v = v[0] if v else None
            if isinstance(v, datetime):
                return v.isoformat()
            return str(v) if v else None

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        return {
            "registrar": str(registrar) if registrar else None,
            "created": _one(w.creation_date),
            "expires": _one(w.expiration_date),
        }
    except Exception as e:
        logger.info("recon.whois_failed", domain=domain, error=str(e))
        return None


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _scan_sync(value: str, asset_type: str) -> dict[str, Any]:
    """Blocking scan body — run via asyncio.to_thread."""
    errors: list[str] = []
    result: dict[str, Any] = {
        "value": value,
        "asset_type": asset_type,
        "dns": {},
        "rdns": None,
        "posture": {},
        "tls": None,
        "whois": None,
        "errors": errors,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    if asset_type == "ip":
        result["rdns"] = _reverse_dns(value)
        # nothing more to resolve for a bare IP
        result["risk"] = recon.risk_score(result)
        return result

    host = recon.normalize_host(value)
    a = _resolve(host, "A")
    aaaa = _resolve(host, "AAAA")
    mx = _resolve(host, "MX")
    ns = _resolve(host, "NS")
    txt = _resolve(host, "TXT")
    dmarc_txt = _resolve(f"_dmarc.{host}", "TXT")
    result["dns"] = {"a": a, "aaaa": aaaa, "mx": mx, "ns": ns, "txt": txt}
    result["posture"] = recon.grade_dns_posture(txt, dmarc_txt, mx)

    if not (a or aaaa):
        errors.append(f"Could not resolve {host}")

    # TLS only makes sense for things that terminate HTTPS
    if a or aaaa:
        result["tls"] = _tls_expiry(host)

    # WHOIS on the registrable host
    result["whois"] = _whois(host)

    result["risk"] = recon.risk_score(result)
    return result


def _portscan_sync(host: str) -> dict[str, Any]:
    """Blocking nmap port + service/version scan → run via asyncio.to_thread."""
    target = recon.normalize_host(host) or host
    # -sT connect scan (no root) · -sV service/version (the 'technology') ·
    # --top-ports 200 fast coverage · bounded host-timeout · `--` stops a target
    # that looks like a flag · -oX - emits XML to stdout (args are a list → no
    # shell, no injection).
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "--top-ports",
        "200",
        "--host-timeout",
        "90s",
        "-T4",
        "-oX",
        "-",
        "--",
        target,
    ]
    now = datetime.now(timezone.utc).isoformat()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_NMAP_TIMEOUT)
        ports = recon.parse_nmap_xml(proc.stdout)
        err = (
            None
            if (proc.returncode == 0 or ports)
            else (proc.stderr or "nmap failed").strip()[:200]
        )
        return {"ports": ports, "ports_scanned_at": now, "ports_error": err}
    except FileNotFoundError:
        return {"ports": [], "ports_scanned_at": now, "ports_error": "nmap not installed"}
    except subprocess.TimeoutExpired:
        return {"ports": [], "ports_scanned_at": now, "ports_error": "nmap timed out"}
    except Exception as e:  # pragma: no cover — defensive
        logger.warning("recon.portscan_failed", host=host, error=str(e))
        return {"ports": [], "ports_scanned_at": now, "ports_error": str(e)[:200]}


async def port_scan(host: str) -> dict[str, Any]:
    """On-demand nmap port + service/version scan, off the event loop. Read-only
    observation of exposed services. Returns {ports, ports_scanned_at, ports_error}."""
    return await asyncio.to_thread(_portscan_sync, host)


async def scan_asset(value: str, asset_type: str | None = None) -> dict[str, Any]:
    """Run the recon scan off the event loop. Read-only + best-effort."""
    at = asset_type or recon.classify_asset(value)
    try:
        return await asyncio.to_thread(_scan_sync, value, at)
    except Exception as e:  # pragma: no cover — defensive
        logger.warning("recon.scan_failed", value=value, error=str(e))
        return {
            "value": value,
            "asset_type": at,
            "dns": {},
            "posture": {},
            "tls": None,
            "whois": None,
            "errors": [f"scan failed: {e}"],
            "risk": {"score": 0, "level": "low", "reasons": []},
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
