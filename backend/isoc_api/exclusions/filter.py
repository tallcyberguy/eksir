"""Apply analyst-curated exclusions to a list of extracted IOCs.

Returns (kept, excluded). `excluded` items carry the reason — both the matched
rule's value and the notes (if any) — so the LLM briefing can render them
transparently.

Performance: one query per pipeline run (we load enabled exclusions once and
match in Python). Total exclusion count is expected to stay small (<<10k)
so the loaded set fits comfortably in memory.
"""

from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Exclusion


async def apply(
    session: AsyncSession,
    iocs: list[tuple[str, str]],
    customer: str | None = None,
) -> tuple[list[tuple[str, str]], list[dict]]:
    """Split extracted IOCs into (kept, excluded).

    `iocs`: [(ioc_type_from_extractor, value), ...]  — extractor uses
            "ipv4" / "ipv6" / "domain" / "url" / "sha256" / etc.
    `customer`: the incident's customer. Per-customer-scoped rules (F8) only
            apply when their `customer` matches; global rules (customer NULL)
            always apply.
    Returns:
        kept     — same shape as input, minus the excluded ones
        excluded — [{value, ioc_type, reason}, ...]
    """
    if not iocs:
        return [], []

    rules = (await session.scalars(select(Exclusion).where(Exclusion.enabled.is_(True)))).all()
    # Drop rules scoped to a different customer than this incident's.
    rules = [r for r in rules if not getattr(r, "customer", None) or r.customer == customer]
    if not rules:
        return list(iocs), []

    # Bucket rules by type — avoid scanning all rules per IOC.
    ip_exact: dict[str, Exclusion] = {}
    cidr_nets: list[tuple[ipaddress._BaseNetwork, Exclusion]] = []
    domain_exact: dict[str, Exclusion] = {}
    domain_suffix: list[tuple[str, Exclusion]] = []  # endswith ".value"
    hash_exact: dict[str, Exclusion] = {}

    for r in rules:
        v = (r.value or "").strip()
        if not v:
            continue
        if r.ioc_type == "ip":
            ip_exact[v] = r
        elif r.ioc_type == "cidr":
            try:
                cidr_nets.append((ipaddress.ip_network(v, strict=False), r))
            except ValueError:
                continue
        elif r.ioc_type == "domain":
            lo = v.lower()
            domain_exact[lo] = r
            domain_suffix.append(("." + lo, r))
        elif r.ioc_type == "hash":
            hash_exact[v.lower()] = r

    kept: list[tuple[str, str]] = []
    excluded: list[dict] = []

    for ioc_type, value in iocs:
        if not (isinstance(value, str) and value.strip()):
            kept.append((ioc_type, value))
            continue

        v = value.strip()
        v_lo = v.lower()
        hit: Exclusion | None = None

        if ioc_type in ("ipv4", "ipv6"):
            hit = ip_exact.get(v)
            if not hit:
                try:
                    ip_obj = ipaddress.ip_address(v)
                    for net, rule in cidr_nets:
                        if ip_obj in net:
                            hit = rule
                            break
                except ValueError:
                    pass
        elif ioc_type in ("domain", "url", "email"):
            # Resolve the host to match against domain rules:
            #   url   → host part of the URL
            #   email → domain part (after @)  ← lets ONE domain exclusion
            #           (e.g. the customer domain) suppress the domain itself
            #           AND every address at it, managed in one place.
            #   domain→ the value as-is
            if ioc_type == "url":
                host = _host_of(v_lo)
            elif ioc_type == "email":
                host = v_lo.rsplit("@", 1)[-1].strip().rstrip(".") if "@" in v_lo else None
            else:
                host = v_lo
            if host:
                hit = domain_exact.get(host)
                if not hit:
                    for suffix, rule in domain_suffix:
                        if host.endswith(suffix):
                            hit = rule
                            break
        elif ioc_type in ("sha256", "sha1", "md5"):
            hit = hash_exact.get(v_lo)

        if hit:
            reason = f"rule `{hit.ioc_type}:{hit.value}`"
            if hit.notes:
                reason += f" — {hit.notes}"
            excluded.append({"value": value, "ioc_type": ioc_type, "reason": reason})
        else:
            kept.append((ioc_type, value))

    return kept, excluded


def _host_of(url: str) -> str | None:
    """Extract the lowercase host from a URL. Conservative; returns None on
    anything that doesn't look like a real URL."""
    try:
        after_scheme = url.split("://", 1)[1] if "://" in url else url
        host = after_scheme.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split("@", 1)[-1]  # drop userinfo
        host = host.split(":", 1)[0]  # drop port
        return host or None
    except (IndexError, AttributeError):
        return None
