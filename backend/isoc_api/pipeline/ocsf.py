"""Pure OCSF entity mapper + canonical-key resolver.

Turns a NormalizedAlert dict into a flat list of resolved *entities* — devices,
users, network endpoints, files, and observables — each carrying a
deterministic ``canonical_key`` so that "the same real thing" (FQDN vs short
host, a source-view vs destination-view of one IP, a file seen with or without
its SHA-1) always collapses to one key.

Pure stdlib only (``ipaddress``, ``re``): no DB, no network, no side effects.
This module does *resolution*, not TI triage — private/loopback/link-local IPs
are kept and canonicalized, never dropped.

Entity dict shape (the only shape crossing module boundaries)::

    {
      "entity_type":   str,          # device|user|network_endpoint|file|observable
      "customer":      str | None,   # canonical customer id; None ONLY for global
      "canonical_key": str,          # deterministic resolution key
      "display_name":  str,          # human label (original casing where possible)
      "attributes":    dict,         # OCSF-shaped object
      "role":          str | None,   # source|destination|agent|subject|sender|recipient|...
    }

Tenancy: device/user/network_endpoint/most-observables are per-customer (key
prefixed with the canonical customer id, or ``unknown``); file + file-hash
observable are GLOBAL (customer=None, key prefixed ``global``).
"""

from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# OCSF observable type_ids (Observable enum) + a couple of OCSF entity type_ids.
# ---------------------------------------------------------------------------
OBS_HOSTNAME, OBS_IP, OBS_MAC, OBS_USERNAME, OBS_EMAIL = 1, 2, 3, 4, 5
OBS_URL, OBS_FILENAME, OBS_HASH, OBS_PROCESS, OBS_RESOURCE_UID = 6, 7, 8, 9, 10
OBS_CVE = OBS_RESOURCE_UID

USER_TYPE_SYSTEM = 3  # machine accounts (trailing '$') / SID-shaped principals
DEVICE_TYPE_FIREWALL = 9

# Products whose alerting host is itself a firewall/edge device.
_FIREWALL_PRODUCTS = {"fortigate", "panos", "paloalto"}

# SID: S-1-<authority>-<sub>... (case-insensitive), all-numeric sub-authorities.
# Any identifier-authority, not just NT Authority (5) — e.g. S-1-1-0 (Everyone),
# S-1-3-* (Creator), S-1-16-* (integrity labels), S-1-12-* (Azure AD). Requires at
# least one sub-authority so the authority-only "S-1-5" is not treated as a SID.
_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)

# Non-canonical characters in a customer id collapse to '-'.
_CUSTOMER_NONCANON_RE = re.compile(r"[^a-z0-9]+")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _clean(value: object) -> str | None:
    """Return a stripped string, or None for non-strings / empty / whitespace."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v or None


def _canon_customer(customer: str | None, normalized: dict | None = None) -> str:
    """Canonical customer slug: lowercased, non-[a-z0-9] runs -> '-', trimmed.

    Falls back to ``normalized['customer']`` then the literal ``unknown``.
    """
    raw = _clean(customer)
    if raw is None and normalized is not None:
        raw = _clean(normalized.get("customer"))
    if raw is None:
        return "unknown"
    slug = _CUSTOMER_NONCANON_RE.sub("-", raw.lower()).strip("-")
    return slug or "unknown"


def _canon_ip(value: str) -> str | None:
    """Canonicalize an IP: IPv6 -> RFC5952 compressed lower, IPv4-mapped -> v4.

    Returns None for a malformed address (never raises).
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip).lower()


def _short_host(hostname: str) -> str:
    """Short host label: lowercase, strip trailing '.', take label before first '.'.

    An IP-literal hostname is canonicalized as an IP instead of being domain-folded
    — otherwise distinct hosts that report themselves as bare IPs (RFC3164/5424
    syslog, QRadar log sources) would all collapse onto their first octet.
    """
    h = hostname.strip().rstrip(".").lower()
    canon = _canon_ip(h)
    if canon is not None:
        return canon
    return h.split(".", 1)[0]


def _is_machine_account(name: str) -> bool:
    return name.endswith("$")


# ---------------------------------------------------------------------------
# canonical_key — "same real thing => same key"
# ---------------------------------------------------------------------------
def canonical_key(entity_type: str, attrs: dict, customer: str | None = None) -> str:
    """Deterministic resolution key for one entity.

    Format: ``f"{scope}:{entity_type}:{typed_key}"`` with fixed parts lowercased.
    ``scope`` is the canonical customer id for host/user/ip/most-observables,
    and the literal ``global`` for files + file-hash observables.

    Raises ``ValueError`` for an unknown ``entity_type``.
    """
    scope = _canon_customer(customer)

    if entity_type == "device":
        uid = _clean(attrs.get("uid"))
        if uid is not None:
            return f"{scope}:device:uid:{uid.lower()}"
        hostname = _clean(attrs.get("hostname")) or _clean(attrs.get("name"))
        if hostname is not None:
            return f"{scope}:device:name:{_short_host(hostname)}"
        # No stable name identity — fall back to a canonicalized ip if present,
        # so IPv4-mapped/IPv6 forms of one host don't false-split.
        ip = _clean(attrs.get("ip"))
        canon = _canon_ip(ip) if ip is not None else None
        if canon is not None:
            return f"{scope}:device:ip:{canon}"
        raise ValueError("device entity has no uid/hostname/ip to key on")

    if entity_type == "user":
        name = _clean(attrs.get("name"))
        uid = _clean(attrs.get("uid"))
        # SID-shaped principals key on the SID (from name or uid).
        for candidate in (name, uid):
            if candidate is not None and _SID_RE.match(candidate):
                return f"{scope}:user:sid:{candidate.lower()}"
        # Email-party users (sender/recipient) key on the address.
        email = _clean(attrs.get("email_addr"))
        if email is not None and name is None:
            return f"{scope}:user:email:{email.lower()}"
        if name is None:
            if email is not None:
                return f"{scope}:user:email:{email.lower()}"
            if uid is not None:
                return f"{scope}:user:sid:{uid.lower()}"
            raise ValueError("user entity has no name/uid/email to key on")
        domain = _clean(attrs.get("domain"))
        if domain is not None:
            dom = domain.rstrip(".").lower()
            return f"{scope}:user:sam:{dom}\\{name.lower()}"
        return f"{scope}:user:sam:{name.lower()}"

    if entity_type == "network_endpoint":
        ip = _clean(attrs.get("ip"))
        canon = _canon_ip(ip) if ip is not None else None
        if canon is None:
            raise ValueError("network_endpoint entity has no valid ip to key on")
        return f"{scope}:network_endpoint:ip:{canon}"

    if entity_type == "file":
        sha256 = _clean(_hash_value(attrs, "SHA-256"))
        if sha256 is not None:
            return f"global:file:sha256:{sha256.lower()}"
        sha1 = _clean(_hash_value(attrs, "SHA-1"))
        if sha1 is not None:
            return f"global:file:sha1:{sha1.lower()}"
        raise ValueError("file entity has no sha256/sha1 to key on")

    if entity_type == "observable":
        type_id = attrs.get("type_id")
        value = _clean(attrs.get("value"))
        if value is None or type_id is None:
            raise ValueError("observable entity has no type_id/value to key on")
        obs_scope = "global" if type_id == OBS_HASH else scope
        # Hostname / IP observables fold through the SAME normalization as their
        # typed-entity counterparts (device short-host, endpoint IP canon), so a
        # single machine collapses to one observable key regardless of FQDN-vs-
        # short or IPv6-vs-mapped form. Other types key on the raw lowercased value.
        if type_id == OBS_HOSTNAME:
            typed = _short_host(value)
        elif type_id == OBS_IP:
            typed = _canon_ip(value) or value.strip().lower()
        else:
            typed = value.strip().lower()
        return f"{obs_scope}:observable:{type_id}:{typed}"

    raise ValueError(f"unknown entity_type: {entity_type!r}")


def _hash_value(attrs: dict, algorithm: str) -> str | None:
    """Pull a hash value for the given algorithm out of an OCSF file attrs dict."""
    for h in attrs.get("hashes") or []:
        if isinstance(h, dict) and h.get("algorithm") == algorithm:
            return h.get("value")
    return None


# ---------------------------------------------------------------------------
# Entity builders — each appends 0..n entity dicts to ``out``.
# ---------------------------------------------------------------------------
def _make(
    entity_type: str,
    attrs: dict,
    *,
    customer: str | None,
    display_name: str,
    role: str | None,
) -> dict | None:
    """Build one entity dict, or None if it cannot be keyed."""
    try:
        key = canonical_key(entity_type, attrs, customer)
    except ValueError:
        return None
    return {
        "entity_type": entity_type,
        "customer": customer,
        "canonical_key": key,
        "display_name": display_name,
        "attributes": attrs,
        "role": role,
    }


def _add_device(out: list[dict], n: dict, cust: str) -> None:
    hostname = _clean(n.get("hostname"))
    if hostname is None:
        return
    ip = _clean(n.get("agent_ip")) or _clean(n.get("src_ip"))
    source_product = (_clean(n.get("source_product")) or "").lower()
    type_id = DEVICE_TYPE_FIREWALL if source_product in _FIREWALL_PRODUCTS else 0
    attrs = {
        "hostname": hostname,
        "ip": ip,
        "uid": None,
        "name": hostname,
        "type_id": type_id,
    }
    ent = _make("device", attrs, customer=cust, display_name=hostname, role=None)
    if ent is not None:
        out.append(ent)


def _classify_user_type(name: str) -> int:
    """type_id for a user principal: machine account or SID => system(3)."""
    if _is_machine_account(name) or _SID_RE.match(name):
        return USER_TYPE_SYSTEM
    return 0


def _user_attrs_from_username(username: str) -> dict:
    """Parse a raw username into an OCSF user attrs dict (name/uid/domain/email/type)."""
    # SID-shaped principal.
    if _SID_RE.match(username):
        return {
            "name": None,
            "uid": username,
            "domain": None,
            "email_addr": None,
            "type_id": USER_TYPE_SYSTEM,
        }
    # DOMAIN\user
    if "\\" in username:
        domain, _, sam = username.partition("\\")
        return {
            "name": sam or None,
            "uid": None,
            "domain": domain or None,
            "email_addr": None,
            "type_id": _classify_user_type(sam),
        }
    # UPN user@domain
    if "@" in username:
        sam, _, domain = username.partition("@")
        return {
            "name": sam or None,
            "uid": None,
            "domain": (domain.rstrip(".") or None),
            "email_addr": username,
            "type_id": _classify_user_type(sam),
        }
    # bare username
    return {
        "name": username,
        "uid": None,
        "domain": None,
        "email_addr": None,
        "type_id": _classify_user_type(username),
    }


def _add_subject_user(out: list[dict], n: dict, cust: str) -> None:
    username = _clean(n.get("username"))
    if username is None:
        return
    attrs = _user_attrs_from_username(username)
    # DOMAIN\ with an empty user resolves to no name/uid/email -> skip.
    if attrs["name"] is None and attrs["uid"] is None and attrs["email_addr"] is None:
        return
    ent = _make("user", attrs, customer=cust, display_name=username, role="subject")
    if ent is not None:
        out.append(ent)


def _add_email_user(out: list[dict], addr: str, role: str, cust: str) -> None:
    attrs = {
        "name": None,
        "uid": None,
        "domain": None,
        "email_addr": addr,
        "type_id": 0,
    }
    ent = _make("user", attrs, customer=cust, display_name=addr, role=role)
    if ent is not None:
        out.append(ent)


def _add_email_users(out: list[dict], n: dict, cust: str) -> None:
    sender = _clean(n.get("sender"))
    if sender is not None:
        _add_email_user(out, sender, "sender", cust)
    recipient = _clean(n.get("recipient"))
    if recipient is not None:
        for part in recipient.split(";"):
            addr = _clean(part)
            if addr is not None:
                _add_email_user(out, addr, "recipient", cust)


def _add_endpoint(out: list[dict], ip: str | None, role: str, cust: str, port=None) -> None:
    ip = _clean(ip)
    if ip is None:
        return
    if _canon_ip(ip) is None:  # malformed -> skip (no raise)
        return
    attrs = {"ip": ip, "port": port, "hostname": None}
    ent = _make("network_endpoint", attrs, customer=cust, display_name=ip, role=role)
    if ent is not None:
        out.append(ent)


def _add_endpoints(out: list[dict], n: dict, cust: str) -> None:
    _add_endpoint(out, n.get("src_ip"), "source", cust)
    dst_port = n.get("dst_port")
    _add_endpoint(out, n.get("dst_ip"), "destination", cust, port=dst_port)
    _add_endpoint(out, n.get("agent_ip"), "agent", cust)


def _add_file(out: list[dict], n: dict) -> None:
    sha256 = _clean(n.get("file_hash_sha256"))
    sha1 = _clean(n.get("file_hash_sha1"))
    if sha256 is None and sha1 is None:
        return  # path alone is not a global identity — no file entity.
    file_path = _clean(n.get("file_path"))
    basename = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if file_path else None
    hashes: list[dict] = []
    if sha256 is not None:
        hashes.append({"algorithm": "SHA-256", "value": sha256.lower()})
    if sha1 is not None:
        hashes.append({"algorithm": "SHA-1", "value": sha1.lower()})
    attrs = {"name": basename, "path": file_path, "hashes": hashes}
    display = basename or (sha256 or sha1)
    ent = _make("file", attrs, customer=None, display_name=display, role=None)
    if ent is not None:
        out.append(ent)


def _add_observable(
    out: list[dict], label: str, type_id: int, value: str | None, cust: str
) -> None:
    value = _clean(value)
    if value is None:
        return
    is_global = type_id == OBS_HASH
    attrs = {"name": label, "type_id": type_id, "value": value, "reputation": None}
    ent = _make(
        "observable",
        attrs,
        customer=None if is_global else cust,
        display_name=value,
        role="observable",
    )
    if ent is not None:
        out.append(ent)


def _add_observables(out: list[dict], n: dict, cust: str) -> None:
    _add_observable(out, "hostname", OBS_HOSTNAME, n.get("hostname"), cust)
    _add_observable(out, "src_ip", OBS_IP, n.get("src_ip"), cust)
    _add_observable(out, "dst_ip", OBS_IP, n.get("dst_ip"), cust)
    _add_observable(out, "agent_ip", OBS_IP, n.get("agent_ip"), cust)
    _add_observable(out, "username", OBS_USERNAME, n.get("username"), cust)
    _add_observable(out, "sender", OBS_EMAIL, n.get("sender"), cust)
    recipient = _clean(n.get("recipient"))
    if recipient is not None:
        for part in recipient.split(";"):
            _add_observable(out, "recipient", OBS_EMAIL, part, cust)
    _add_observable(out, "url", OBS_URL, n.get("url"), cust)
    # File basename observable — emitted even when there's no hash (path-only case).
    file_path = _clean(n.get("file_path"))
    if file_path is not None:
        basename = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        _add_observable(out, "file_name", OBS_FILENAME, basename, cust)
    # Hashes are GLOBAL observables.
    _add_observable(out, "file_hash_sha256", OBS_HASH, n.get("file_hash_sha256"), cust)
    _add_observable(out, "file_hash_sha1", OBS_HASH, n.get("file_hash_sha1"), cust)
    # CVE -> observable type_id=10, value lowercased.
    cve = _clean(n.get("cve"))
    if cve is not None:
        _add_observable(out, "cve", OBS_CVE, cve.lower(), cust)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def to_entities(normalized: dict, customer: str | None = None) -> list[dict]:
    """Map a NormalizedAlert dict to a deduplicated list of entity dicts.

    ``customer`` overrides ``normalized['customer']`` for tenancy scoping. The
    result is deduplicated by ``canonical_key`` — the first occurrence wins
    (its role/display_name are kept; roles are not merged).
    """
    if not isinstance(normalized, dict):
        return []
    cust = _canon_customer(customer, normalized)

    out: list[dict] = []
    _add_device(out, normalized, cust)
    _add_subject_user(out, normalized, cust)
    _add_email_users(out, normalized, cust)
    _add_endpoints(out, normalized, cust)
    _add_file(out, normalized)
    _add_observables(out, normalized, cust)

    # Dedup by canonical_key, first occurrence wins.
    seen: set[str] = set()
    deduped: list[dict] = []
    for ent in out:
        key = ent["canonical_key"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ent)
    return deduped


# ---------------------------------------------------------------------------
# OCSF event envelope (ADR-0006 P1c) — the *event* companion to to_entities'
# *entity* list. OCSF Detection Finding: category_uid 2 ("Findings"),
# class_uid 2004. Additive + pure; does not replace incident.normalized.
# ---------------------------------------------------------------------------
OCSF_CATEGORY_FINDINGS = 2
OCSF_CLASS_DETECTION_FINDING = 2004
# Mirrors adapters.connectors.severity.SEVERITY_ID_LABEL (kept inline to preserve this
# module's stdlib-only contract).
_SEVERITY_ID_LABEL = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}
_ENTITY_TO_OBS_TYPE = {
    "device": OBS_HOSTNAME,
    "user": OBS_USERNAME,
    "network_endpoint": OBS_IP,
    "file": OBS_FILENAME,
}


def _event_observables(entities: list[dict]) -> list[dict]:
    """Compact OCSF observables from resolved entities (name/type_id/value)."""
    obs: list[dict] = []
    for e in entities:
        et = e.get("entity_type") or ""
        type_id = _ENTITY_TO_OBS_TYPE.get(et)
        if type_id is None:  # an 'observable' entity carries its OCSF type in attributes
            type_id = (e.get("attributes") or {}).get("type_id") or OBS_RESOURCE_UID
        obs.append({"name": et, "type_id": type_id, "value": e.get("display_name")})
    return obs


def to_ocsf_event(normalized: dict, customer: str | None = None) -> dict:
    """Map a NormalizedAlert dict to a minimal OCSF Detection Finding (2004) envelope.

    Carries the OCSF ``severity_id`` (stamped by ``parser_adapter._with_ocsf_severity``), the
    product, a ``finding_info`` title, and the resolved observables — a standards-shaped view of
    the alert the rest of the system can converge on. Pure; returns ``{}`` for a non-dict input.
    """
    if not isinstance(normalized, dict):
        return {}
    sev_id = normalized.get("severity_id")
    if not isinstance(sev_id, int) or sev_id < 0 or sev_id > 6:
        sev_id = 0
    product = _clean(normalized.get("source_product")) or "unknown"
    title = _clean(normalized.get("rule_name")) or _clean(normalized.get("event_name")) or "Alert"
    entities = to_entities(normalized, customer)
    return {
        "category_uid": OCSF_CATEGORY_FINDINGS,
        "class_uid": OCSF_CLASS_DETECTION_FINDING,
        "activity_id": 1,  # Create
        "type_uid": OCSF_CLASS_DETECTION_FINDING * 100 + 1,
        "severity_id": sev_id,
        "severity": _SEVERITY_ID_LABEL.get(sev_id, "Unknown"),
        "metadata": {"product": {"name": product}, "version": "1.3.0"},
        "finding_info": {"title": title, "uid": _clean(normalized.get("alert_id"))},
        "time": normalized.get("timestamp"),
        "message": _clean(normalized.get("event_description")) or title,
        "observables": _event_observables(entities),
    }
