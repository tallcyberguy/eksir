"""Native OCSF-first parser for Microsoft Defender Graph ``alerts_v2``.

First of the isoc_api-side parsers that supersede the retiring vendored ones as
the project moves to connector-based OCSF ingestion (see CLAUDE.md). Maps a Graph
Security alert (``GET /security/alerts_v2``) to a ``NormalizedAlert`` covering the
FULL polymorphic ``evidence[]`` set — crucially the Defender-for-Office-365 email
evidence (``analyzedMessageEvidence``, ``mailboxEvidence``) the vendored parser
dropped. ``pipeline/ocsf.py`` then derives OCSF entities + a Detection Finding
from the normalized alert, so complete parsing yields complete OCSF.

Defensive by design: every field optional, a missing/garbled section is left
None, the parser never raises. Evidence field paths verified against a live
tenant (2026-07) + the public Graph Security v1.0 alert/alertEvidence schema.
"""

from __future__ import annotations

import json
import re
from typing import Any

# The vendored ``normalizer`` is imported lazily inside ``parse`` so importing this
# module stays cheap on the host (parser_adapter imports it at module top).

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# Graph severity word -> Wazuh-style 1-15 int (finalize derives the shared label).
_SEVERITY = {"high": 10, "medium": 6, "low": 3, "informational": 1, "unknown": 3}


def _clean(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v or None


def _evtype(ev: dict) -> str:
    return str(ev.get("@odata.type") or "").lower()


def _first_email(*senders: object) -> str | None:
    """First ``emailAddress`` across the given emailSender objects (p2 preferred)."""
    for s in senders:
        if isinstance(s, dict):
            addr = _clean(s.get("emailAddress"))
            if addr:
                return addr
    return None


def mde_device_id(raw: Any) -> str | None:
    """First Defender-for-Endpoint device id (``deviceEvidence.mdeDeviceId``) in the alert.

    Accepts the raw alerts_v2 dict or its JSON string (``normalized['raw']``). Returns None
    when there's no device evidence (e.g. email/MDO alerts), so a gate isolate is only ever
    proposed for endpoint alerts that actually name a device.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return None
    if not isinstance(raw, dict):
        return None
    for ev in raw.get("evidence") or []:
        if isinstance(ev, dict) and "deviceevidence" in _evtype(ev):
            mid = _clean(ev.get("mdeDeviceId"))
            if mid:
                return mid
    return None


def entra_user_id(raw: Any) -> str | None:
    """Entra user id for disable-user: ``userEvidence.userAccount.azureAdUserId`` (object id)
    or ``userPrincipalName``. Accepts the raw dict or ``normalized['raw']`` JSON. Returns None
    when no user account has a Graph-addressable id (a bare accountName/sAMAccountName won't do).
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return None
    if not isinstance(raw, dict):
        return None
    for ev in raw.get("evidence") or []:
        if isinstance(ev, dict) and "userevidence" in _evtype(ev):
            acct = ev.get("userAccount") or {}
            uid = _clean(acct.get("azureAdUserId")) or _clean(acct.get("userPrincipalName"))
            if uid:
                return uid
    return None


def _take_hashes_and_path(alert: Any, details: object) -> None:
    """Fill file hash/path from a fileDetails-shaped object (first occurrence wins)."""
    if not isinstance(details, dict):
        return
    sha256, sha1 = details.get("sha256"), details.get("sha1")
    if sha256 and _SHA256_RE.match(str(sha256)) and not alert.file_hash_sha256:
        alert.file_hash_sha256 = str(sha256).lower()
    if sha1 and _SHA1_RE.match(str(sha1)) and not alert.file_hash_sha1:
        alert.file_hash_sha1 = str(sha1).lower()
    if not alert.file_path:
        alert.file_path = _clean(details.get("filePath")) or _clean(details.get("fileName"))


def parse(raw: Any, customer: str | None = None) -> Any:
    """Map a Graph ``alerts_v2`` alert (dict or JSON str) to a finalized NormalizedAlert."""
    from normalizer import NormalizedAlert  # type: ignore[import-not-found]

    data = raw if isinstance(raw, dict) else {}
    ev_raw = data.get("evidence")
    evidence = ev_raw if isinstance(ev_raw, list) else []

    a = NormalizedAlert()
    a.source_product = "microsoft_defender"
    a.customer = customer
    a.raw = json.dumps(data, ensure_ascii=False, default=str)

    alert_id = _clean(data.get("id"))
    if alert_id:
        a.rule_id = alert_id
        a.alert_id = alert_id  # stable finding uid (overrides the NormalizedAlert uuid default)
    title = _clean(data.get("title"))
    if title:
        a.rule_name = title
        a.event_name = title
    desc = _clean(data.get("description"))
    if desc:
        a.event_description = desc
    # categories[0] -> deprecated `category` -> threatFamilyName, in that order.
    cats = data.get("categories")
    category = (
        (cats[0] if isinstance(cats, list) and cats else None)
        or data.get("category")
        or data.get("threatFamilyName")
    )
    category = _clean(category)
    if category:
        a.threat_category = category
    a.severity = _SEVERITY.get(str(data.get("severity") or "").lower(), 3)
    a.timestamp = data.get("createdDateTime")

    techniques = data.get("mitreTechniques")
    if isinstance(techniques, list):
        for t in techniques:
            if _TECHNIQUE_RE.match(str(t)):
                a.mitre_technique = str(t)
                break

    # Walk the polymorphic evidence array; first occurrence of each field wins.
    process_cmds: list[str] = []
    mailbox_addr: str | None = None
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        etype = _evtype(ev)
        if "deviceevidence" in etype and not a.hostname:
            a.hostname = _clean(ev.get("deviceDnsName")) or _clean(ev.get("hostName"))
        elif "ipevidence" in etype and not a.src_ip:
            a.src_ip = _clean(ev.get("ipAddress"))
        elif "userevidence" in etype and not a.username:
            acct = ev.get("userAccount") or {}
            a.username = _clean(acct.get("accountName")) or _clean(acct.get("userPrincipalName"))
        elif "fileevidence" in etype:
            _take_hashes_and_path(a, ev.get("fileDetails"))
        elif "processevidence" in etype:
            _take_hashes_and_path(a, ev.get("imageFile"))
            if ev.get("processCommandLine"):
                process_cmds.append(str(ev["processCommandLine"])[:500])
            if not a.username:
                acct = ev.get("userAccount") or {}
                a.username = _clean(acct.get("accountName")) or _clean(
                    acct.get("userPrincipalName")
                )
        elif "urlevidence" in etype and not a.url:
            a.url = _clean(ev.get("url"))
        elif "analyzedmessageevidence" in etype:
            # The email fix: sender/recipient/subject the vendored parser never read.
            if not a.sender:
                a.sender = _first_email(ev.get("p2Sender"), ev.get("p1Sender"))
            if not a.recipient:
                a.recipient = _clean(ev.get("recipientEmailAddress"))
            if not a.subject:
                a.subject = _clean(ev.get("subject"))
            if not a.src_ip:
                a.src_ip = _clean(ev.get("senderIp"))
        elif "mailboxevidence" in etype and mailbox_addr is None:
            mailbox_addr = _clean(ev.get("primaryAddress")) or _clean(ev.get("upn"))

    # The mailbox is the affected recipient/user when message evidence didn't name one.
    if not a.recipient and mailbox_addr:
        a.recipient = mailbox_addr
    if not a.username and mailbox_addr:
        a.username = mailbox_addr

    if process_cmds:
        base = (a.event_description or "").rstrip()
        cmds = "\n".join(f"cmdline: {c}" for c in process_cmds[:3])
        a.event_description = (base + "\n" + cmds).strip()

    return a.finalize()
