"""Tests for the native OCSF-first Microsoft Defender parser (adapters/ocsf_defender.py).

Payloads mirror the real Graph ``alerts_v2`` evidence shapes captured from a live tenant:
email (Defender-for-Office-365) alerts carry ``analyzedMessageEvidence`` + ``mailboxEvidence``,
endpoint alerts carry ``deviceEvidence`` + ``fileEvidence`` + ``processEvidence``. The key
regression this locks in: sender/recipient/subject are now extracted (the vendored parser
dropped them), so ``pipeline/ocsf.py`` emits the sender/recipient email-user entities.

The parser builds a vendored ``NormalizedAlert``; we put the vendored package on the path here
so the test runs on the host like the other pure tests.
"""

from __future__ import annotations

import os
import sys

_VENDOR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
)
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

from isoc_api.adapters import ocsf_defender, parser_adapter  # noqa: E402
from isoc_api.pipeline import ocsf  # noqa: E402


def _parse(alert, customer: str = "acme") -> dict:
    """parse() returns a NormalizedAlert (parser_adapter finalizes/to_dicts it); the pure
    parser tests want the dict shape, so unwrap it here."""
    return ocsf_defender.parse(alert, customer=customer).to_dict()


# ── realistic payloads (real evidence shapes, synthetic values) ───────────────

EMAIL_ALERT = {
    "id": "email-1",
    "title": "Email messages containing malicious URL removed after delivery",
    "description": "A message with a malicious URL was delivered then removed.",
    "severity": "low",
    "categories": ["Phishing"],
    "createdDateTime": "2026-07-14T05:26:50.12Z",
    "mitreTechniques": ["T1566.002"],
    "serviceSource": "microsoftDefenderForOffice365",
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.mailboxEvidence",
            "primaryAddress": "victim@acme.example.com",
            "upn": "victim@acme.example.com",
            "displayName": "Victim User",
        },
        {
            "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
            "p1Sender": {"emailAddress": "envelope@bad.example", "domainName": "bad.example"},
            "p2Sender": {"emailAddress": "display@bad.example", "domainName": "bad.example"},
            "recipientEmailAddress": "victim@acme.example.com",
            "subject": "Urgent: verify your account",
            "senderIp": "203.0.113.7",
            "networkMessageId": "abc-123",
            "deliveryAction": "Delivered",
            "urls": ["http://bad.example/phish"],
        },
        {"@odata.type": "#microsoft.graph.security.urlEvidence", "url": "http://bad.example/phish"},
        {
            "@odata.type": "#microsoft.graph.security.ipEvidence",
            "ipAddress": "203.0.113.7",
            "countryLetterCode": "US",
        },
        {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            "userAccount": {"accountName": "victim", "userPrincipalName": "victim@acme.example.com"},
        },
    ],
}

ENDPOINT_ALERT = {
    "id": "ep-1",
    "title": "Suspicious PowerShell",
    "severity": "high",
    "categories": ["Execution"],
    "createdDateTime": "2026-07-14T10:00:00Z",
    "mitreTechniques": ["T1059.001"],
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            "deviceDnsName": "HOST-42.acme.local",
            "hostName": "HOST-42",
        },
        {
            "@odata.type": "#microsoft.graph.security.processEvidence",
            "imageFile": {
                "sha256": "a" * 64,
                "fileName": "powershell.exe",
                "filePath": "C:\\ps.exe",
            },
            "processCommandLine": "powershell -enc ZZZ",
            "userAccount": {"accountName": "jdoe"},
        },
        {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            "fileDetails": {"sha1": "b" * 40, "fileName": "evil.exe"},
        },
    ],
}


# ── email alert: the evidence the vendored parser dropped ─────────────────────


def test_email_alert_extracts_message_evidence():
    n = _parse(EMAIL_ALERT)
    assert n["sender"] == "display@bad.example"  # p2Sender preferred over p1
    assert n["recipient"] == "victim@acme.example.com"
    assert n["subject"] == "Urgent: verify your account"
    assert n["url"] == "http://bad.example/phish"
    assert n["src_ip"] == "203.0.113.7"
    assert n["username"] == "victim"
    assert n["threat_category"] == "Phishing"
    assert n["mitre_technique"] == "T1566.002"
    assert n["source_product"] == "microsoft_defender"
    assert n["severity_label"]  # finalize derived a label from severity=3


def test_email_alert_yields_ocsf_email_user_entities():
    # The payoff: sender + recipient now resolve to OCSF user entities (they didn't before).
    n = _parse(EMAIL_ALERT)
    ents = ocsf.to_entities(n, "acme")
    roles = {(e["entity_type"], e.get("role")) for e in ents}
    assert ("user", "sender") in roles
    assert ("user", "recipient") in roles


def test_mailbox_fallback_recipient_when_message_lacks_one():
    alert = {
        "id": "email-2",
        "title": "Reported phish",
        "severity": "low",
        "createdDateTime": "2026-07-15T00:00:00Z",
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.mailboxEvidence",
                "primaryAddress": "m@acme.example.com",
            },
            {"@odata.type": "#microsoft.graph.security.analyzedMessageEvidence", "subject": "hi"},
        ],
    }
    n = _parse(alert)
    assert n["recipient"] == "m@acme.example.com"  # mailbox filled the recipient
    assert n["username"] == "m@acme.example.com"


# ── endpoint alert ────────────────────────────────────────────────────────────


def test_endpoint_alert_extracts_device_file_process():
    n = _parse(ENDPOINT_ALERT)
    assert n["hostname"] == "HOST-42.acme.local"
    assert n["file_hash_sha256"] == "a" * 64  # processEvidence.imageFile
    assert n["file_hash_sha1"] == "b" * 40  # fileEvidence
    assert n["username"] == "jdoe"
    assert n["mitre_technique"] == "T1059.001"
    assert "cmdline: powershell -enc ZZZ" in (n["event_description"] or "")


# ── routing + defensiveness ───────────────────────────────────────────────────


def test_parser_adapter_routes_defender_to_native():
    n = parser_adapter.parse_to_normalized(
        EMAIL_ALERT, source_hint="microsoft_defender", customer="acme"
    )
    assert n["sender"] == "display@bad.example"  # native parser ran, not the vendored one
    assert n.get("severity_id") is not None  # parser_adapter stamped OCSF severity_id


def test_parse_never_raises_on_garbled_input():
    n = _parse(
        {
            "id": "x",
            "evidence": ["not-a-dict", {}, {"@odata.type": "unknown"}, {"@odata.type": None}],
        }
    )
    assert n["source_product"] == "microsoft_defender"
    assert n["rule_id"] == "x"
    # non-dict raw is tolerated too
    assert _parse("not json")["source_product"] == "microsoft_defender"
