"""File-hash extraction in the vendored alert parsers (STEP C).

Confirms the parsers now populate ``NormalizedAlert.file_hash_sha256`` /
``file_hash_sha1`` (length-gated, lowercased) — previously always None even
though the fields exist and are wired downstream (Qdrant iocs_v2, embed_text).

Pure tests. The parsers live in the vendored ``alert-memory-mcp`` package
(stdlib-only), so we add its dir to ``sys.path`` the same way
``test_store_adapter_retrieval.py`` does, then import ``parsers``.
"""

from __future__ import annotations

import json
import os
import sys

import pytest


def _add_vendored_path() -> None:
    """The parsers + NormalizedAlert live in the vendored alert-memory-mcp."""
    p = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "vendor", "alert-memory-mcp")
    )
    if p not in sys.path:
        sys.path.insert(0, p)


# Mixed-case on purpose so the lowercasing is exercised too.
SHA256 = "AABBccDD" + "0" * 56  # 64 hex chars
SHA1 = "1122AAbb" + "0" * 32  # 40 hex chars
MD5 = "DEADbeef" + "0" * 24  # 32 hex chars
CRC8 = "DEAD1234"  # 8 hex — a FortiGate checksum, NOT a hash


def test_wazuh_sysmon_hashes_blob():
    """Sysmon event with a combined 'hashes' blob → sha256 + sha1 (lowercased)."""
    _add_vendored_path()
    parsers = pytest.importorskip("parsers")

    event = {
        "timestamp": "2026-07-08T10:00:00Z",
        "rule": {"id": "92000", "description": "Sysmon - Process Create", "level": 5},
        "agent": {"ip": "10.0.0.5", "name": "WKS-01"},
        "data": {
            "win": {
                "system": {"computer": "WKS-01", "eventID": "1"},
                "eventdata": {
                    "image": "C:\\\\Windows\\\\Temp\\\\evil.exe",
                    "hashes": f"SHA1={SHA1},MD5={MD5},SHA256={SHA256}",
                },
            }
        },
    }

    alert = parsers.parse(json.dumps(event), customer="acme")

    assert alert.source_product == "wazuh"
    assert alert.file_hash_sha256 == SHA256.lower()
    assert alert.file_hash_sha1 == SHA1.lower()


def test_wazuh_sysmon_split_keys():
    """Split sha256/sha1 keys (case-insensitive) are read and length-gated."""
    _add_vendored_path()
    parsers = pytest.importorskip("parsers")

    event = {
        "rule": {"id": "92001", "description": "Sysmon FileCreate", "level": 5},
        "agent": {"ip": "10.0.0.6", "name": "WKS-02"},
        "data": {
            "win": {
                "system": {"computer": "WKS-02", "eventID": "11"},
                "eventdata": {"SHA256": SHA256, "Sha1": SHA1},
            }
        },
    }

    alert = parsers.parse(json.dumps(event), customer="acme")

    assert alert.file_hash_sha256 == SHA256.lower()
    assert alert.file_hash_sha1 == SHA1.lower()


def test_fortigate_filehash_sha256_and_checksum_not_slotted():
    """AV line: filehash=<64hex> → sha256; an 8-hex checksum is NOT a hash."""
    _add_vendored_path()
    fortigate = pytest.importorskip("parsers.fortigate")

    line = (
        "date=2026-07-08 time=10:00:00 devname=FW-01 devid=FG100 "
        "type=utm subtype=antivirus level=warning "
        'logdesc="Virus detected" action=blocked '
        "srcip=10.1.1.10 dstip=93.184.216.34 "
        f'filename="invoice.exe" filehash={SHA256} checksum={CRC8}'
    )

    alert = fortigate.parse(line, customer="acme")

    assert alert.source_product == "fortigate"
    assert alert.file_hash_sha256 == SHA256.lower()
    # The 8-hex CRC must never be mistaken for a real hash.
    assert alert.file_hash_sha1 is None
    assert CRC8.lower() not in (alert.file_hash_sha256 or "")


def test_fortigate_sha1_length_gate():
    """A 40-hex hash slots as sha1, not sha256."""
    _add_vendored_path()
    fortigate = pytest.importorskip("parsers.fortigate")

    line = (
        "date=2026-07-08 time=10:00:00 devname=FW-01 "
        "type=utm subtype=antivirus level=warning "
        f"srcip=10.1.1.10 filehash={SHA1} checksum={CRC8}"
    )

    alert = fortigate.parse(line, customer="acme")

    assert alert.file_hash_sha1 == SHA1.lower()
    assert alert.file_hash_sha256 is None


# ---------------------------------------------------------------------------
# regression: free-text hash fallbacks must be label-anchored (no cert-fingerprint
# / trace-id false positives). Review findings 5 (VisionOne) + 6 (QRadar).
# ---------------------------------------------------------------------------
def test_qradar_payload_cert_fingerprint_not_slotted():
    """A bare cert-fingerprint (no *hash label) must NOT become a file hash."""
    _add_vendored_path()
    qradar = pytest.importorskip("parsers.qradar")

    raw = (
        "Offense: Suspicious outbound\n"
        "Rule Name: Threat detected\n"
        f"Payload: proto=TLS sslCertFingerprint={SHA1} sessionId={SHA256}"
    )
    alert = qradar.parse(raw, customer="acme")
    assert alert.file_hash_sha1 is None
    assert alert.file_hash_sha256 is None


def test_qradar_payload_labeled_hash_is_slotted():
    """A labeled hash in free-text payload IS captured (label-anchored group)."""
    _add_vendored_path()
    qradar = pytest.importorskip("parsers.qradar")

    raw = (
        "Offense: Malware\nRule Name: EDR detection\n"
        f"Payload: process=evil.exe fileHash: {SHA256} verdict=malicious"
    )
    alert = qradar.parse(raw, customer="acme")
    assert alert.file_hash_sha256 == SHA256.lower()


def test_visionone_cert_fingerprint_not_slotted():
    """VisionOne: an unlabeled 40/64-hex token in the email body is not a hash."""
    _add_vendored_path()
    visionone = pytest.importorskip("parsers.visionone")

    raw = (
        "Trend Micro Vision One Workbench Alert\n"
        "Model: Suspicious Process\n"
        "Detail: https://portal.eu.xdr.trendmicro.com/index WB-18364-20260708-00001\n"
        f"TLS Certificate SHA1: {SHA1}\n"
        f"x-trace-id: {SHA256}\n"
    )
    alert = visionone.parse(raw, customer="acme")
    assert alert.file_hash_sha1 is None
    assert alert.file_hash_sha256 is None


def test_visionone_labeled_object_hash_is_slotted():
    """VisionOne: a labeled objectHash IS captured."""
    _add_vendored_path()
    visionone = pytest.importorskip("parsers.visionone")

    raw = (
        "Trend Micro Vision One Workbench Alert\n"
        "Model: Malware Detection\n"
        "Detail: https://portal.eu.xdr.trendmicro.com/index WB-18364-20260708-00002\n"
        f"(objectHash) {SHA256}\n"
    )
    alert = visionone.parse(raw, customer="acme")
    assert alert.file_hash_sha256 == SHA256.lower()
