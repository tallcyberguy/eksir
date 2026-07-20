"""
Parser tests using real alert fixtures.
Run: python -m pytest tests/ -v
  or: python tests/test_parsers.py
"""

import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import parsers

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(filename: str) -> str:
    with open(os.path.join(FIXTURES, filename)) as f:
        return f.read()


def test_qradar_basic():
    raw = load("qradar_sample.txt")
    alert = parsers.parse(raw, customer="contoso")

    print("\n=== QRadar Alert ===")
    print(f"  source_product : {alert.source_product}")
    print(f"  rule_name      : {alert.rule_name}")
    print(f"  src_ip         : {alert.src_ip}")
    print(f"  dst_ip         : {alert.dst_ip}")
    print(f"  dst_port       : {alert.dst_port}")
    print(f"  severity       : {alert.severity} ({alert.severity_label})")
    print(f"  threat_category: {alert.threat_category}")
    print(f"  mitre_tactic   : {alert.mitre_tactic}")
    print(f"  mitre_technique: {alert.mitre_technique}")
    print(f"  customer       : {alert.customer}")
    print(f"\n--- embed_text ---\n{alert.embed_text}")

    assert alert.source_product == "qradar"
    assert alert.customer == "contoso"
    assert alert.src_ip == "10.0.3.45"
    assert alert.threat_category == "recon"
    assert alert.embed_text != ""
    print("\n[PASS] QRadar parser")


def test_wazuh_suricata():
    raw = load("wazuh_suricata_sample.json")
    data = json.loads(raw)
    alert = parsers.parse(data, customer="musteri_x")

    print("\n=== Wazuh Suricata Alert ===")
    print(f"  source_product : {alert.source_product}")
    print(f"  rule_id        : {alert.rule_id}")
    print(f"  rule_name      : {alert.rule_name}")
    print(f"  src_ip         : {alert.src_ip}")
    print(f"  dst_ip         : {alert.dst_ip}")
    print(f"  dst_port       : {alert.dst_port}")
    print(f"  cve            : {alert.cve}")
    print(f"  mitre_technique: {alert.mitre_technique}")
    print(f"  mitre_tactic   : {alert.mitre_tactic}")
    print(f"  severity       : {alert.severity} ({alert.severity_label})")
    print(f"  threat_category: {alert.threat_category}")
    print(f"\n--- embed_text ---\n{alert.embed_text}")

    assert alert.source_product == "wazuh"
    assert alert.src_ip == "198.51.100.201"
    assert alert.cve == "CVE-2024-4577"
    assert alert.mitre_technique == "T1190"
    assert alert.threat_category == "exploit"
    print("\n[PASS] Wazuh Suricata parser")


def test_wazuh_winevent():
    raw = load("wazuh_winevent_sample.json")
    data = json.loads(raw)
    alert = parsers.parse(data, customer="fabrikam")

    print("\n=== Wazuh WinEvent Alert ===")
    print(f"  source_product : {alert.source_product}")
    print(f"  rule_id        : {alert.rule_id}")
    print(f"  rule_name      : {alert.rule_name}")
    print(f"  hostname       : {alert.hostname}")
    print(f"  username       : {alert.username}")
    print(f"  agent_ip       : {alert.agent_ip}")
    print(f"  mitre_technique: {alert.mitre_technique}")
    print(f"  severity       : {alert.severity} ({alert.severity_label})")
    print(f"  threat_category: {alert.threat_category}")
    print(f"\n--- embed_text ---\n{alert.embed_text}")

    assert alert.source_product == "wazuh"
    assert alert.rule_id == "60235"
    assert alert.hostname == "DC01.fabrikam.local"
    assert alert.mitre_technique == "T1110"
    assert alert.threat_category == "brute_force"
    print("\n[PASS] Wazuh WinEvent parser")


def test_auto_detect():
    """Auto-detect should correctly route without specifying source."""
    qradar_raw = load("qradar_sample.txt")
    wazuh_raw = json.loads(load("wazuh_suricata_sample.json"))

    assert parsers.detect_source(qradar_raw) == "qradar"
    assert parsers.detect_source(wazuh_raw) == "wazuh"
    print("\n[PASS] Auto-detect")


if __name__ == "__main__":
    test_qradar_basic()
    test_wazuh_suricata()
    test_wazuh_winevent()
    test_auto_detect()
    print("\n=== All tests passed ===")
