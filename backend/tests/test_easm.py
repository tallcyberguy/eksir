"""EASM (Phase 3) — pure recon grading/scoring tests (no network)."""

from __future__ import annotations

from isoc_api.easm import recon


def test_classify_asset():
    assert recon.classify_asset("8.8.8.8") == "ip"
    assert recon.classify_asset("2606:4700:4700::1111") == "ip"
    assert recon.classify_asset("https://evil.example.com/path") == "url"
    assert recon.classify_asset("example.com") == "domain"
    assert recon.classify_asset("api.corp.example.com") == "subdomain"


def test_normalize_host_strips_scheme_path_port():
    assert recon.normalize_host("https://api.example.com:8443/x?y=1") == "api.example.com"
    assert recon.normalize_host("user@mail.example.com") == "mail.example.com"
    assert recon.normalize_host("Example.COM.") == "example.com"


def test_cert_status_bands():
    assert recon.cert_status(90) == "valid"
    assert recon.cert_status(30) == "expiring"
    assert recon.cert_status(0) == "expiring"
    assert recon.cert_status(-1) == "expired"
    assert recon.cert_status(None) == "unknown"


def test_grade_dns_posture_strong():
    g = recon.grade_dns_posture(
        txt=["v=spf1 include:_spf.google.com ~all"],
        dmarc_txt=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        mx=["10 mail.example.com."],
    )
    assert g["spf"] is True
    assert g["dmarc"] is True
    assert g["dmarc_policy"] == "reject"
    assert g["posture"] == "strong"
    assert g["findings"] == []


def test_grade_dns_posture_monitoring_only_is_moderate():
    g = recon.grade_dns_posture(
        txt=["v=spf1 -all"],
        dmarc_txt=["v=DMARC1; p=none"],
        mx=["10 mx.example.com."],
    )
    assert g["posture"] == "moderate"
    assert any("p=none" in f for f in g["findings"])


def test_grade_dns_posture_none():
    g = recon.grade_dns_posture(txt=["some-other-txt"], dmarc_txt=[], mx=[])
    assert g["spf"] is False and g["dmarc"] is False
    assert g["posture"] == "none"
    assert len(g["findings"]) >= 2


def test_risk_score_expired_cert_and_weak_posture():
    result = {
        "asset_type": "domain",
        "dns": {"a": ["1.2.3.4"]},
        "tls": {"days_remaining": -3},
        "posture": {"posture": "none"},
        "errors": [],
    }
    r = recon.risk_score(result)
    assert r["score"] >= 70
    assert r["level"] == "critical"
    assert any("expired" in x.lower() for x in r["reasons"])


def test_risk_score_clean_asset_is_low():
    result = {
        "asset_type": "domain",
        "dns": {"a": ["1.2.3.4"]},
        "tls": {"days_remaining": 200},
        "posture": {"posture": "strong"},
        "errors": [],
    }
    r = recon.risk_score(result)
    assert r["score"] == 0
    assert r["level"] == "low"


def test_risk_score_unresolved_domain_penalized():
    result = {
        "asset_type": "domain",
        "dns": {"a": [], "aaaa": []},
        "tls": None,
        "posture": {"posture": "moderate"},
        "errors": ["Could not resolve x"],
    }
    r = recon.risk_score(result)
    assert r["score"] >= 15
    assert any("A/AAAA" in x for x in r["reasons"])


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <ports>
   <port protocol="tcp" portid="22"><state state="open"/>
     <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
   <port protocol="tcp" portid="443"><state state="open"/>
     <service name="https" product="nginx" version="1.18.0" tunnel="ssl"/></port>
   <port protocol="tcp" portid="3389"><state state="open"/>
     <service name="ms-wbt-server"/></port>
   <port protocol="tcp" portid="8080"><state state="closed"/>
     <service name="http"/></port>
  </ports>
 </host>
</nmaprun>"""


def test_parse_nmap_xml_open_ports_only():
    ports = recon.parse_nmap_xml(_NMAP_XML)
    pn = [p["port"] for p in ports]
    assert pn == [22, 443, 3389]  # sorted, closed 8080 excluded
    https = next(p for p in ports if p["port"] == 443)
    assert (
        https["service"] == "https" and https["product"] == "nginx" and https["version"] == "1.18.0"
    )


def test_parse_nmap_xml_tolerates_garbage():
    assert recon.parse_nmap_xml("") == []
    assert recon.parse_nmap_xml("not xml <<<") == []


def test_port_risk_flags_rdp_and_scores():
    ports = recon.parse_nmap_xml(_NMAP_XML)
    pr = recon.port_risk(ports)
    assert pr["open_count"] == 3
    assert pr["risky_count"] == 1  # RDP (ms-wbt-server)
    assert any("RDP" in r for r in pr["reasons"])
    assert pr["score"] > 0


def test_port_risk_clean_when_no_risky_services():
    ports = [{"port": 443, "service": "https"}, {"port": 22, "service": "ssh"}]
    pr = recon.port_risk(ports)
    assert pr["risky_count"] == 0
    assert pr["score"] == 0


def test_risk_score_includes_exposed_ports():
    result = {
        "asset_type": "ip",
        "dns": {"a": ["1.2.3.4"]},
        "tls": None,
        "posture": {"posture": "strong"},
        "errors": [],
        "ports": [{"port": 3389, "service": "ms-wbt-server"}, {"port": 23, "service": "telnet"}],
    }
    r = recon.risk_score(result)
    assert r["score"] >= 28  # two risky services
    assert any("RDP" in x for x in r["reasons"])
    assert any("Telnet" in x for x in r["reasons"])


def test_summarize_rolls_up_register():
    assets = [
        {
            "asset_type": "domain",
            "last_result": {
                "tls": {"days_remaining": 5},
                "posture": {"posture": "none"},
                "risk": {"score": 80},
            },
        },
        {
            "asset_type": "ip",
            "last_result": {
                "tls": {"days_remaining": 200},
                "posture": {"posture": "strong"},
                "risk": {"score": 0},
            },
        },
        {"asset_type": "domain", "last_result": None},  # never scanned
    ]
    s = recon.summarize(assets)
    assert s["total_assets"] == 3
    assert s["scanned"] == 2
    assert s["cert_issues"] == 1  # the 5-day cert
    assert s["weak_posture"] == 1  # the 'none' posture
    assert s["max_risk"] == 80
    assert s["by_type"]["domain"] == 2
