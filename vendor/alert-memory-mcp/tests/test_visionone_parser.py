"""Tests for the Vision One Workbench email parser + its detect_source routing.

Runnable two ways:
    pytest vendor/alert-memory-mcp/tests/test_visionone_parser.py
    PYTHONPATH=vendor/alert-memory-mcp python3 vendor/alert-memory-mcp/tests/test_visionone_parser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers import detect_source, parse  # noqa: E402

V1_EMAIL = """\
Subject: Unmas Unlu Mamuller | Workbench | Alert Severity: Medium | Score: 66 | \
Model: Multiple Identified Failed Logon via NetworkCleartext | WB-18364-20260621-00001 | \
12fd4994-3b4c-4967-ab1c-cb33d44bbfc4 (do not reply)

TrendAI Vision One has triggered an alert.

Alert Information
Score: 66
Workbench ID: WB-18364-20260621-00001
Model: Multiple Identified Failed Logon via NetworkCleartext
Model severity: Medium
Created: 2026-06-21 20:47:56

Impact Scope
Endpoint - Servers: 1
   UNOEXCSRV01
User accounts: 1
   UNMAS_WG\\furkan.akkaya

Highlighted Objects
1. (processCmd) "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\MSExchangeFrontendTransport.exe"

Techniques
T1110 - Brute Force

For more alert information, go to the console:
https://portal.sg.xdr.trendmicro.com/index.html#/workbench/alerts/WB-18364-20260621-00001?ref=a88b7dcd
"""


def test_detects_visionone():
    assert detect_source(V1_EMAIL) == "visionone"


def test_parses_core_fields():
    a = parse(V1_EMAIL, customer="unmas")
    assert a.source_product == "visionone"
    assert a.v1_workbench_id == "WB-18364-20260621-00001"
    assert a.rule_id == "WB-18364-20260621-00001"
    assert a.rule_name == "Multiple Identified Failed Logon via NetworkCleartext"
    assert a.v1_console_host == "portal.sg.xdr.trendmicro.com"
    assert a.v1_region == "sg"
    assert a.severity_label == "medium"
    assert a.hostname == "UNOEXCSRV01"
    assert a.username == "UNMAS_WG\\furkan.akkaya"   # domain-prefixed, verbatim
    assert a.mitre_technique == "T1110"
    assert a.timestamp == "2026-06-21T20:47:56"
    assert a.customer == "unmas"
    # carried fields survive to_dict()
    d = a.to_dict()
    assert d["v1_workbench_id"] == "WB-18364-20260621-00001"
    assert d["v1_region"] == "sg"


def test_region_defaults_us_without_segment():
    email = V1_EMAIL.replace("portal.sg.xdr.trendmicro.com", "portal.xdr.trendmicro.com")
    a = parse(email)
    assert a.v1_region == "us"


def test_malformed_never_raises():
    # Enough markers to route to visionone, but missing every field.
    junk = "TrendAI Vision One | Workbench | (no fields here) WB-1-20260101-1"
    a = parse(junk)
    assert a.source_product == "visionone"
    assert a.v1_workbench_id == "WB-1-20260101-1"
    # missing sections -> None, no exception
    assert a.rule_name is None
    assert a.hostname is None


def test_detect_source_regression_other_products_unchanged():
    # The new visionone branch must NOT shadow existing products.
    wazuh = '{"rule": {"id": 5710, "description": "sshd"}, "agent": {"name": "srv1"}}'
    qradar = "Rule Name: Suspicious Outbound\nQID: 1002\nSource IP: 10.0.0.1"
    fortigate = 'logver=604 devid=FG100 type=traffic action=deny'
    syslog = "Jan  3 10:00:00 host sshd[1]: Failed password"
    assert detect_source(wazuh) == "wazuh"
    assert detect_source(qradar) == "qradar"
    assert detect_source(fortigate) == "fortigate"
    assert detect_source(syslog) == "syslog"
    assert detect_source("hello world, nothing to see") == "unknown"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
