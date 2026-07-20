"""Unit tests for adapters.pe_static — entropy + PE section parsing."""

from __future__ import annotations

import struct
import tempfile

from isoc_api.adapters import pe_static


def test_entropy_bounds():
    assert pe_static._entropy(b"") == 0.0
    assert pe_static._entropy(b"A" * 500) == 0.0  # single symbol → 0 bits
    assert pe_static._entropy(bytes(range(256))) == 8.0  # uniform 256 → 8 bits


def test_non_pe_returns_none(tmp_path=None):
    import os

    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"this is not a PE file")
    try:
        assert pe_static.analyze(p) is None
    finally:
        os.unlink(p)


def _build_minimal_pe() -> bytes:
    """A structurally-valid PE32+ with one RWX, high-entropy .text section."""
    pe_off = 0x80
    opt_size = 0xF0
    section_off = pe_off + 24 + opt_size
    raw_off = 0x400
    raw_size = 256

    buf = bytearray(raw_off + raw_size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)  # e_lfanew
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, pe_off + 4, 0x8664)  # machine = AMD64
    struct.pack_into("<H", buf, pe_off + 6, 1)  # num_sections
    struct.pack_into("<I", buf, pe_off + 8, 1577836800)  # timestamp = 2020-01-01
    struct.pack_into("<H", buf, pe_off + 20, opt_size)
    struct.pack_into("<H", buf, pe_off + 22, 0x0002)  # characteristics: executable image
    struct.pack_into("<H", buf, pe_off + 24, 0x20B)  # optional magic = PE32+

    # one section header
    buf[section_off : section_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, section_off + 8, raw_size)  # virtual size
    struct.pack_into("<I", buf, section_off + 16, raw_size)  # raw size
    struct.pack_into("<I", buf, section_off + 20, raw_off)  # raw offset
    # exec (0x20000000) + write (0x80000000) = RWX
    struct.pack_into("<I", buf, section_off + 36, 0xE0000020)

    buf[raw_off : raw_off + raw_size] = bytes(range(256))  # entropy 8.0
    return bytes(buf)


def test_minimal_pe_parsed():
    import os

    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(_build_minimal_pe())
    try:
        r = pe_static.analyze(p)
    finally:
        os.unlink(p)

    assert r is not None and "error" not in r
    assert r["type"] == "PE32+"
    assert r["machine"] == "AMD64"
    assert r["num_sections"] == 1
    assert len(r["sections"]) == 1
    sec = r["sections"][0]
    assert sec["name"] == ".text"
    assert sec["rwx"] is True
    assert sec["entropy"] == 8.0
    assert r["packed"] is True  # high-entropy section
    assert ".text" in r["rwx_sections"]
    assert any("RWX" in i for i in r["packing_indicators"])
    assert any("High entropy" in i for i in r["packing_indicators"])
