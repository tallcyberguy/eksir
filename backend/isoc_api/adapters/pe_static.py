"""Pure-stdlib PE structural analysis — per-section entropy, RWX flags, packer
heuristics, machine type, compile timestamp.

Ported from the malware-analysis skill's static_analysis.py. This complements the
REMnux tool wave (diec/portex give packer *identification*; this gives the
quantitative entropy/RWX signals the CLI tools don't surface). Runs in the
worker on the already-uploaded sample — no container round-trip, no third-party
deps (struct/hashlib/math only). Fully fail-soft: any parse error returns a
block with an `error` key rather than raising.
"""

from __future__ import annotations

import math
import struct
from collections import Counter

from ..logging_config import get_logger

logger = get_logger("isoc.adapter.pe_static")

_MAX_READ = 128 * 1024 * 1024  # 128 MiB cap — don't slurp absurd uploads
_MACHINE_TYPES = {0x14C: "i386", 0x8664: "AMD64", 0x1C0: "ARM", 0xAA64: "ARM64"}
_PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".packed", ".aspack", ".adata", ".vmp0", ".vmp1"}
_HIGH_ENTROPY = 7.0


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counter.values()), 4)


def analyze(path: str) -> dict | None:
    """Parse a PE file's structure. Returns None if it isn't a PE; a dict with
    an `error` key on a parse failure; otherwise the structural analysis."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(_MAX_READ)
    except OSError as e:
        return {"error": f"read failed: {e}"}

    if len(data) < 64 or data[:2] != b"MZ":
        return None  # not a PE

    try:
        pe_off = struct.unpack("<I", data[0x3C:0x40])[0]
        if len(data) < pe_off + 24 or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return None

        machine = struct.unpack("<H", data[pe_off + 4 : pe_off + 6])[0]
        num_sections = struct.unpack("<H", data[pe_off + 6 : pe_off + 8])[0]
        timestamp = struct.unpack("<I", data[pe_off + 8 : pe_off + 12])[0]
        opt_size = struct.unpack("<H", data[pe_off + 20 : pe_off + 22])[0]
        characteristics = struct.unpack("<H", data[pe_off + 22 : pe_off + 24])[0]
        magic = struct.unpack("<H", data[pe_off + 24 : pe_off + 26])[0]
        is_64 = magic == 0x20B

        from datetime import datetime, timezone

        compile_ts = (
            datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
            if 0 < timestamp < 4102444800  # plausible epoch .. year 2100
            else "unknown/tampered"
        )

        section_off = pe_off + 24 + opt_size
        sections: list[dict] = []
        for i in range(min(num_sections, 30)):
            s = section_off + i * 40
            if s + 40 > len(data):
                break
            name = data[s : s + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
            virtual_size = struct.unpack("<I", data[s + 8 : s + 12])[0]
            raw_size = struct.unpack("<I", data[s + 16 : s + 20])[0]
            raw_off = struct.unpack("<I", data[s + 20 : s + 24])[0]
            chars = struct.unpack("<I", data[s + 36 : s + 40])[0]
            sec_entropy = (
                _entropy(data[raw_off : raw_off + raw_size])
                if 0 < raw_size and raw_off + raw_size <= len(data)
                else 0.0
            )
            executable = bool(chars & 0x20000000)
            writable = bool(chars & 0x80000000)
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "entropy": sec_entropy,
                    "executable": executable,
                    "writable": writable,
                    "rwx": executable and writable,
                }
            )

        indicators: list[str] = []
        for sec in sections:
            if sec["entropy"] > _HIGH_ENTROPY:
                indicators.append(f"High entropy in {sec['name'] or '(unnamed)'}: {sec['entropy']}")
            if sec["name"] in _PACKER_SECTIONS:
                indicators.append(f"Known packer section: {sec['name']}")
            if sec["rwx"]:
                indicators.append(f"RWX section: {sec['name'] or '(unnamed)'}")

        packed = any(
            sec["entropy"] > _HIGH_ENTROPY or sec["name"] in _PACKER_SECTIONS for sec in sections
        )

        return {
            "type": "PE32+" if is_64 else "PE32",
            "architecture": "x64" if is_64 else "x86",
            "machine": _MACHINE_TYPES.get(machine, f"unknown (0x{machine:x})"),
            "compile_timestamp": compile_ts,
            "timestamp_raw": timestamp,
            "num_sections": num_sections,
            "is_dll": bool(characteristics & 0x2000),
            "is_executable": bool(characteristics & 0x0002),
            "file_entropy": _entropy(data),
            "sections": sections,
            "rwx_sections": [s["name"] for s in sections if s["rwx"]],
            "packing_indicators": indicators,
            "packed": packed,
        }
    except (struct.error, ValueError, IndexError) as e:
        logger.warning("pe_static.parse_failed", error=str(e))
        return {"error": str(e)}
