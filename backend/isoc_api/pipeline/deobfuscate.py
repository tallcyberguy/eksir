"""Deterministic payload extraction, layered decoding, and obfuscation scoring.

This runs as a cheap, pure-Python pre-enrichment stage. It finds encoded blobs
hiding inside alert fields (base64 PowerShell ``-EncodedCommand``, generic
base64, hex, percent/`\\x`/`\\u` escapes), decodes them recursively (a base64 →
gzip → base64 chain is common), and scores how obfuscated the input is using a
heuristic feature model (Shannon entropy + symbol ratio + known obfuscation
markers).

It intentionally does NOT call an LLM or the REMnux container — the decoded
artifacts it returns are fed back through ``ioc_extract`` by the orchestrator so
IOCs hidden inside payloads (e.g. a C2 domain inside a base64 command) surface
and get the full triage/threat-intel treatment, and they are rendered into the
briefing + report so the analyst sees them.

Revoke-Obfuscation (a PowerShell *detector*, not a decoder) was evaluated for
the scoring half; we deliberately implement an equivalent heuristic scorer in
Python here to avoid baking PowerShell into the REMnux image. See
docs/ — the score is heuristic, not an ML classifier, and is labelled as such.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import math
import re
import urllib.parse
import zlib
from collections import Counter
from typing import Any

# ── Tunables ────────────────────────────────────────────────────────────────
MAX_DEPTH = 4  # recursive decode passes (base64 -> gzip -> base64 -> ...)
MAX_ARTIFACTS = 25  # hard cap on returned decoded layers
MIN_B64_LEN = 24  # ignore short base64-ish tokens (too many false positives)
MIN_HEX_LEN = 32  # ignore short hex runs (also dodges 32-char MD5 hashes below)
MAX_DECODED_STORE = 8000  # chars of decoded_text persisted per artifact
SNIPPET_LEN = 240  # chars shown in the briefing/UI snippet
MIN_PRINTABLE_RATIO = 0.80  # decoded output must be mostly text to keep it

# ── Candidate detectors ─────────────────────────────────────────────────────
# PowerShell encoded command: -enc / -e / -EncodedCommand <base64>. The payload
# is base64 of UTF-16LE text, so it decodes in two steps.
_PS_ENC_RE = re.compile(r"(?i)(?:-enc(?:odedcommand)?|-ec|-e)\s+([A-Za-z0-9+/]{20,}={0,2})")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(MIN_B64_LEN) + r",}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{" + str(MIN_HEX_LEN) + r",}")
_PCT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_BACKSLASH_X_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_BACKSLASH_U_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")

# PowerShell char-code arrays:  [char]72,[char]101  or  (72,101,108 -join '')
_CHARCODE_RE = re.compile(r"(?:\[char\]\s*)?(\d{2,3})", re.IGNORECASE)
_CHARCODE_CTX_RE = re.compile(r"\[char\]", re.IGNORECASE)

# Obfuscation markers (used by the heuristic scorer, not for decoding).
_MARKERS = (
    "frombase64string",
    "-encodedcommand",
    "-enc ",
    "iex",
    "invoke-expression",
    "-join",
    "[char]",
    "-bxor",
    "::fromhexstring",
    "downloadstring",
    "downloaddata",
    "[convert]",
    "gzipstream",
    "deflatestream",
    "[scriptblock]",
    "${",
    "`",  # PowerShell escape backtick used to break up tokens
)


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)
    return printable / len(b)


def _to_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char (0–8). Plain text ~4.5, base64 ~6, packed ~8."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def obfuscation_score(s: str) -> float:
    """Heuristic obfuscation likelihood in [0, 1].

    NOT an ML classifier — a transparent blend of three signals analysts can
    reason about: symbol density, known obfuscation markers, and entropy. High
    scores mean "looks deliberately obscured"; benign one-liners score low.
    """
    if not s or len(s) < 12:
        return 0.0
    lower = s.lower()

    # 1) Symbol density — obfuscated PowerShell is heavy on +,^,{,},`,$,(
    symbols = sum(1 for c in s if not c.isalnum() and not c.isspace())
    symbol_ratio = symbols / len(s)
    symbol_component = min(symbol_ratio / 0.30, 1.0)

    # 2) Marker hits — capped contribution so one marker can't max it out
    marker_hits = sum(1 for m in _MARKERS if m in lower)
    # backtick density is a strong signal on its own
    backtick_ratio = s.count("`") / len(s)
    marker_component = min((marker_hits / 5.0) + min(backtick_ratio / 0.05, 0.4), 1.0)

    # 3) Entropy — normalise around 4.0 (text) .. 6.0 (base64-ish)
    ent = shannon_entropy(s)
    entropy_component = min(max((ent - 4.0) / 2.0, 0.0), 1.0)

    score = 0.45 * symbol_component + 0.35 * marker_component + 0.20 * entropy_component
    return round(min(score, 1.0), 3)


def _score_band(score: float) -> str:
    if score >= 0.66:
        return "heavy"
    if score >= 0.40:
        return "moderate"
    if score >= 0.18:
        return "low"
    return "none"


# ── Decoders. Each returns decoded bytes or None. ───────────────────────────
def _decode_b64(token: str) -> bytes | None:
    t = token.strip()
    pad = (-len(t)) % 4
    try:
        raw = base64.b64decode(t + ("=" * pad), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 3:
        return None
    return raw


def _decode_hex(token: str) -> bytes | None:
    t = token[2:] if token.lower().startswith("0x") else token
    if len(t) % 2:
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def _maybe_decompress(raw: bytes) -> bytes | None:
    """gzip (1f 8b) or raw/zlib deflate — common second layer after base64."""
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except (OSError, EOFError, zlib.error):
            return None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            out = zlib.decompress(raw, wbits)
            if out:
                return out
        except zlib.error:
            continue
    return None


def _utf16le_if_clean(raw: bytes) -> bytes | None:
    """PowerShell -EncodedCommand payloads are UTF-16LE (lots of NUL bytes)."""
    if b"\x00" not in raw:
        return None
    try:
        text = raw.decode("utf-16-le")
    except (UnicodeDecodeError, ValueError):
        return None
    return text.encode("utf-8")


def _decode_charcodes(text: str) -> bytes | None:
    """Unroll [char]72,[char]101,... arrays into their string."""
    if not _CHARCODE_CTX_RE.search(text):
        return None
    codes = [int(m) for m in _CHARCODE_RE.findall(text)]
    chars = [chr(c) for c in codes if 9 <= c <= 126]
    if len(chars) < 4:
        return None
    return "".join(chars).encode("utf-8")


def _keep(raw: bytes) -> bool:
    """Only keep a decoded layer that looks like text or decompressed cleanly."""
    return _printable_ratio(raw) >= MIN_PRINTABLE_RATIO


# ── Main analysis ───────────────────────────────────────────────────────────
def _collect_fields(normalized: dict, raw_text: str) -> list[tuple[str, str]]:
    """(source_label, text) pairs to scan: command/script fields first, then raw."""
    out: list[tuple[str, str]] = []
    candidate_fields = (
        "command_line",
        "commandline",
        "process_command_line",
        "command",
        "script",
        "script_block",
        "powershell",
        "payload",
        "message",
        "process",
        "parent_command_line",
    )
    for f in candidate_fields:
        v = normalized.get(f)
        if isinstance(v, str) and v.strip():
            out.append((f, v))
    if raw_text and raw_text.strip():
        out.append(("raw", raw_text))
    return out


def _decode_candidates(label: str, text: str) -> list[dict[str, Any]]:
    """Find + decode all candidate blobs in one text field (single layer)."""
    found: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()

    def add(encoding: str, token: str, decoded: bytes) -> None:
        h = _sha256(decoded)
        if h in seen_tokens:
            return
        seen_tokens.add(h)
        found.append(
            {"encoding": encoding, "source_field": label, "raw_bytes": decoded, "sha256": h}
        )

    # PowerShell -EncodedCommand → base64 → UTF-16LE
    for m in _PS_ENC_RE.finditer(text):
        b = _decode_b64(m.group(1))
        if b is None:
            continue
        utf16 = _utf16le_if_clean(b)
        add("powershell-encodedcommand", m.group(1), utf16 or b)

    # Generic base64 (then opportunistic decompress / utf16)
    for token in _B64_RE.findall(text):
        if token in seen_tokens:
            continue
        b = _decode_b64(token)
        if b is None:
            continue
        decompressed = _maybe_decompress(b)
        utf16 = _utf16le_if_clean(b)
        chosen = decompressed or utf16 or b
        if _keep(chosen):
            add("base64" + ("+gzip" if decompressed else ""), token, chosen)

    # Hex (skip exact hash lengths — those are real IOCs handled elsewhere)
    for token in _HEX_RE.findall(text):
        bare = token[2:] if token.lower().startswith("0x") else token
        if len(bare) in (32, 40, 64):  # md5 / sha1 / sha256
            continue
        b = _decode_hex(token)
        if b is not None and _keep(b):
            add("hex", token, b)

    # Percent-encoding
    for token in _PCT_RE.findall(text):
        try:
            dec = urllib.parse.unquote(token, errors="strict")
        except (UnicodeDecodeError, ValueError):
            continue
        if dec != token and len(dec) >= 4:
            add("percent", token, dec.encode("utf-8", errors="replace"))

    # \x and \u escapes (both decoded the same way)
    for rx in (_BACKSLASH_X_RE, _BACKSLASH_U_RE):
        for token in rx.findall(text):
            try:
                dec = codecs.decode(token, "unicode_escape")
            except (UnicodeDecodeError, ValueError):
                continue
            if dec and dec != token:
                add("backslash-escape", token, dec.encode("utf-8", errors="replace"))

    # PowerShell [char] arrays
    cc = _decode_charcodes(text)
    if cc is not None and _keep(cc):
        add("char-array", text[:40], cc)

    return found


def analyze(
    normalized: dict | None,
    raw_text: str,
    *,
    max_depth: int = MAX_DEPTH,
    max_artifacts: int = MAX_ARTIFACTS,
) -> dict[str, Any] | None:
    """Decode encoded payloads and score obfuscation.

    Returns ``None`` when nothing decodable is present (so the orchestrator can
    skip storing an empty section). Otherwise returns a JSON-safe dict::

        {
          "artifacts": [
            {layer, encoding, source_field, sha256, size, snippet, decoded_text}, ...
          ],
          "obfuscation": {
            "score": float,            # how obfuscated the *input* looked
            "original_max": float,
            "decoded_max": float,
            "delta": float,            # original - decoded (positive = we reduced it)
            "band": "heavy|moderate|low|none",
          },
        }
    """
    normalized = normalized or {}
    fields = _collect_fields(normalized, raw_text)
    if not fields:
        return None

    # Score the obfuscation of the original command/script content.
    original_max = max((obfuscation_score(t) for _, t in fields), default=0.0)

    artifacts: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    # BFS over decode layers.
    queue: list[tuple[str, str, int]] = [(label, text, 0) for label, text in fields]
    while queue and len(artifacts) < max_artifacts:
        label, text, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for found in _decode_candidates(label, text):
            if found["sha256"] in seen_hashes:
                continue
            seen_hashes.add(found["sha256"])
            decoded_bytes: bytes = found["raw_bytes"]
            decoded_text = _to_text(decoded_bytes)
            artifacts.append(
                {
                    "layer": depth + 1,
                    "encoding": found["encoding"],
                    "source_field": found["source_field"],
                    "sha256": found["sha256"],
                    "size": len(decoded_bytes),
                    "snippet": decoded_text[:SNIPPET_LEN],
                    "decoded_text": decoded_text[:MAX_DECODED_STORE],
                }
            )
            if len(artifacts) >= max_artifacts:
                break
            # Recurse: the decoded layer may itself contain another blob.
            queue.append((f"{found['source_field']}:L{depth + 1}", decoded_text, depth + 1))

    if not artifacts:
        # Nothing decoded. Only surface a section if the input itself looked
        # meaningfully obfuscated (e.g. unrollable custom obfuscation).
        if original_max < 0.40:
            return None
        return {
            "artifacts": [],
            "obfuscation": {
                "score": original_max,
                "original_max": original_max,
                "decoded_max": 0.0,
                "encoded_layers": 0,
                "band": _score_band(original_max),
            },
        }

    # Headline score = the most obfuscated thing we saw, BEFORE or AFTER
    # decoding. A base64 -EncodedCommand scores low on the outer (alphanumeric)
    # blob but high once decoded to `IEX (...).DownloadString(...)`; taking the
    # max keeps the signal honest either way. The mere presence of encoded
    # layers is itself reported separately as `encoded_layers`.
    decoded_max = max((obfuscation_score(a["decoded_text"]) for a in artifacts), default=0.0)
    score = max(original_max, decoded_max)
    return {
        "artifacts": artifacts,
        "obfuscation": {
            "score": score,
            "original_max": original_max,
            "decoded_max": decoded_max,
            "encoded_layers": len(artifacts),
            "band": _score_band(score),
        },
    }
