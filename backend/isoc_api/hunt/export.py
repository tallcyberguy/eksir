"""Serialize Microsoft Defender advanced-hunting result rows to CSV.

Graph's ``POST /security/runHuntingQuery`` returns ``list[dict]``. Turning that
into a file an analyst can open is NOT a one-liner, because the payload has four
properties a generic dict→CSV writer gets wrong (all four confirmed against a
live tenant, not assumed):

1. **Ragged rows.** A ``union`` query returns rows with differing key sets, so
   the column list is the first-seen-order union across ALL rows, not
   ``rows[0].keys()``. (``csv.DictWriter`` would raise on the extra keys.)
2. **OData pseudo-columns.** Graph injects ``<Field>@odata.type`` metadata keys
   (5 of them on a bare ``DeviceInfo`` row). They are transport plumbing, not
   query output, so they are dropped.
3. **Nested values.** Some columns (e.g. ``IsInternetFacing``) are dicts, not
   scalars. ``str(dict)`` emits Python repr with single quotes, which no JSON
   parser reads back, so nested values are JSON-encoded.
4. **Formula injection.** Defender rows carry attacker-influenced free text
   (``ProcessCommandLine``, ``FileName``, ``RemoteUrl``). A cell starting with
   ``=``/``+``/``-``/``@`` is executed as a formula by Excel and LibreOffice
   (CWE-1236), so such cells are prefixed with an apostrophe. Genuine numbers
   are exempt, so ``-5`` stays ``-5`` and only non-numeric leaders are escaped.

Everything here is pure and unit-tested: no DB, no network, no Defender client.
The caller encodes with ``utf-8-sig``: Excel misreads UTF-8 CSV without a BOM.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

# Graph appends these to annotate a field's EDM type (e.g. "OSBuild@odata.type").
# Never part of the analyst's query output.
_ODATA_MARKER = "@odata."

# Leading characters a spreadsheet treats as the start of a formula.
# Tab and CR are included: both let a payload lead a cell after Excel trims it.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def _looks_numeric(text: str) -> bool:
    """True when the cell is a plain number, so a negative value is not escaped.

    Guards the formula-injection escape from mangling legitimate data: ``-5`` and
    ``+1.5e3`` parse and stay verbatim, while ``-2+3+cmd|' /C calc'!A0`` does not.
    """
    try:
        float(text)
    except ValueError:
        return False
    return True


def _escape_formula(text: str) -> str:
    """Neutralize a spreadsheet formula cell by prefixing an apostrophe (CWE-1236).

    Excel/LibreOffice/Sheets render the value verbatim and never evaluate it. Applied
    only to non-numeric cells so real numbers survive a round-trip unchanged.
    """
    if text.startswith(_FORMULA_LEADERS) and not _looks_numeric(text):
        return "'" + text
    return text


def _cell(value: Any) -> str:
    """One JSON value → its CSV cell text.

    None becomes empty (an unset column reads as blank, not the string "None");
    bools become JSON's lowercase spelling rather than Python's ``True``; dict/list
    are JSON-encoded so the cell re-parses; everything else is ``str()``. Quoting,
    embedded commas, quotes, and newlines are left to ``csv``, which does that right.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        # ensure_ascii=False keeps non-Latin hostnames readable; compact separators
        # keep wide rows from ballooning.
        return _escape_formula(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    return _escape_formula(str(value))


def columns(rows: list[dict[str, Any]]) -> list[str]:
    """The CSV header: first-seen-order union of keys across rows, OData keys dropped.

    First-seen order (not sorted) preserves the projection order the analyst wrote
    in their ``| project`` clause, which is what they expect to read left-to-right.
    """
    out: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if _ODATA_MARKER in key or key in seen:
                continue
            seen.add(key)
            out.append(key)
    return out


def rows_to_csv(rows: list[dict[str, Any]]) -> str:
    """Advanced-hunting rows → RFC 4180 CSV text (header + one line per row).

    Returns "" for an empty result set: there are no columns to name, and an empty
    file is a truer representation of "the query matched nothing" than a bare header.
    """
    cols = columns(rows)
    if not cols:
        return ""
    buf = io.StringIO()
    writer = csv.writer(buf)  # default lineterminator is \r\n (RFC 4180 / Excel)
    # The HEADER needs the same formula guard as the data. Column names are not
    # always the fixed table schema: `| evaluate bag_unpack(...)` promotes telemetry
    # JSON keys to column names, and those keys are attacker-influenced. Verified
    # against a live tenant: Graph accepted a query returning a column named "=1+1".
    writer.writerow([_escape_formula(c) for c in cols])
    for row in rows:
        writer.writerow([_cell(row.get(c)) for c in cols])
    return buf.getvalue()


def to_csv_bytes(rows: list[dict[str, Any]]) -> bytes:
    """CSV encoded for download: UTF-8 with a BOM, surrogate-safe.

    The BOM is what makes Excel read the file as UTF-8 instead of the local
    codepage (without it, ``Müller`` renders as mojibake).

    ``errors="replace"`` is load-bearing, not defensive dressing: JSON permits lone
    UTF-16 surrogates and ``json.loads`` returns them verbatim, so a file named with
    an unpaired surrogate (legal on NTFS, whose names are UTF-16) reaches us intact
    and a plain ``.encode()`` raises UnicodeEncodeError, turning one hostile
    filename into a 500 for the whole export. Verified reproducible.

    Encoding lives here rather than in the route so a caller cannot get it wrong.
    """
    return rows_to_csv(rows).encode("utf-8-sig", errors="replace")


_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def download_filename(label: str, stamp: str) -> str:
    """A Content-Disposition filename that cannot break out of the header.

    ``label`` is caller-supplied (a tenant identifier or case number), so a quote,
    newline, or semicolon in it would otherwise let the value escape the quoted
    header parameter. Everything outside ``[A-Za-z0-9._-]`` collapses to a single
    dash, and the label is length-capped.
    """
    safe = _SAFE_FILENAME.sub("-", label).strip("-")[:60] or "tenant"
    return f"defender-hunt-{safe}-{stamp}.csv"


def graph_error_message(raw: str) -> str:
    """Pull the human-readable message out of a Graph error envelope.

    ``DefenderError.message`` carries the raw response body, which for a KQL syntax
    error is a JSON envelope wrapping the one useful sentence alongside request-ids
    an analyst cannot act on:

        {"error":{"code":"BadRequest","message":"Query operator expected.. Fix
         syntax errors in your query.","innerError":{"request-id":"…"}}}

    Returns the inner ``error.message`` when present, else the input unchanged, so a
    non-JSON body (proxy HTML, timeout text) still surfaces something.
    """
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return raw
    if isinstance(parsed, dict):
        err = parsed.get("error")
        if isinstance(err, dict):
            message = err.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()
    return raw
