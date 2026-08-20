"""Unit tests for hunt.export: Defender advanced-hunting rows → CSV.

Every case here was derived from a real Graph payload against a live tenant, not
imagined: the ragged-key behaviour, the ``@odata.type`` pseudo-columns, the nested
dict value, and the error envelope are all things the API actually sends. The two
regression blocks at the bottom cover defects found by smoke-testing the real API
after an automated review had declared the module clean.

Pure: no DB, no network, no Defender client.
"""

from __future__ import annotations

import csv
import io
import json

from isoc_api.hunt import export


def _parse(text: str) -> list[list[str]]:
    """CSV text → rows, so assertions test what a spreadsheet actually sees
    rather than the pre-quoting string."""
    return list(csv.reader(io.StringIO(text)))


# ── columns(): union, ordering, odata stripping ─────────────────────────────
def test_columns_are_first_seen_union_across_ragged_rows():
    # Real cause: Graph emits <Field>@odata.type only for non-null values, so
    # "DeviceEvents | take 50" comes back with 4 distinct raw key sets.
    rows = [{"a": 1, "b": 2}, {"b": 20, "c": 30}, {"c": 300, "a": 100, "d": 4}]
    assert export.columns(rows) == ["a", "b", "c", "d"]


def test_columns_preserve_projection_order_not_alphabetical():
    rows = [{"zeta": 1, "alpha": 2, "mid": 3}]
    assert export.columns(rows) == ["zeta", "alpha", "mid"]


def test_columns_drop_odata_pseudo_columns():
    rows = [{"OSBuild": 22631, "OSBuild@odata.type": "#Int64", "DeviceName": "WS01"}]
    assert export.columns(rows) == ["OSBuild", "DeviceName"]


def test_columns_deduplicate_repeated_keys_across_rows():
    rows = [{"a": 1}, {"a": 2}, {"a": 3}]
    assert export.columns(rows) == ["a"]


# ── rows_to_csv(): shape ────────────────────────────────────────────────────
def test_ragged_rows_produce_rectangular_csv_with_blank_fills():
    rows = [{"a": 1, "b": 2}, {"b": 20, "c": 30}, {"c": 300, "a": 100, "d": 4}]
    parsed = _parse(export.rows_to_csv(rows))
    assert parsed[0] == ["a", "b", "c", "d"]
    assert parsed[1] == ["1", "2", "", ""]
    assert parsed[2] == ["", "20", "30", ""]
    assert parsed[3] == ["100", "", "300", "4"]
    assert all(len(r) == 4 for r in parsed)


def test_missing_key_is_blank_not_the_string_none():
    parsed = _parse(export.rows_to_csv([{"a": 1}, {"b": 2}]))
    assert "None" not in [cell for row in parsed[1:] for cell in row]


def test_empty_inputs_produce_empty_output():
    assert export.rows_to_csv([]) == ""
    assert export.rows_to_csv([{}]) == ""
    # A row of nothing but Graph plumbing has no real columns either.
    assert export.rows_to_csv([{"X@odata.type": "#Int64"}]) == ""


# ── rows_to_csv(): value encoding ───────────────────────────────────────────
def test_none_becomes_empty_cell():
    assert _parse(export.rows_to_csv([{"a": None}]))[1] == [""]


def test_bools_use_json_spelling_and_false_is_not_blank():
    parsed = _parse(export.rows_to_csv([{"t": True, "f": False}]))
    assert parsed[1] == ["true", "false"]


def test_nested_values_are_json_encoded_so_the_cell_reparses():
    # DeviceInfo.IsInternetFacing really does arrive as a dict. str(dict) would
    # emit Python repr with single quotes, which no JSON parser reads back.
    rows = [{"IsInternetFacing": {"deep": {"n": 1}}, "tags": ["a", "b"]}]
    parsed = _parse(export.rows_to_csv(rows))
    assert json.loads(parsed[1][0]) == {"deep": {"n": 1}}
    assert json.loads(parsed[1][1]) == ["a", "b"]


def test_csv_structural_characters_survive_a_round_trip():
    rows = [{"q": 'has "quotes"', "c": "a,b", "n": "l1\nl2", "u": "Müller / 日本語 / 🛡"}]
    parsed = _parse(export.rows_to_csv(rows))
    assert parsed[1] == ['has "quotes"', "a,b", "l1\nl2", "Müller / 日本語 / 🛡"]
    # An embedded newline must stay inside its cell, not split the record.
    assert len(parsed) == 2


# ── Formula injection (CWE-1236) ────────────────────────────────────────────
# Defender rows carry attacker-influenced free text (ProcessCommandLine, FileName,
# RemoteUrl). A cell starting with =/+/-/@ is executed by Excel and LibreOffice.
def test_formula_payloads_in_data_cells_are_neutralized():
    rows = [
        {
            "cmd": "=cmd|' /C calc'!A0",
            "plus": "+SUM(1+1)*cmd|' /C powershell'!A0",
            "minus": "-2+3+cmd|' /C calc'!A0",
            "at": "@SUM(1+1)",
            "tab": "\tcalc",
        }
    ]
    for cell in _parse(export.rows_to_csv(rows))[1]:
        assert cell.startswith("'"), cell


def test_genuine_numbers_are_never_mangled_by_the_formula_guard():
    rows = [{"neg_int": -5, "neg_str": "-5", "sci": "+1.5e3", "plain": "42"}]
    assert _parse(export.rows_to_csv(rows))[1] == ["-5", "-5", "+1.5e3", "42"]


def test_benign_values_pass_through_untouched():
    assert _parse(export.rows_to_csv([{"f": "explorer.exe"}]))[1] == ["explorer.exe"]


# ── REGRESSION: header-row formula injection ────────────────────────────────
# Found by smoke-testing the live API. Column names are NOT always the fixed table
# schema: `| evaluate bag_unpack(todynamic(AdditionalFields))` promotes telemetry
# JSON keys to column names, and those keys are attacker-influenced. Graph accepted
# such a query and returned a column literally named "=1+1", which was written into
# the header raw while the identical string as a data value was correctly escaped.
def test_header_cells_get_the_same_formula_guard_as_data_cells():
    rows = [{"=1+1": "pwned", "DeviceName": "WS01"}]
    header = _parse(export.rows_to_csv(rows))[0]
    assert header[0] == "'=1+1"
    assert header[1] == "DeviceName"


def test_every_formula_leader_is_escaped_in_the_header():
    for payload in ("=1+1", "+SUM(1)", "-2+3+cmd|' /C calc'!A0", "@SUM(1)", "\tcalc"):
        header = _parse(export.rows_to_csv([{payload: "v"}]))[0]
        assert header[0].startswith("'"), payload


def test_numeric_column_name_is_not_mangled():
    assert _parse(export.rows_to_csv([{"-5": "v"}]))[0] == ["-5"]


def test_ordinary_column_names_are_left_alone():
    header = _parse(export.rows_to_csv([{"Timestamp": 1, "DeviceId": "x"}]))[0]
    assert header == ["Timestamp", "DeviceId"]


# ── to_csv_bytes(): download encoding ───────────────────────────────────────
def test_csv_bytes_carry_the_utf8_bom_excel_needs():
    data = export.to_csv_bytes([{"host": "Müller"}])
    assert data[:3] == b"\xef\xbb\xbf"
    assert "Müller" in data.decode("utf-8-sig")


# REGRESSION: JSON permits lone UTF-16 surrogates and json.loads returns them
# verbatim. NTFS filenames are UTF-16 and may contain unpaired surrogates, so one
# hostile filename made a plain .encode() raise UnicodeEncodeError, turning the
# whole export into a 500.
def test_lone_surrogate_in_a_value_does_not_break_the_download():
    rows = json.loads('{"r":[{"FileName":"evil\\ud83d.exe","DeviceName":"WS01"}]}')["r"]
    data = export.to_csv_bytes(rows)  # must not raise
    assert data[:3] == b"\xef\xbb\xbf"
    assert "WS01" in data.decode("utf-8-sig")


def test_empty_result_encodes_to_just_the_bom():
    assert export.to_csv_bytes([]) == b"\xef\xbb\xbf"


# ── graph_error_message() ───────────────────────────────────────────────────
def test_graph_envelope_yields_the_actionable_sentence_only():
    raw = (
        '{"error":{"code":"BadRequest","message":"Query operator expected.. Fix syntax '
        'errors in your query.","innerError":{"date":"2026-08-19T08:12:18",'
        '"request-id":"b2d2f2e0-830b-4df6-a930-ad0945a8e7c0"}}}'
    )
    out = export.graph_error_message(raw)
    assert out == "Query operator expected.. Fix syntax errors in your query."
    assert "request-id" not in out


def test_non_json_body_passes_through_unchanged():
    # A proxy error page or timeout text must still surface something.
    assert (
        export.graph_error_message("<html>502 Bad Gateway</html>") == "<html>502 Bad Gateway</html>"
    )


def test_json_without_an_error_object_passes_through():
    assert export.graph_error_message('{"results":[]}') == '{"results":[]}'


def test_blank_inner_message_falls_back_to_the_raw_body():
    raw = '{"error":{"message":"   "}}'
    assert export.graph_error_message(raw) == raw


def test_non_dict_json_passes_through():
    assert export.graph_error_message("[1,2,3]") == "[1,2,3]"
    assert export.graph_error_message('"just a string"') == '"just a string"'
