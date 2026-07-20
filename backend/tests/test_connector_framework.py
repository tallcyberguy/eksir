"""Unit tests for the typed connector framework (ADR-0006).

Pure — no stack, no vendored parsers, no httpx. Locks the contract's behavior and, crucially, that
`Connector.to_spec()` is backward-compatible with the legacy `registry.py` catalogue so the
registry can be flipped to build from `Connector` classes without breaking routes/admin or the UI.
"""

from __future__ import annotations

from isoc_api.adapters.connectors import registry, severity
from isoc_api.adapters.connectors.capabilities import Capability, coarse_for, is_response
from isoc_api.adapters.connectors.drift import (
    detect_drift,
    detect_drift_keyset,
    field_fingerprint,
)
from isoc_api.adapters.connectors.fields import (
    Field,
    FieldType,
    OAuthHints,
    validate_config,
)
from isoc_api.adapters.connectors.providers import CortexXdrConnector, SentinelOneConnector
from isoc_api.adapters.connectors.routing import KNOWN_PARSER_SOURCES, resolve_parser_source

# --- fields + validation ---------------------------------------------------


def test_field_to_dict_exposes_type_and_masking():
    f = Field("api_key", "API token", FieldType.SECRET, help="bearer")
    d = f.to_dict()
    assert d["type"] == "secret" and d["secret"] is True and d["required"] is True


def test_validate_config_flags_missing_required_and_bad_select():
    fields = (
        Field("api_key", "API token", FieldType.SECRET, required=True),
        Field("region", "Region", FieldType.SELECT, required=False, options=("us", "eu")),
    )
    assert validate_config(fields, {"api_key": "x", "region": "us"}) == []
    assert any("api_key" in e for e in validate_config(fields, {"region": "us"}))
    assert any("region" in e for e in validate_config(fields, {"api_key": "x", "region": "jp"}))


def test_validate_config_tolerates_unknown_keys():
    fields = (Field("api_key", "API token", FieldType.SECRET),)
    assert validate_config(fields, {"api_key": "x", "extra": "ignored"}) == []


def test_oauth_hints_round_trip():
    oh = OAuthHints(token_url="{base_url}/oauth2/token", scopes=("a", "b"))
    d = oh.to_dict()
    assert d["token_url"].endswith("/oauth2/token") and d["scopes"] == ["a", "b"]


# --- capabilities ----------------------------------------------------------


def test_coarse_projection_matches_legacy_words():
    caps = (
        Capability.PULL_ALERTS,
        Capability.ENRICH_IOC,
        Capability.HUNT_QUERY,
        Capability.ISOLATE_HOST,
    )
    assert set(coarse_for(caps)) == {"enrich", "hunt", "respond"}
    # stable order
    assert coarse_for(caps) == ("enrich", "hunt", "respond")


def test_is_response_only_for_effect_verbs():
    assert is_response(Capability.ISOLATE_HOST)
    assert is_response(Capability.PUSH_CASE)
    assert not is_response(Capability.ENRICH_IOC)
    assert not is_response(Capability.HUNT_QUERY)


# --- OCSF severity ---------------------------------------------------------


def test_ocsf_severity_words():
    assert severity.to_ocsf_severity("critical") == 5
    assert severity.to_ocsf_severity("High") == 4
    assert severity.to_ocsf_severity("medium") == 3
    assert severity.to_ocsf_severity("low") == 2
    assert severity.to_ocsf_severity("informational") == 1
    assert severity.to_ocsf_severity(None) == 0
    # unmapped word does not silently sink to noise
    assert severity.to_ocsf_severity("weird-vendor-word") == 3


def test_ocsf_severity_numbers_by_scale():
    # 0-100 score bands
    assert severity.to_ocsf_severity(95) == 5
    assert severity.to_ocsf_severity(75) == 4
    assert severity.to_ocsf_severity(50) == 3
    assert severity.to_ocsf_severity(25) == 2
    # Wazuh 1-15 levels (7-15 read as a Wazuh rule level; <=6 is an OCSF ordinal passthrough)
    assert severity.to_ocsf_severity(12) == 4  # Wazuh "high" band (7-12)
    assert severity.to_ocsf_severity(9) == 4
    assert severity.to_ocsf_severity(14) == 5  # Wazuh "critical" band (13-15)
    # n <= 6 is treated as an already-OCSF ordinal (ambiguous with a Wazuh low level by design)
    assert severity.to_ocsf_severity(3) == 3


def test_wazuh_bridge_matches_normalizer_bands():
    # normalizer word bands: low 1-3, medium 4-6, high 7-12, critical 13-15; 0 -> unknown
    assert severity.wazuh_to_ocsf(2) == 2  # low
    assert severity.wazuh_to_ocsf(5) == 3  # medium
    assert severity.wazuh_to_ocsf(12) == 4  # high
    assert severity.wazuh_to_ocsf(14) == 5  # critical
    assert severity.wazuh_to_ocsf(0) == 0  # unknown
    assert severity.ocsf_to_wazuh(4) == 9


def test_severity_id_from_alert_prefers_word_and_stays_monotonic():
    # the analyst-visible word wins, even if the raw level disagrees
    assert severity.severity_id_from_alert("high", 3) == 4
    assert severity.severity_id_from_alert("low") == 2
    assert severity.severity_id_from_alert("critical") == 5
    # fall back to the Wazuh level only when the word is missing/unknown
    assert severity.severity_id_from_alert(None, 8) == 4
    assert severity.severity_id_from_alert("unknown", 14) == 5
    assert severity.severity_id_from_alert(None, 0) == 0
    assert severity.severity_id_from_alert(None, None) == 0


def test_ocsf_to_severity_word_drives_incident_severity():
    # OCSF severity_id -> ISOC Severity enum word (option B: high alert -> high incident)
    assert severity.ocsf_to_severity_word(5) == "critical"
    assert severity.ocsf_to_severity_word(6) == "critical"  # Fatal
    assert severity.ocsf_to_severity_word(4) == "high"
    assert severity.ocsf_to_severity_word(3) == "medium"
    assert severity.ocsf_to_severity_word(2) == "low"
    assert severity.ocsf_to_severity_word(1) == "low"  # Informational
    assert severity.ocsf_to_severity_word(0) == "medium"  # Unknown -> safe baseline


def test_parser_adapter_stamps_ocsf_severity_id():
    # the normalized dict gains severity_id additively, monotonic with the word (ADR-0006 P1c)
    from isoc_api.adapters.parser_adapter import _with_ocsf_severity

    assert _with_ocsf_severity({"severity_label": "high", "severity": 8})["severity_id"] == 4
    assert _with_ocsf_severity({"severity_label": "unknown", "severity": 14})["severity_id"] == 5
    assert _with_ocsf_severity({})["severity_id"] == 0
    # existing fields are left untouched
    d = _with_ocsf_severity({"severity_label": "low", "severity": 2})
    assert d["severity_label"] == "low" and d["severity"] == 2


# --- schema-drift sentinel -------------------------------------------------


def test_fingerprint_is_value_independent_but_shape_sensitive():
    a = [{"src_ip": "1.1.1.1", "severity": "high"}]
    b = [{"src_ip": "9.9.9.9", "severity": "low"}]  # same keys, different values
    c = [{"src": "1.1.1.1", "severity": "high"}]  # vendor renamed src_ip -> src
    assert field_fingerprint(a) == field_fingerprint(b)
    assert field_fingerprint(a) != field_fingerprint(c)


def test_detect_drift_first_run_not_flagged_then_flags_change():
    a = [{"src_ip": "1.1.1.1"}]
    first = detect_drift(None, a)
    assert first.changed is False
    same = detect_drift(first.fingerprint, [{"src_ip": "2.2.2.2"}])
    assert same.changed is False
    drift = detect_drift(first.fingerprint, [{"src": "2.2.2.2"}])
    assert drift.changed is True


def test_detect_drift_keyset_reports_added_and_removed():
    r = detect_drift_keyset({"src_ip", "severity"}, [{"src": "x", "severity": "high"}])
    assert r.added == ("src",) and r.removed == ("src_ip",) and r.changed is True


# --- deterministic routing (the P0 fix) ------------------------------------


def test_resolve_parser_source_prefers_declared_over_sniffing():
    # a wrong sniff would return "wazuh"; the declaration wins
    src, reason = resolve_parser_source("sentinelone", KNOWN_PARSER_SOURCES, lambda: "wazuh")
    assert src == "sentinelone" and reason == "declared"


def test_resolve_parser_source_falls_back_when_unknown_or_absent():
    src, reason = resolve_parser_source(None, KNOWN_PARSER_SOURCES, lambda: "qradar")
    assert src == "qradar" and reason == "detected"
    # a declared source we have no parser for => sniff (graceful degrade)
    src, reason = resolve_parser_source("cortex_xdr", KNOWN_PARSER_SOURCES, lambda: "unknown")
    assert src == "unknown" and reason == "detected"


# --- the flip (ADR-0006 P0.2): catalogue is now built from Connector classes ---------
# Golden snapshot of the legacy catalogue captured BEFORE the flip. These are the load-bearing
# fields every existing consumer depends on (routes/admin provider allow-list, admin UI, health);
# the flip rebuilt the catalogue from Connector classes and must reproduce them exactly. Hardcoded
# (not derived from the connectors) so this is a real regression guard, not a tautology.
_LEGACY_GOLDEN: dict[str, dict] = {
    "vision_one": {
        "label": "Trend Micro Vision One",
        "category": "edr",
        "capabilities": ["enrich", "respond"],
        "fields": ["api_key", "region"],
        "identifier_label": "Customer name",
        "adapter_status": "live",
    },
    "sentinelone": {
        "label": "SentinelOne",
        "category": "edr",
        "capabilities": ["enrich", "hunt", "respond"],
        "fields": ["api_key", "base_url"],
        "identifier_label": "Console host",
        "adapter_status": "live",
    },
    "crowdstrike": {
        "label": "CrowdStrike Falcon",
        "category": "edr",
        "capabilities": ["enrich", "respond"],
        "fields": ["client_id", "client_secret", "base_url"],
        "identifier_label": "Customer",
        "adapter_status": "live",
    },
    "cortex_xdr": {
        "label": "Palo Alto Cortex XDR",
        "category": "edr",
        "capabilities": ["enrich", "respond"],
        "fields": ["api_key", "base_url"],
        "identifier_label": "Tenant FQDN",
        "adapter_status": "planned",
    },
    "microsoft_defender": {
        "label": "Microsoft 365 Defender",
        "category": "edr",
        "capabilities": ["enrich", "respond"],
        "fields": ["client_id", "client_secret", "oauth_tenant_id"],
        "identifier_label": "Customer",
        "adapter_status": "live",
    },
    "guardduty": {
        "label": "AWS GuardDuty",
        "category": "edr",
        "capabilities": ["enrich"],
        "fields": ["api_key", "region"],
        "identifier_label": "AWS account",
        "adapter_status": "planned",
    },
    "misp": {
        "label": "MISP",
        "category": "ti",
        "capabilities": ["enrich"],
        "fields": ["api_key", "base_url"],
        "identifier_label": "Instance URL",
        "adapter_status": "planned",
    },
    "taxii": {
        "label": "TAXII 2.1",
        "category": "ti",
        "capabilities": ["enrich"],
        "fields": ["api_key", "base_url"],
        "identifier_label": "Collection URL",
        "adapter_status": "planned",
    },
    "otx": {
        "label": "AlienVault OTX",
        "category": "ti",
        "capabilities": ["enrich"],
        "fields": ["api_key"],
        "identifier_label": "Account",
        "adapter_status": "planned",
    },
    "abuseipdb": {
        "label": "AbuseIPDB",
        "category": "ti",
        "capabilities": ["enrich"],
        "fields": ["api_key"],
        "identifier_label": "Account",
        "adapter_status": "planned",
    },
    "shodan": {
        "label": "Shodan",
        "category": "recon",
        "capabilities": ["enrich"],
        "fields": ["api_key"],
        "identifier_label": "Account",
        "adapter_status": "planned",
    },
    "censys": {
        "label": "Censys",
        "category": "recon",
        "capabilities": ["enrich"],
        "fields": ["api_key"],
        "identifier_label": "Account",
        "adapter_status": "planned",
    },
}


def test_flip_preserves_legacy_catalogue_exactly():
    cat = {c["key"]: c for c in registry.catalog()}
    assert set(cat) == set(_LEGACY_GOLDEN)
    for key, want in _LEGACY_GOLDEN.items():
        got = cat[key]
        for field, val in want.items():
            assert got[field] == val, f"{key}.{field}: {got[field]!r} != {val!r}"


def test_connector_keys_preserve_legacy_order():
    assert registry.connector_keys() == tuple(_LEGACY_GOLDEN)


def test_catalogue_adds_typed_superset():
    cat = {c["key"]: c for c in registry.catalog()}
    s1 = cat["sentinelone"]
    assert s1["parser_source"] == "sentinelone" and s1["auth_shape"] == "token"
    assert s1["field_specs"] and all("type" in f for f in s1["field_specs"])
    df = cat["microsoft_defender"]
    assert df["auth_shape"] == "oauth_client_creds" and df["oauth_hints"]


def test_sentinelone_to_spec_shape():
    spec = SentinelOneConnector.to_spec()
    assert spec["key"] == "sentinelone" and spec["fields"] == ["api_key", "base_url"]
    assert set(spec["capabilities"]) == {"enrich", "hunt", "respond"}
    assert spec["capability_verbs"]  # fine verbs present alongside coarse


async def test_planned_connector_reports_no_adapter():
    # a planned connector (cortex_xdr) is storable but not live-testable yet (asyncio_mode=auto)
    res = await CortexXdrConnector().test_connection(creds=object())
    assert res["ok"] is None and res["status"] == "no_adapter"
