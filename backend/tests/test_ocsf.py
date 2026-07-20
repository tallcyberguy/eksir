"""Unit tests for the pure OCSF entity mapper/resolver (pipeline/ocsf.py).

Pure functions — no stack. Assertions pin the *resolution invariants*:
  1. canonical_key is pure/deterministic.
  2. same real thing -> same key.
  3. different real thing -> different key.
  4. file keys are global (no customer segment); host/user/ip keys start with
     the canonical customer (or 'unknown').
  5. no input shape raises, except an unknown entity_type to canonical_key.
plus targeted edge cases (machine-account type_id, ';'-recipient split,
malformed-ip skip, path-only => no file entity).
"""

from __future__ import annotations

import pytest

from isoc_api.pipeline.ocsf import (
    DEVICE_TYPE_FIREWALL,
    OBS_CVE,
    OBS_HASH,
    OBS_RESOURCE_UID,
    USER_TYPE_SYSTEM,
    canonical_key,
    to_entities,
    to_ocsf_event,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _by_type(ents, entity_type):
    return [e for e in ents if e["entity_type"] == entity_type]


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
def test_constant_aliases():
    assert OBS_CVE == OBS_RESOURCE_UID == 10
    assert USER_TYPE_SYSTEM == 3
    assert DEVICE_TYPE_FIREWALL == 9
    assert OBS_HASH == 8


# ---------------------------------------------------------------------------
# (1) canonical_key is pure/deterministic
# ---------------------------------------------------------------------------
def test_canonical_key_is_deterministic():
    attrs = {"hostname": "DC01.corp.local", "ip": "10.0.0.1", "uid": None, "name": "DC01"}
    k1 = canonical_key("device", attrs, "AcmeCorp")
    k2 = canonical_key("device", dict(attrs), "AcmeCorp")
    assert k1 == k2 == "acmecorp:device:name:dc01"


# ---------------------------------------------------------------------------
# (2) same real thing -> same key
# ---------------------------------------------------------------------------
def test_fqdn_and_short_host_unify():
    fqdn = canonical_key("device", {"hostname": "dc01.corp.local"}, "acme")
    short = canonical_key("device", {"hostname": "DC01"}, "acme")
    assert fqdn == short == "acme:device:name:dc01"


def test_ipv4_and_ipv4_mapped_unify():
    plain = canonical_key("network_endpoint", {"ip": "10.1.2.3"}, "acme")
    mapped = canonical_key("network_endpoint", {"ip": "::ffff:10.1.2.3"}, "acme")
    assert plain == mapped == "acme:network_endpoint:ip:10.1.2.3"


def test_ipv6_is_rfc5952_compressed_lower():
    k = canonical_key("network_endpoint", {"ip": "2001:0DB8:0000:0000:0000:0000:0000:0001"}, "acme")
    assert k == "acme:network_endpoint:ip:2001:db8::1"


def test_sha256_with_and_without_sha1_same_key():
    both = {
        "hashes": [
            {"algorithm": "SHA-256", "value": "a" * 64},
            {"algorithm": "SHA-1", "value": "b" * 40},
        ]
    }
    only256 = {"hashes": [{"algorithm": "SHA-256", "value": "A" * 64}]}
    assert canonical_key("file", both) == canonical_key("file", only256)
    assert canonical_key("file", both) == "global:file:sha256:" + "a" * 64


def test_src_view_and_dst_view_of_one_ip_same_endpoint():
    n = {"customer": "acme", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.10", "dst_port": 443}
    ents = to_entities(n)
    endpoints = _by_type(ents, "network_endpoint")
    # role is NOT part of the key -> one dedup'd endpoint for the shared IP.
    assert len(endpoints) == 1
    assert endpoints[0]["canonical_key"] == "acme:network_endpoint:ip:192.168.1.10"


# ---------------------------------------------------------------------------
# (3) different real thing -> different key
# ---------------------------------------------------------------------------
def test_sid_vs_unresolved_name_differ():
    sid = canonical_key("user", {"uid": "S-1-5-21-1-2-3", "name": None}, "acme")
    named = canonical_key("user", {"name": "jsmith"}, "acme")
    assert sid != named
    assert sid == "acme:user:sid:s-1-5-21-1-2-3"
    assert named == "acme:user:sam:jsmith"


def test_different_customers_separated_by_scope():
    k_a = canonical_key("device", {"hostname": "host1"}, "cust-a")
    k_b = canonical_key("device", {"hostname": "host1"}, "cust-b")
    assert k_a != k_b
    assert k_a.startswith("cust-a:")
    assert k_b.startswith("cust-b:")


def test_different_sha256_differ():
    k1 = canonical_key("file", {"hashes": [{"algorithm": "SHA-256", "value": "a" * 64}]})
    k2 = canonical_key("file", {"hashes": [{"algorithm": "SHA-256", "value": "c" * 64}]})
    assert k1 != k2


# ---------------------------------------------------------------------------
# (4) tenancy of keys
# ---------------------------------------------------------------------------
def test_file_keys_are_global_no_customer_segment():
    n = {"customer": "acme", "file_hash_sha256": "d" * 64, "file_path": "/tmp/x.exe"}
    ents = to_entities(n)
    files = _by_type(ents, "file")
    assert len(files) == 1
    f = files[0]
    assert f["customer"] is None
    assert f["canonical_key"].startswith("global:file:")
    assert "acme" not in f["canonical_key"]


def test_hash_observable_is_global_other_observables_per_customer():
    n = {"customer": "acme", "hostname": "web01", "file_hash_sha256": "e" * 64}
    ents = to_entities(n)
    obs = _by_type(ents, "observable")
    hash_obs = [o for o in obs if o["attributes"]["type_id"] == OBS_HASH]
    host_obs = [o for o in obs if o["attributes"]["name"] == "hostname"]
    assert hash_obs and hash_obs[0]["customer"] is None
    assert hash_obs[0]["canonical_key"].startswith("global:observable:")
    assert host_obs and host_obs[0]["customer"] == "acme"
    assert host_obs[0]["canonical_key"].startswith("acme:observable:")


def test_host_user_ip_keys_start_with_canonical_customer():
    n = {
        "customer": "Acme Corp!",  # -> 'acme-corp'
        "hostname": "srv1",
        "username": "alice",
        "src_ip": "203.0.113.9",
    }
    ents = to_entities(n)
    for et in ("device", "user", "network_endpoint"):
        for e in _by_type(ents, et):
            assert e["canonical_key"].startswith("acme-corp:")
            assert e["customer"] == "acme-corp"


def test_missing_customer_falls_back_to_unknown():
    ents = to_entities({"hostname": "srv1"})
    dev = _by_type(ents, "device")[0]
    assert dev["customer"] == "unknown"
    assert dev["canonical_key"].startswith("unknown:")


# ---------------------------------------------------------------------------
# (5) robustness — no input shape raises (except unknown entity_type)
# ---------------------------------------------------------------------------
def test_unknown_entity_type_raises():
    with pytest.raises(ValueError):
        canonical_key("planet", {"value": "mars"}, "acme")


def test_empty_and_none_inputs_do_not_raise():
    assert to_entities({}) == []
    assert to_entities({"hostname": "", "username": "   ", "src_ip": None}) == []
    # non-dict guard
    assert to_entities(None) == []  # type: ignore[arg-type]


def test_non_str_field_values_are_skipped():
    n = {"customer": "acme", "hostname": 12345, "username": ["x"], "src_ip": {"a": 1}}
    ents = to_entities(n)
    assert ents == []


# ---------------------------------------------------------------------------
# targeted edge cases
# ---------------------------------------------------------------------------
def test_machine_account_type_id_and_key_keeps_dollar():
    ents = to_entities({"customer": "acme", "username": "DC01$"})
    users = _by_type(ents, "user")
    assert len(users) == 1
    u = users[0]
    assert u["attributes"]["type_id"] == USER_TYPE_SYSTEM
    assert u["canonical_key"] == "acme:user:sam:dc01$"


def test_sid_username_keyed_on_sid():
    ents = to_entities({"customer": "acme", "username": "S-1-5-21-99-1-500"})
    users = _by_type(ents, "user")
    assert len(users) == 1
    u = users[0]
    assert u["attributes"]["name"] is None
    assert u["attributes"]["uid"] == "S-1-5-21-99-1-500"
    assert u["attributes"]["type_id"] == USER_TYPE_SYSTEM
    assert u["canonical_key"] == "acme:user:sid:s-1-5-21-99-1-500"


def test_domain_backslash_user_key():
    ents = to_entities({"customer": "acme", "username": "CORP\\Alice"})
    u = _by_type(ents, "user")[0]
    assert u["canonical_key"] == "acme:user:sam:corp\\alice"
    assert u["attributes"]["domain"] == "CORP"
    assert u["attributes"]["name"] == "Alice"


def test_upn_user_sets_email_and_sam_key():
    ents = to_entities({"customer": "acme", "username": "alice@corp.local."})
    u = _by_type(ents, "user")[0]
    assert u["canonical_key"] == "acme:user:sam:corp.local\\alice"
    assert u["attributes"]["email_addr"] == "alice@corp.local."


def test_domain_backslash_empty_user_skipped():
    ents = to_entities({"customer": "acme", "username": "CORP\\"})
    assert _by_type(ents, "user") == []


def test_recipient_semicolon_split():
    n = {"customer": "acme", "recipient": "a@x.com; b@x.com ;c@x.com"}
    ents = to_entities(n)
    recips = [e for e in _by_type(ents, "user") if e["role"] == "recipient"]
    addrs = {e["display_name"] for e in recips}
    assert addrs == {"a@x.com", "b@x.com", "c@x.com"}
    for e in recips:
        assert e["canonical_key"].startswith("acme:user:email:")


def test_sender_and_recipient_roles():
    n = {"customer": "acme", "sender": "boss@evil.com", "recipient": "victim@corp.com"}
    ents = to_entities(n)
    roles = {e["role"] for e in _by_type(ents, "user")}
    assert "sender" in roles
    assert "recipient" in roles


def test_malformed_ip_skipped():
    n = {"customer": "acme", "src_ip": "999.999.999.999", "dst_ip": "not-an-ip"}
    ents = to_entities(n)
    assert _by_type(ents, "network_endpoint") == []
    # ...but the observable is still emitted (raw value, no resolution).
    ip_obs = [o for o in _by_type(ents, "observable") if o["attributes"]["type_id"] == 2]
    assert {o["display_name"] for o in ip_obs} == {"999.999.999.999", "not-an-ip"}


def test_path_only_no_file_entity_but_filename_observable():
    n = {"customer": "acme", "file_path": "C:\\Users\\bob\\payload.exe"}
    ents = to_entities(n)
    assert _by_type(ents, "file") == []
    fn_obs = [o for o in _by_type(ents, "observable") if o["attributes"]["name"] == "file_name"]
    assert len(fn_obs) == 1
    assert fn_obs[0]["display_name"] == "payload.exe"


def test_both_hashes_one_file_entity_keyed_on_sha256():
    n = {
        "customer": "acme",
        "file_path": "/opt/mal.bin",
        "file_hash_sha256": "F" * 64,
        "file_hash_sha1": "9" * 40,
    }
    ents = to_entities(n)
    files = _by_type(ents, "file")
    assert len(files) == 1
    f = files[0]
    assert f["canonical_key"] == "global:file:sha256:" + "f" * 64
    assert f["attributes"]["name"] == "mal.bin"
    algos = {h["algorithm"] for h in f["attributes"]["hashes"]}
    assert algos == {"SHA-256", "SHA-1"}


def test_firewall_device_type_id():
    fw = to_entities({"customer": "acme", "hostname": "fw01", "source_product": "fortigate"})
    assert _by_type(fw, "device")[0]["attributes"]["type_id"] == DEVICE_TYPE_FIREWALL
    non_fw = to_entities({"customer": "acme", "hostname": "srv1", "source_product": "wazuh"})
    assert _by_type(non_fw, "device")[0]["attributes"]["type_id"] == 0


def test_device_ip_prefers_agent_ip_then_src_ip():
    d1 = to_entities(
        {"customer": "acme", "hostname": "h", "agent_ip": "10.0.0.5", "src_ip": "1.1.1.1"}
    )
    assert _by_type(d1, "device")[0]["attributes"]["ip"] == "10.0.0.5"
    d2 = to_entities({"customer": "acme", "hostname": "h", "src_ip": "1.1.1.1"})
    assert _by_type(d2, "device")[0]["attributes"]["ip"] == "1.1.1.1"


def test_cve_observable_lowercased_type_10():
    ents = to_entities({"customer": "acme", "cve": "CVE-2024-1234"})
    cve_obs = [o for o in _by_type(ents, "observable") if o["attributes"]["name"] == "cve"]
    assert len(cve_obs) == 1
    o = cve_obs[0]
    assert o["attributes"]["type_id"] == OBS_CVE == 10
    assert o["display_name"] == "cve-2024-1234"
    assert o["canonical_key"] == "acme:observable:10:cve-2024-1234"


def test_private_and_loopback_ips_are_kept():
    n = {"customer": "acme", "src_ip": "127.0.0.1", "dst_ip": "169.254.1.1", "agent_ip": "10.0.0.1"}
    ents = to_entities(n)
    endpoints = _by_type(ents, "network_endpoint")
    got = {e["canonical_key"] for e in endpoints}
    assert got == {
        "acme:network_endpoint:ip:127.0.0.1",
        "acme:network_endpoint:ip:169.254.1.1",
        "acme:network_endpoint:ip:10.0.0.1",
    }


def test_entity_dict_shape():
    ents = to_entities({"customer": "acme", "hostname": "web01"})
    dev = _by_type(ents, "device")[0]
    assert set(dev.keys()) == {
        "entity_type",
        "customer",
        "canonical_key",
        "display_name",
        "attributes",
        "role",
    }


def test_dedup_first_occurrence_wins():
    # Same host appears as device hostname and hostname observable; distinct
    # entity_types so both survive, but a repeated IP across src/dst/agent
    # collapses to one endpoint.
    n = {
        "customer": "acme",
        "src_ip": "8.8.8.8",
        "dst_ip": "8.8.8.8",
        "agent_ip": "8.8.8.8",
    }
    ents = to_entities(n)
    endpoints = _by_type(ents, "network_endpoint")
    assert len(endpoints) == 1
    # first occurrence (source) wins the role.
    assert endpoints[0]["role"] == "source"


def test_all_keys_unique_after_dedup():
    n = {
        "customer": "acme",
        "hostname": "web01",
        "username": "alice",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "dst_port": 443,
        "sender": "a@x.com",
        "recipient": "b@y.com;c@z.com",
        "url": "http://evil.test/p",
        "file_path": "/tmp/x.exe",
        "file_hash_sha256": "1" * 64,
        "cve": "CVE-2024-0001",
    }
    ents = to_entities(n)
    keys = [e["canonical_key"] for e in ents]
    assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# regression: review findings (IP-literal host, non-NT SID, observable folding)
# ---------------------------------------------------------------------------
def test_ip_literal_hostname_not_folded_to_octet():
    # A bare-IP hostname (RFC3164 syslog / QRadar log source) must NOT fold to
    # its first octet, or all 192.x hosts collapse onto one device.
    a = canonical_key("device", {"hostname": "192.0.2.10"}, "acme")
    b = canonical_key("device", {"hostname": "192.0.2.20"}, "acme")
    assert a != b
    assert a == "acme:device:name:192.0.2.10"
    # a real FQDN still folds to its short label
    assert (
        canonical_key("device", {"hostname": "dc01.corp.local"}, "acme") == "acme:device:name:dc01"
    )


def test_device_ip_fallback_canonicalizes():
    # If ever keyed by ip alone, IPv4-mapped and plain IPv4 must unify.
    a = canonical_key("device", {"ip": "::ffff:10.0.0.5"}, "acme")
    b = canonical_key("device", {"ip": "10.0.0.5"}, "acme")
    assert a == b == "acme:device:ip:10.0.0.5"


def test_non_nt_authority_sids_recognized():
    # SIDs with a non-5 identifier authority (Everyone, integrity labels, Azure AD)
    # must key on :sid: with type_id=System, not be treated as SAM usernames.
    for sid in ("S-1-1-0", "S-1-16-12288", "S-1-12-1-4"):
        u = _by_type(to_entities({"customer": "acme", "username": sid}), "user")[0]
        assert u["attributes"]["type_id"] == USER_TYPE_SYSTEM
        assert u["canonical_key"] == f"acme:user:sid:{sid.lower()}"
    # authority-only 'S-1-5' has no sub-authority -> NOT a SID, stays a SAM name.
    u = _by_type(to_entities({"customer": "acme", "username": "S-1-5"}), "user")[0]
    assert u["canonical_key"] == "acme:user:sam:s-1-5"


def test_hostname_observable_folds_like_device():
    def host_obs_key(ents):
        return next(
            o["canonical_key"]
            for o in _by_type(ents, "observable")
            if o["attributes"]["name"] == "hostname"
        )

    short = host_obs_key(to_entities({"customer": "acme", "hostname": "dc01"}))
    fqdn = host_obs_key(to_entities({"customer": "acme", "hostname": "dc01.corp.local"}))
    assert short == fqdn == "acme:observable:1:dc01"


def test_ip_observable_canonicalized():
    def ip_obs_key(ents):
        return next(
            o["canonical_key"]
            for o in _by_type(ents, "observable")
            if o["attributes"]["type_id"] == 2
        )

    exploded = ip_obs_key(to_entities({"customer": "acme", "src_ip": "2001:0DB8:0000::1"}))
    compressed = ip_obs_key(to_entities({"customer": "acme", "src_ip": "2001:db8::1"}))
    assert exploded == compressed == "acme:observable:2:2001:db8::1"


# ---------------------------------------------------------------------------
# OCSF event envelope (ADR-0006 P1c)
# ---------------------------------------------------------------------------
def test_to_ocsf_event_basic_detection_finding():
    n = {
        "source_product": "wazuh",
        "rule_name": "sshd: authentication failed",
        "severity_id": 4,
        "alert_id": "abc-123",
        "src_ip": "203.0.113.9",
        "hostname": "web01",
        "timestamp": "2026-07-13T10:00:00Z",
    }
    ev = to_ocsf_event(n, customer="acme")
    assert ev["class_uid"] == 2004 and ev["category_uid"] == 2
    assert ev["type_uid"] == 200401 and ev["activity_id"] == 1
    assert ev["severity_id"] == 4 and ev["severity"] == "High"
    assert ev["metadata"]["product"]["name"] == "wazuh"
    assert ev["finding_info"]["title"] == "sshd: authentication failed"
    assert ev["finding_info"]["uid"] == "abc-123"
    # observables were derived from the resolved entities (host + ip)
    values = {o["value"] for o in ev["observables"]}
    assert "web01" in values and "203.0.113.9" in values


def test_to_ocsf_event_defaults_severity_when_missing():
    ev = to_ocsf_event({"source_product": "custom", "rule_name": "x"})
    assert ev["severity_id"] == 0 and ev["severity"] == "Unknown"


def test_to_ocsf_event_title_falls_back():
    ev = to_ocsf_event({"source_product": "custom", "severity_id": 2})
    assert ev["finding_info"]["title"] == "Alert"


def test_to_ocsf_event_non_dict_is_empty():
    assert to_ocsf_event(None) == {}  # type: ignore[arg-type]
    assert to_ocsf_event("nope") == {}  # type: ignore[arg-type]
