"""Unit tests for ADR-0009 PR-1/2/3: pre-L2 Microsoft enrichment.

Pure/mock-only, no stack needed. Covers the reputation (PR-1), endpoint (PR-2),
and identity (PR-3) slices, the flag/creds gates, the new adapter reads, and the
briefing sections. `prefetch_ms_enrichment` returns the merged `enrichment["ms"]`
dict (or None when nothing ran).
"""

from types import SimpleNamespace

from isoc_api.adapters import defender_adapter
from isoc_api.pipeline import briefing, prefetch

_CREDS = SimpleNamespace(
    oauth_tenant_id="t", client_id="c", client_secret="s", region="us", api_key="k"
)


class _Inc:
    def __init__(self, enrichment=None, normalized=None, customer="acme"):
        self.id = "inc-1"
        self.customer = customer
        self.enrichment = enrichment if enrichment is not None else {}
        self.normalized = normalized if normalized is not None else {}


def _triage_enrichment():
    return {
        "triage": [
            {"query": {"ioc": "abc123sha", "type": "sha256"}, "verdict": "clean_or_unknown"},
            {"query": {"ioc": "release-assets.githubusercontent.com", "type": "domain"}},
            {"query": {"ioc": "140.82.121.3", "type": "ipv4"}},
            {"query": {"ioc": "bob@acme.com", "type": "email"}},  # ignored (not reputable here)
        ]
    }


def _patch_creds(monkeypatch, creds=_CREDS):
    async def _fake(provider, identifier=None):
        return creds

    monkeypatch.setattr(prefetch.integration_store, "get_creds", _fake)


def _patch_creds_by_provider(monkeypatch, **by_provider):
    async def _fake(provider, identifier=None):
        return by_provider.get(provider)

    monkeypatch.setattr(prefetch.integration_store, "get_creds", _fake)


def _patch_reads(monkeypatch, **overrides):
    canned = {
        "get_file_info": {
            "determinationValue": "Clean",
            "signer": "Contoso",
            "isValidCertificate": True,
        },
        "get_file_stats": {"organizationPrevalence": 42, "orgFirstSeen": "2024-01-01"},
        "get_domain_stats": {"organizationPrevalence": 5000, "orgFirstSeen": "2020-01-01"},
        "get_ip_stats": {"organizationPrevalence": 12},
        "check_custom_indicator": {"matches": [{"action": "Allowed"}]},
    }
    for name, value in canned.items():
        payload = overrides.get(name, value)

        def _make(v):
            async def _read(*a, **k):
                if isinstance(v, Exception):
                    raise v
                return v

            return _read

        monkeypatch.setattr(prefetch.defender_adapter, name, _make(payload))


def _async(value):
    async def _fn(*a, **k):
        return value

    return _fn


# ── IOC bucketing ────────────────────────────────────────────────────────────
def test_iocs_by_type_buckets_and_dedupes():
    enrichment = _triage_enrichment()
    enrichment["triage"].append({"query": {"ioc": "140.82.121.3", "type": "ipv4"}})  # dup
    out = prefetch._iocs_by_type(enrichment)
    assert out["hash"] == ["abc123sha"]
    assert out["domain"] == ["release-assets.githubusercontent.com"]
    assert out["ip"] == ["140.82.121.3"]  # deduped


def test_iocs_by_type_caps_per_type():
    rows = [{"query": {"ioc": f"1.1.1.{i}", "type": "ipv4"}} for i in range(20)]
    out = prefetch._iocs_by_type({"triage": rows})
    assert len(out["ip"]) == prefetch._MAX_PER_TYPE


# ── Gates ────────────────────────────────────────────────────────────────────
async def test_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", False)
    inc = _Inc(_triage_enrichment())
    assert await prefetch.prefetch_ms_enrichment(inc) is None
    assert "ms" not in inc.enrichment


async def test_no_creds_returns_none(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch, creds=None)
    inc = _Inc(_triage_enrichment())
    assert await prefetch.prefetch_ms_enrichment(inc) is None
    assert "ms" not in inc.enrichment


async def test_no_entities_returns_none(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch)
    inc = _Inc({"triage": [{"query": {"ioc": "bob@acme.com", "type": "email"}}]})
    assert await prefetch.prefetch_ms_enrichment(inc) is None


# ── Reputation slice (PR-1) ──────────────────────────────────────────────────
async def test_populates_reputation(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch)
    _patch_reads(monkeypatch)
    inc = _Inc(_triage_enrichment())

    ms = await prefetch.prefetch_ms_enrichment(inc)
    rep = ms["reputation"]

    assert rep is inc.enrichment["ms"]["reputation"]
    assert [f["value"] for f in rep["files"]] == ["abc123sha"]
    assert rep["files"][0]["info"]["determinationValue"] == "Clean"
    assert rep["files"][0]["stats"]["organizationPrevalence"] == 42
    assert rep["files"][0]["custom_indicator"]["matches"] == [{"action": "Allowed"}]
    assert rep["domains"][0]["stats"]["organizationPrevalence"] == 5000
    assert [i["value"] for i in rep["ips"]] == ["140.82.121.3"]


async def test_failsoft_one_read_raises(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch)
    _patch_reads(monkeypatch, get_file_stats=RuntimeError("403 forbidden"))
    inc = _Inc(_triage_enrichment())

    rep = (await prefetch.prefetch_ms_enrichment(inc))["reputation"]

    file_rec = rep["files"][0]
    assert "stats" not in file_rec  # the failing read is dropped
    assert file_rec["info"]["determinationValue"] == "Clean"  # the others survive
    assert "stats" in file_rec["errors"]
    assert rep["domains"] and rep["ips"]  # the batch is not sunk


async def test_slims_oversized_strings(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch)
    big = "x" * (prefetch._STR_TRUNC + 50)
    _patch_reads(monkeypatch, get_domain_stats={"note": big})
    inc = _Inc({"triage": [{"query": {"ioc": "d.com", "type": "domain"}}]})

    rep = (await prefetch.prefetch_ms_enrichment(inc))["reputation"]
    note = rep["domains"][0]["stats"]["note"]
    assert len(note) <= prefetch._STR_TRUNC + 1  # truncated (+ the ellipsis char)


# ── Endpoint slice (PR-2) ────────────────────────────────────────────────────
async def test_endpoint_defender(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds_by_provider(monkeypatch, microsoft_defender=_CREDS)
    monkeypatch.setattr(prefetch.ocsf_defender, "mde_device_id", lambda raw: "dev123")
    monkeypatch.setattr(prefetch.ocsf_defender, "entra_user_id", lambda raw: None)
    monkeypatch.setattr(
        prefetch.defender_adapter,
        "get_machine",
        _async(
            {
                "computerDnsName": "PC1",
                "osPlatform": "Windows10",
                "version": "10.0.19045",
                "riskScore": "High",
                "exposureLevel": "Medium",
                "deviceValue": "High",
                "healthStatus": "Active",
                "lastSeen": "2026-07-01",
                "lastIpAddress": "10.0.0.5",
            }
        ),
    )
    inc = _Inc({}, normalized={"source_product": "microsoft_defender", "raw": {}})

    ep = (await prefetch.prefetch_ms_enrichment(inc))["endpoint"]
    assert ep["provider"] == "microsoft_defender"
    assert ep["hostname"] == "PC1"
    assert ep["risk_score"] == "High"
    assert ep["device_value"] == "High"
    assert ep["os_version"] == "10.0.19045"  # Defender `version`, not osVersion


async def test_endpoint_vision_one_has_no_criticality(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds_by_provider(monkeypatch, vision_one=_CREDS)
    monkeypatch.setattr(
        prefetch.v1_adapter,
        "get_endpoint_details",
        _async(
            [
                {
                    "endpointName": "SRV1",
                    "agentGuid": "g1",
                    "os": {"name": "Windows Server"},
                    "lastUsedIp": "10.0.0.9",
                    "isolationStatus": "notIsolated",
                    "eppAgent": {"status": "on"},
                    "edrSensor": {"connectivity": "online"},
                }
            ]
        ),
    )
    inc = _Inc({}, normalized={"source_product": "visionone", "hostname": "SRV1"})

    ep = (await prefetch.prefetch_ms_enrichment(inc))["endpoint"]
    assert ep["provider"] == "vision_one"
    assert ep["hostname"] == "SRV1"
    assert ep["epp_status"] == "on"
    assert ep["criticality"] is None  # V1 eiqs/endpoints exposes no device risk score


# ── Identity slice (PR-3) ────────────────────────────────────────────────────
async def test_identity_cross_provider(monkeypatch):
    # A non-Defender incident still gets Entra identity via the Defender app's Graph creds.
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds_by_provider(monkeypatch, microsoft_defender=_CREDS)
    gia = prefetch.graph_identity_adapter
    monkeypatch.setattr(
        gia,
        "get_user_profile",
        _async(
            {
                "id": "guid-1",
                "userPrincipalName": "bob@acme.com",
                "displayName": "Bob",
                "department": "Engineering",
                "accountEnabled": True,
                "manager": {"userPrincipalName": "george@acme.com"},
            }
        ),
    )
    monkeypatch.setattr(gia, "get_risky_user", _async({"riskLevel": "none", "riskState": "none"}))
    monkeypatch.setattr(
        gia,
        "get_risk_detections",
        _async({"detections": [{"riskEventType": "unfamiliarFeatures"}]}),
    )
    monkeypatch.setattr(
        gia,
        "get_registration_details",
        _async(
            {"methodsRegistered": ["microsoftAuthenticatorPush", "email"], "isMfaCapable": True}
        ),
    )
    monkeypatch.setattr(
        gia,
        "get_sign_ins",
        _async(
            {
                "sign_ins": [
                    {
                        "ipAddress": "1.2.3.4",
                        "location": {"city": "Zurich", "countryOrRegion": "CH"},
                    }
                ]
            }
        ),
    )
    inc = _Inc({}, normalized={"source_product": "crowdstrike", "username": "bob@acme.com"})

    idn = (await prefetch.prefetch_ms_enrichment(inc))["identity"]
    assert idn["user"] == "bob@acme.com"
    assert idn["profile"]["department"] == "Engineering"
    assert idn["profile"]["manager"]["userPrincipalName"] == "george@acme.com"
    assert idn["risk"]["riskLevel"] == "none"
    assert len(idn["mfa"]["methodsRegistered"]) == 2
    assert idn["risk_detections"][0]["riskEventType"] == "unfamiliarFeatures"
    assert idn["sign_ins"][0]["location"]["city"] == "Zurich"


def test_resolve_user_requires_upn_like():
    assert prefetch._resolve_user({"username": "bob@acme.com"}) == "bob@acme.com"
    assert prefetch._resolve_user({"username": "plainname"}) is None
    assert prefetch._resolve_user({}) is None


# ── Adapter reads ────────────────────────────────────────────────────────────
async def test_check_custom_indicator_unwraps_value(monkeypatch):
    captured = {}

    async def _fake_mde_get(path, *, tenant_id, client_id, client_secret, params=None):
        captured["path"] = path
        captured["params"] = params
        return {"value": [{"action": "Block", "indicatorValue": "x"}]}

    monkeypatch.setattr(defender_adapter, "_mde_get", _fake_mde_get)
    out = await defender_adapter.check_custom_indicator(
        "1.2.3.4", tenant_id="t", client_id="c", client_secret="s"
    )
    assert out == {"matches": [{"action": "Block", "indicatorValue": "x"}]}
    assert captured["path"] == "indicators"
    assert captured["params"] == {"$filter": "indicatorValue eq '1.2.3.4'"}


async def test_domain_stats_path(monkeypatch):
    captured = {}

    async def _fake_mde_get(path, *, tenant_id, client_id, client_secret, params=None):
        captured["path"] = path
        return {"organizationPrevalence": 1}

    monkeypatch.setattr(defender_adapter, "_mde_get", _fake_mde_get)
    await defender_adapter.get_domain_stats(
        "evil.test", tenant_id="t", client_id="c", client_secret="s"
    )
    assert captured["path"] == "domains/evil.test/stats"


# ── Briefing sections ────────────────────────────────────────────────────────
def _render(**kw):
    base = dict(
        normalized={},
        autoclose_pre=None,
        autoclose_post=None,
        exact_match=None,
        n_way=None,
        similar=[],
        kb_hits=[],
        triage_results=[],
        ip_enrichments=[],
    )
    base.update(kw)
    return briefing.render(**base)


def test_briefing_renders_ms_reputation():
    rep = {
        "files": [
            {
                "value": "abc",
                "info": {
                    "determinationValue": "Clean",
                    "signer": "Contoso",
                    "isValidCertificate": True,
                },
                "stats": {"organizationPrevalence": 42},
                "custom_indicator": {"matches": [{"action": "Allowed"}]},
            }
        ],
        "domains": [
            {
                "value": "cdn.example",
                "stats": {"organizationPrevalence": 5000},
                "custom_indicator": {"matches": []},
            }
        ],
        "ips": [
            {"value": "1.2.3.4", "stats": {"organizationPrevalence": 3}, "custom_indicator": {}}
        ],
    }
    out = _render(ms_reputation=rep)
    assert "## Microsoft Defender reputation" in out
    assert "`abc`" in out
    assert "determination=Clean" in out
    assert "custom-list=Allowed" in out
    assert "org_prevalence=5000" in out


def test_briefing_renders_endpoint_and_identity():
    out = _render(
        ms_endpoint={
            "provider": "microsoft_defender",
            "hostname": "PC1",
            "os": "Windows10",
            "os_version": "10.0",
            "risk_score": "High",
            "exposure_level": "Medium",
            "device_value": "High",
            "health": "Active",
            "last_seen": "2026-07-01",
            "last_ip": "10.0.0.5",
        },
        ms_identity={
            "user": "bob@acme.com",
            "profile": {
                "userPrincipalName": "bob@acme.com",
                "displayName": "Bob",
                "department": "Engineering",
                "accountEnabled": True,
                "manager": {"userPrincipalName": "george@acme.com"},
            },
            "risk": {"riskLevel": "none", "riskState": "none"},
            "mfa": {"methodsRegistered": ["a", "b"], "isMfaCapable": True, "isAdmin": False},
            "risk_detections": [{"riskEventType": "unfamiliarFeatures"}],
            "sign_ins": [
                {"ipAddress": "1.2.3.4", "location": {"city": "Zurich", "countryOrRegion": "CH"}}
            ],
        },
    )
    assert "## Endpoint" in out
    assert "risk_score=High" in out and "device_value=High" in out
    assert "## Identity (Entra)" in out
    assert "Engineering" in out and "george@acme.com" in out
    assert "registered=2" in out
    assert "unfamiliarFeatures" in out
    assert "Zurich" in out


def test_briefing_omits_sections_when_empty():
    out = _render(ms_reputation={"files": [], "domains": [], "ips": []})
    assert "Microsoft Defender reputation" not in out
    assert "## Endpoint" not in out
    assert "## Identity" not in out
