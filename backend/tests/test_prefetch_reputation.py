"""Unit tests for ADR-0009 PR-1: pre-L2 Microsoft reputation enrichment.

Pure/mock-only, no stack needed. Covers the IOC bucketing, the fail-soft
concurrent fetch, the flag/creds gates, the new adapter reads, and the briefing
section.
"""

from types import SimpleNamespace

from isoc_api.adapters import defender_adapter
from isoc_api.pipeline import briefing, prefetch

_CREDS = SimpleNamespace(oauth_tenant_id="t", client_id="c", client_secret="s")


class _Inc:
    def __init__(self, enrichment=None, customer="acme"):
        self.id = "inc-1"
        self.customer = customer
        self.enrichment = enrichment if enrichment is not None else {}
        self.normalized = {}


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


async def test_no_iocs_returns_none(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch)
    inc = _Inc({"triage": [{"query": {"ioc": "bob@acme.com", "type": "email"}}]})
    assert await prefetch.prefetch_ms_enrichment(inc) is None


# ── Happy path ───────────────────────────────────────────────────────────────
async def test_populates_reputation(monkeypatch):
    monkeypatch.setattr(prefetch.settings, "ms_autoenrich_enabled", True)
    _patch_creds(monkeypatch)
    _patch_reads(monkeypatch)
    inc = _Inc(_triage_enrichment())

    rep = await prefetch.prefetch_ms_enrichment(inc)

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

    rep = await prefetch.prefetch_ms_enrichment(inc)

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

    rep = await prefetch.prefetch_ms_enrichment(inc)
    note = rep["domains"][0]["stats"]["note"]
    assert len(note) <= prefetch._STR_TRUNC + 1  # truncated (+ the ellipsis char)


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


# ── Briefing section ─────────────────────────────────────────────────────────
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
                "stats": {"organizationPrevalence": 5000, "orgFirstSeen": "2020-01-01"},
                "custom_indicator": {"matches": []},
            }
        ],
        "ips": [
            {"value": "1.2.3.4", "stats": {"organizationPrevalence": 3}, "custom_indicator": {}}
        ],
    }
    out = briefing.render(
        normalized={},
        autoclose_pre=None,
        autoclose_post=None,
        exact_match=None,
        n_way=None,
        similar=[],
        kb_hits=[],
        triage_results=[],
        ip_enrichments=[],
        ms_reputation=rep,
    )
    assert "## Microsoft Defender reputation" in out
    assert "`abc`" in out
    assert "determination=Clean" in out
    assert "custom-list=Allowed" in out
    assert "org_prevalence=5000" in out


def test_briefing_omits_section_when_empty():
    out = briefing.render(
        normalized={},
        autoclose_pre=None,
        autoclose_post=None,
        exact_match=None,
        n_way=None,
        similar=[],
        kb_hits=[],
        triage_results=[],
        ip_enrichments=[],
        ms_reputation={"files": [], "domains": [], "ips": []},
    )
    assert "Microsoft Defender reputation" not in out
