"""Unit tests for the pure correlation guard (pipeline/correlation.py).

Pure function — no stack. Pins ``is_strong_entity``: file/user/device are
always strong; the weak/high-fan-out types (network_endpoint, and observable
ip/hostname/mac/process/filename) NEVER form an edge; the strong observables
(username/email/url/hash/cve) do. This is the over-correlation guard — a
regression here silently fuses unrelated incidents, so it is pinned tightly.
"""

from __future__ import annotations

import pytest

from isoc_api.pipeline.correlation import (
    STRONG_ENTITY_TYPES,
    STRONG_OBSERVABLE_TYPE_IDS,
    is_strong_entity,
)


# ── strong entity types (no attributes needed) ──────────────────────────
@pytest.mark.parametrize("etype", ["file", "user", "device"])
def test_strong_entity_types_are_strong(etype: str) -> None:
    assert is_strong_entity(etype, None) is True
    assert is_strong_entity(etype, {}) is True
    # attributes are irrelevant for these types.
    assert is_strong_entity(etype, {"type_id": 2}) is True


def test_strong_entity_types_constant() -> None:
    assert STRONG_ENTITY_TYPES == {"file", "user", "device"}


# ── network_endpoint is NEVER strong ────────────────────────────────────
def test_network_endpoint_not_strong() -> None:
    assert is_strong_entity("network_endpoint", None) is False
    assert is_strong_entity("network_endpoint", {"ip": "1.2.3.4"}) is False


# ── strong observables: username(4)/email(5)/url(6)/hash(8)/cve(10) ─────
@pytest.mark.parametrize("type_id", [4, 5, 6, 8, 10])
def test_strong_observables(type_id: int) -> None:
    assert is_strong_entity("observable", {"type_id": type_id}) is True


def test_strong_observable_ids_constant() -> None:
    assert STRONG_OBSERVABLE_TYPE_IDS == {4, 5, 6, 8, 10}


# ── weak observables: hostname(1)/ip(2)/mac(3)/filename(7)/process(9) ────
@pytest.mark.parametrize("type_id", [1, 2, 3, 7, 9])
def test_weak_observables_not_strong(type_id: int) -> None:
    assert is_strong_entity("observable", {"type_id": type_id}) is False


def test_ip_observable_not_strong() -> None:
    # explicit named case: an IP observable must never correlate.
    assert is_strong_entity("observable", {"type_id": 2}) is False


def test_hostname_observable_not_strong() -> None:
    assert is_strong_entity("observable", {"type_id": 1}) is False


# ── observable edge cases: missing/None/absent type_id ──────────────────
def test_observable_missing_type_id_not_strong() -> None:
    assert is_strong_entity("observable", None) is False
    assert is_strong_entity("observable", {}) is False
    assert is_strong_entity("observable", {"value": "x"}) is False
    assert is_strong_entity("observable", {"type_id": None}) is False


# ── unknown entity type -> not strong (never raises) ────────────────────
def test_unknown_entity_type_not_strong() -> None:
    assert is_strong_entity("mystery", {"type_id": 8}) is False
    assert is_strong_entity("", None) is False


# ── schema guard: no duplicate indexes on the cluster tables ────────────────
# A column-level index=True AND an explicit Index() with the same auto-name emit
# CREATE INDEX twice, which crashes Base.metadata.create_all on a fresh DB.
def test_incident_cluster_indexes_have_no_duplicates() -> None:
    from isoc_api.db.models import IncidentCluster

    names = [ix.name for ix in IncidentCluster.__table__.indexes]
    assert len(names) == len(set(names)), f"duplicate index names: {names}"
    assert set(names) == {
        "ix_incident_clusters_tenant_id",
        "ix_incident_clusters_cluster_key",
        "ix_incident_clusters_created_at",
    }
