"""Unit tests for RBAC pure logic — resolver + route builders."""

from __future__ import annotations

import uuid

from isoc_api.auth import permissions as perms
from isoc_api.db.enums import Role
from isoc_api.routes import rbac


# ── resolver (the load-bearing dual-path bridge) ───────────────────────────
def test_no_db_roles_falls_back_to_static_per_role():
    assert perms.effective_permissions(Role.VIEWER, set()) == perms.STATIC_FALLBACK[Role.VIEWER]
    assert perms.effective_permissions(Role.ANALYST, set()) == perms.STATIC_FALLBACK[Role.ANALYST]


def test_admin_is_wildcard():
    eff = perms.effective_permissions(Role.ADMIN, set())
    assert eff == {"*"}
    assert perms.has_permission(eff, "roles:read") is True
    assert perms.has_permission(eff, "anything:at:all") is True


def test_db_perms_union_never_demotes():
    # A viewer granted an extra perm via a DB role keeps all read perms + the extra.
    eff = perms.effective_permissions(Role.VIEWER, {"incidents:write"})
    assert "incidents:write" in eff
    assert perms.STATIC_FALLBACK[Role.VIEWER] <= eff  # static perms never lost


def test_regression_roles_perms_present_in_catalogue_and_admin():
    # AiSOC's exact bug: roles:* was DB-only and missing from the static map.
    names = {n for n, _, _ in perms.CATALOGUE}
    assert {"roles:read", "roles:write"} <= names
    # admin (wildcard) authorizes them
    assert perms.has_permission(perms.effective_permissions(Role.ADMIN, set()), "roles:write")


def test_catalogue_has_no_duplicates():
    names = [n for n, _, _ in perms.CATALOGUE]
    assert len(names) == len(set(names))


# ── route builders ─────────────────────────────────────────────────────────
def test_validate_role_mutation_rejects_system():
    assert rbac.validate_role_mutation(True, [], set()) == "system roles are read-only"


def test_validate_role_mutation_rejects_unknown_perm_ids():
    known = {"p1", "p2"}
    err = rbac.validate_role_mutation(False, ["p1", "pX"], known)
    assert err and "pX" in err
    assert rbac.validate_role_mutation(False, ["p1", "p2"], known) is None


def test_build_role_view_shapes_role():
    rid = uuid.uuid4()
    view = rbac.build_role_view(
        {"id": rid, "tenant_id": None, "name": "soc", "description": "d", "is_system": False},
        ["incidents:read", "cases:read"],
    )
    assert view["id"] == str(rid)
    assert view["permission_count"] == 2
    assert view["permissions"] == ["cases:read", "incidents:read"]  # sorted
    assert view["is_system"] is False


def test_build_permission_matrix_groups_by_category_stable():
    out = rbac.build_permission_matrix(
        [
            {"id": uuid.uuid4(), "name": "incidents:write", "category": "incidents"},
            {"id": uuid.uuid4(), "name": "incidents:read", "category": "incidents"},
            {"id": uuid.uuid4(), "name": "audit:read", "category": "audit"},
        ]
    )
    assert set(out) == {"incidents", "audit"}
    # within a category, sorted by name
    assert [p["name"] for p in out["incidents"]] == ["incidents:read", "incidents:write"]


def test_static_fallback_analyst_can_approve_not_manage_users():
    a = perms.STATIC_FALLBACK[Role.ANALYST]
    assert "incidents:approve" in a
    assert "users:write" not in a
    assert "roles:write" not in a
