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


# ── L1/L2 critical-action gating ────────────────────────────────────────────
def test_bare_analyst_l1_lacks_every_critical_action_perm():
    # L1 = a bare analyst (no assigned RBAC role). The additive model means L1 is
    # denied criticals ONLY because the actions:* perms are kept out of the
    # analyst fallback. If any leak in, every analyst silently becomes L2.
    l1 = perms.effective_permissions(Role.ANALYST, set())
    for p in perms._L2_ACTION_PERMS:
        assert not perms.has_permission(l1, p), f"L1 must not have {p}"
    # Viewer must lack them too.
    viewer = perms.effective_permissions(Role.VIEWER, set())
    for p in perms._L2_ACTION_PERMS:
        assert not perms.has_permission(viewer, p)


def test_l2_role_grants_criticals_admin_wildcard():
    # L2 = analyst + the seeded L2 action perms (union).
    l2 = perms.effective_permissions(Role.ANALYST, set(perms._L2_ACTION_PERMS))
    for p in perms._L2_ACTION_PERMS:
        assert perms.has_permission(l2, p)
    # ...but L2 is not admin.
    assert not perms.has_permission(l2, "users:write")
    assert not perms.has_permission(l2, "roles:write")
    # Admin (wildcard) has everything.
    admin = perms.effective_permissions(Role.ADMIN, set())
    for p in perms._L2_ACTION_PERMS:
        assert perms.has_permission(admin, p)


def test_missing_action_permissions():
    # L1: checking a critical kind flags the missing perm.
    l1 = perms.effective_permissions(Role.ANALYST, set())
    assert perms.missing_action_permissions({"isolate_host"}, l1) == {"actions:isolate"}
    # A read-only / non-critical kind needs no perm.
    assert perms.missing_action_permissions({"tag", "create_case"}, l1) == set()
    # L2: nothing missing for its granted kinds.
    l2 = perms.effective_permissions(Role.ANALYST, set(perms._L2_ACTION_PERMS))
    assert perms.missing_action_permissions(set(perms.CRITICAL_KINDS), l2) == set()
    # Admin (wildcard): never missing anything.
    assert perms.missing_action_permissions(set(perms.CRITICAL_KINDS), {perms.WILDCARD}) == set()


def test_critical_action_map_uses_exact_dispatch_kind_strings():
    # A typo here silently un-gates a critical action, so pin the exact kinds.
    assert set(perms.CRITICAL_ACTION_PERMISSION) == {
        "isolate_host",
        "disable_user",
        "blocklist_ioc",
        "scan_endpoint",
        "collect_file",
    }


def test_l2_analyst_seeded_role_present():
    assert "L2 Analyst" in perms.EXTRA_SYSTEM_ROLES
    _desc, l2perms = perms.EXTRA_SYSTEM_ROLES["L2 Analyst"]
    assert l2perms == set(perms._L2_ACTION_PERMS)
    # Every seeded perm must exist in the catalogue (else the seeder no-ops it).
    assert l2perms <= perms.ALL_PERMS


# ── Structural: EVERY critical action route must be permission-gated ─────────
# Regression guard for the bypass class where a parallel route (v1ops/defenderops)
# runs a critical EDR action while still gated only by current_user (any user).
def _walk_deps(dep, out: list[str]) -> None:
    if dep.call is not None:
        out.append(getattr(dep.call, "__qualname__", getattr(dep.call, "__name__", "")))
    for sub in dep.dependencies:
        _walk_deps(sub, out)


def _dep_qualnames(router, path: str, method: str = "POST") -> list[str] | None:
    for r in router.routes:
        if getattr(r, "path", None) == path and method in getattr(r, "methods", set()):
            names: list[str] = []
            for d in r.dependant.dependencies:
                _walk_deps(d, names)
            return names
    return None


def test_all_critical_action_routes_are_permission_gated():
    from isoc_api.routes import defenderactions, defenderops, v1actions, v1ops

    critical = [
        (v1ops.router, "/isolate"),
        (v1ops.router, "/restore"),
        (v1ops.router, "/blocklist"),
        (v1ops.router, "/collect"),
        (defenderops.router, "/isolate"),
        (defenderops.router, "/unisolate"),
        (defenderops.router, "/scan"),
        (defenderops.router, "/blocklist"),
        (defenderops.router, "/disable-user"),
        (defenderops.router, "/enable-user"),
        (v1actions.router, "/{incident_id}/isolate"),
        (v1actions.router, "/{incident_id}/restore"),
        (v1actions.router, "/{incident_id}/blocklist"),
        (v1actions.router, "/{incident_id}/collect"),
        (defenderactions.router, "/{incident_id}/isolate"),
        (defenderactions.router, "/{incident_id}/unisolate"),
        (defenderactions.router, "/{incident_id}/scan"),
        (defenderactions.router, "/{incident_id}/blocklist"),
        (defenderactions.router, "/{incident_id}/disable-user"),
        (defenderactions.router, "/{incident_id}/enable-user"),
    ]
    for router, path in critical:
        names = _dep_qualnames(router, path)
        assert names is not None, f"critical route not found: {path}"
        assert any("require_permission" in n for n in names), (
            f"critical route {path} is NOT permission-gated (deps: {names})"
        )
