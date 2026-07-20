"""Unit tests for Stage 3b/3c — TOTP helpers + JWT claims/revocation logic.

Pure: exercises `auth.mfa` (pyotp wrappers) and `auth.security` (token minting +
the access/version checks used by current_user) without a DB or the stack. The
route-level flow (login → challenge → /login/mfa, logout revocation) is DB-bound
and left to live verification.
"""

from __future__ import annotations

import uuid

import pyotp

from isoc_api.auth import mfa, security

# ── TOTP helpers (auth/mfa.py) ──────────────────────────────────────────────


def test_generate_secret_is_usable_base32():
    secret = mfa.generate_secret()
    assert len(secret) >= 16
    # A freshly generated secret verifies its own current code.
    assert mfa.verify_code(secret, pyotp.TOTP(secret).now()) is True


def test_verify_code_rejects_wrong_code():
    secret = mfa.generate_secret()
    now = pyotp.TOTP(secret).now()
    wrong = "000000" if now != "000000" else "111111"
    assert mfa.verify_code(secret, wrong) is False


def test_verify_code_tolerates_spaces():
    secret = mfa.generate_secret()
    code = pyotp.TOTP(secret).now()
    spaced = f"{code[:3]} {code[3:]}"
    assert mfa.verify_code(secret, spaced) is True


def test_verify_code_rejects_empty_or_nondigit():
    secret = mfa.generate_secret()
    assert mfa.verify_code(secret, "") is False
    assert mfa.verify_code(secret, "abcdef") is False
    assert mfa.verify_code("", "123456") is False


def test_provisioning_uri_shape():
    secret = mfa.generate_secret()
    uri = mfa.provisioning_uri(secret, "analyst@eksir.io")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=EKSIR" in uri
    assert f"secret={secret}" in uri
    assert "analyst%40eksir.io" in uri  # email is URL-encoded


def test_qr_data_uri_is_inline_svg():
    uri = mfa.provisioning_uri(mfa.generate_secret(), "analyst@eksir.io")
    data_uri = mfa.qr_data_uri(uri)
    # Inline (no external host) SVG data URI — safe under a strict img-src CSP.
    assert data_uri.startswith("data:image/svg+xml")
    assert "http://" not in data_uri and "https://" not in data_uri


# ── Access-token claims (auth/security.py) ──────────────────────────────────


def test_issue_token_embeds_ver_jti_purpose():
    uid = uuid.uuid4()
    payload = security.decode_token(security.issue_token(uid, "analyst", 7))
    assert payload["sub"] == str(uid)
    assert payload["role"] == "analyst"
    assert payload["purpose"] == "access"
    assert payload["ver"] == 7
    assert len(payload["jti"]) == 32
    assert payload["iss"] == "isoc"


def test_issue_token_defaults_ver_zero():
    payload = security.decode_token(security.issue_token(uuid.uuid4(), "viewer"))
    assert payload["ver"] == 0


def test_jti_is_unique_per_token():
    uid = uuid.uuid4()
    a = security.decode_token(security.issue_token(uid, "analyst", 0))
    b = security.decode_token(security.issue_token(uid, "analyst", 0))
    assert a["jti"] != b["jti"]


def test_mfa_challenge_is_not_an_access_token():
    uid = uuid.uuid4()
    payload = security.decode_token(security.issue_mfa_challenge(uid))
    assert payload["purpose"] == "mfa"
    assert payload["sub"] == str(uid)
    assert security.is_access_token(payload) is False


def test_access_token_is_accepted_as_access():
    payload = security.decode_token(security.issue_token(uuid.uuid4(), "analyst", 0))
    assert security.is_access_token(payload) is True


# ── Revocation check (token_version_ok) ─────────────────────────────────────


def test_token_version_match_and_mismatch():
    assert security.token_version_ok({"ver": 3}, 3) is True
    assert security.token_version_ok({"ver": 3}, 4) is False  # user bumped → revoked


def test_missing_ver_counts_as_zero():
    # A pre-feature token (no `ver`) is valid against the default column value 0.
    assert security.token_version_ok({}, 0) is True
    assert security.token_version_ok({}, 1) is False


def test_malformed_ver_fails_closed():
    assert security.token_version_ok({"ver": "nope"}, 0) is False
