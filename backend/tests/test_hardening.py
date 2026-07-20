"""Unit tests for Stage 3a security hardening — weak-secret audit + headers.

Pure: constructs `Settings` hermetically (`_env_file=None` + explicit secrets so
a developer's exported env can't perturb the result) and exercises the pure
`secret_findings` / `assert_secrets_hardened` logic. No DB/stack needed.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from isoc_api import hardening
from isoc_api.settings import Settings

_STRONG_JWT = "0" * 64  # 64 chars, not a known dev default → strong


def _settings(**over) -> Settings:
    """A hermetic Settings with all-strong secrets, overridable per test."""
    base = dict(
        _env_file=None,
        jwt_secret=SecretStr(_STRONG_JWT),
        litellm_master_key=SecretStr("sk-" + "m" * 40),
        ingest_hmac_secret=SecretStr("b" * 32),
        settings_encryption_key=SecretStr("fernet-key-placeholder"),
        isoc_bootstrap_admin_password=SecretStr("strong-admin-pw-123"),
        isoc_env="dev",
    )
    base.update(over)
    return Settings(**base)


class _StubLog:
    """Captures structlog-style warning calls."""

    def __init__(self) -> None:
        self.warnings: list[tuple[str, dict]] = []

    def warning(self, event: str, **kw) -> None:
        self.warnings.append((event, kw))


# ── secret_findings (pure audit) ───────────────────────────────────────────
def test_strong_secrets_yield_no_findings():
    assert hardening.secret_findings(_settings()) == []


def test_weak_default_jwt_is_fatal():
    findings = hardening.secret_findings(_settings(jwt_secret=SecretStr("change-me-dev-only")))
    assert any(f.severity == "fatal" and f.key == "JWT_SECRET" for f in findings)


def test_short_jwt_is_fatal():
    findings = hardening.secret_findings(_settings(jwt_secret=SecretStr("tooshort")))
    assert any(f.severity == "fatal" and f.key == "JWT_SECRET" for f in findings)


def test_boundary_jwt_length_is_ok():
    # Exactly 32 chars (and not a known default) is acceptable — no finding.
    assert hardening.secret_findings(_settings(jwt_secret=SecretStr("c" * 32))) == []


def test_long_placeholder_jwt_is_fatal():
    # The 33-char ".env.example" placeholder is long enough to pass the length
    # floor but must still be caught by the "change-me" substring marker.
    findings = hardening.secret_findings(
        _settings(jwt_secret=SecretStr("change-me-very-long-random-string"))
    )
    assert any(f.severity == "fatal" and f.key == "JWT_SECRET" for f in findings)


def test_weak_litellm_master_key_is_fatal():
    findings = hardening.secret_findings(
        _settings(litellm_master_key=SecretStr("CHANGE-ME-litellm-master-key"))
    )
    assert any(f.severity == "fatal" and f.key == "LITELLM_MASTER_KEY" for f in findings)


def test_dev_default_litellm_master_key_is_fatal():
    findings = hardening.secret_findings(_settings(litellm_master_key=SecretStr("sk-dev-only")))
    assert any(f.severity == "fatal" and f.key == "LITELLM_MASTER_KEY" for f in findings)


def test_default_hmac_is_warn_not_fatal():
    findings = hardening.secret_findings(
        _settings(ingest_hmac_secret=SecretStr("change-me-32-char-random"))
    )
    assert any(f.severity == "warn" and f.key == "INGEST_HMAC_SECRET" for f in findings)
    assert not any(f.severity == "fatal" for f in findings)


def test_missing_encryption_key_is_warn():
    findings = hardening.secret_findings(_settings(settings_encryption_key=None))
    assert any(f.key == "SETTINGS_ENCRYPTION_KEY" and f.severity == "warn" for f in findings)


def test_default_admin_password_is_warn():
    findings = hardening.secret_findings(
        _settings(isoc_bootstrap_admin_password=SecretStr("change-me"))
    )
    assert any(f.key == "ISOC_BOOTSTRAP_ADMIN_PASSWORD" and f.severity == "warn" for f in findings)


# ── is_production mapping ───────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["prod", "production", "staging", " PROD ", "Production"])
def test_production_like_values(value):
    assert _settings(isoc_env=value).is_production is True


@pytest.mark.parametrize("value", ["dev", "development", "local", "", "whatever"])
def test_non_production_values(value):
    assert _settings(isoc_env=value).is_production is False


# ── assert_secrets_hardened (fail-closed only in prod) ──────────────────────
def test_prod_weak_jwt_aborts_boot():
    s = _settings(isoc_env="prod", jwt_secret=SecretStr("change-me-dev-only"))
    with pytest.raises(RuntimeError, match="Refusing to boot"):
        hardening.assert_secrets_hardened(s, _StubLog())


def test_dev_weak_jwt_does_not_abort_but_warns():
    s = _settings(isoc_env="dev", jwt_secret=SecretStr("change-me-dev-only"))
    log = _StubLog()
    hardening.assert_secrets_hardened(s, log)  # must NOT raise
    assert any(ev == "security.weak_secret_dev" for ev, _ in log.warnings)


def test_prod_strong_secrets_boot_clean():
    log = _StubLog()
    hardening.assert_secrets_hardened(_settings(isoc_env="prod"), log)  # no raise
    assert log.warnings == []


def test_prod_warn_only_finding_does_not_abort():
    # A warn-severity issue (missing encryption key) in prod logs but never blocks.
    s = _settings(isoc_env="prod", settings_encryption_key=None)
    log = _StubLog()
    hardening.assert_secrets_hardened(s, log)  # no raise
    assert any(ev == "security.weak_secret" for ev, _ in log.warnings)


# ── security headers ────────────────────────────────────────────────────────
def test_security_headers_cover_the_essentials():
    h = hardening.SECURITY_HEADERS
    for key in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Permissions-Policy",
    ):
        assert key in h
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
