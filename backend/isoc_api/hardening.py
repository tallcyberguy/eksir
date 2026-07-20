"""Product-security hardening: fail-closed secret checks + security headers.

Stage 3a of the security-hardening feature (see docs/BUILD-PLAN.md). Two jobs,
both import-safe and side-effect free so they can be unit-tested without the
stack:

  • `secret_findings(settings)` — pure audit of the configured secrets. Returns
    the weak ones with a severity. `assert_secrets_hardened(...)` turns a "fatal"
    finding into a boot abort, but ONLY when `settings.is_production` — so a local
    or test boot (isoc_env="dev") never trips it, it only warns.
  • `SECURITY_HEADERS` — the response headers applied by the FastAPI middleware
    in main.py (defence-in-depth; the edge Caddyfile sets the same set on the
    frontend + proxied API).

Why a startup check and not a pydantic validator: the pure unit tests import
`isoc_api.*` and construct `Settings()` with the in-code defaults (which include
the weak `change-me-dev-only` JWT secret). A constructor-time raise would break
every test and every dev boot. Checking at app startup keeps import cheap and
lets the guard key off `is_production`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, NamedTuple

if TYPE_CHECKING:  # avoid a runtime import cycle; only needed for type hints
    from .settings import Settings

# Known dev/scaffold defaults shipped in-code and in .env.example. Any secret
# still set to one of these in production is effectively public.
WEAK_SECRETS: frozenset[str] = frozenset(
    {
        "change-me-dev-only",
        "change-me",
        "changeme",
        "change-me-32-char-random",
        "CHANGE-ME-generate-with-openssl-rand-hex-64",
        "sk-dev-only",
    }
)

# Substrings that mark a value as an unedited placeholder regardless of length.
# This closes the gap where a long-but-obvious placeholder (e.g. the 33-char
# "change-me-very-long-random-string" shipped in an .env.example, or
# "CHANGE-ME-litellm-master-key") slipped past the length floor.
_WEAK_MARKERS: tuple[str, ...] = ("change-me", "changeme", "your-", "example-secret")

# Minimum acceptable length for a high-entropy secret (32 hex chars ≈ 128 bits).
_MIN_JWT_LEN = 32
_MIN_HMAC_LEN = 16
_MIN_KEY_LEN = 16  # LiteLLM master key / proxy keys

Severity = Literal["fatal", "warn"]


class SecretFinding(NamedTuple):
    severity: Severity
    key: str  # the env var name, for the operator's benefit
    message: str


def _is_weak(value: str, min_len: int) -> bool:
    lowered = value.lower()
    return (
        value in WEAK_SECRETS
        or len(value) < min_len
        or any(marker in lowered for marker in _WEAK_MARKERS)
    )


def secret_findings(s: Settings) -> list[SecretFinding]:
    """Audit the configured secrets. Pure — no logging, no raising.

    `fatal` findings abort boot in production (auth-critical). `warn` findings
    are always advisory (defence-in-depth defaults an operator should still fix
    but that don't, on their own, break the auth boundary).
    """
    out: list[SecretFinding] = []

    jwt = s.jwt_secret.get_secret_value()
    if _is_weak(jwt, _MIN_JWT_LEN):
        out.append(
            SecretFinding(
                "fatal",
                "JWT_SECRET",
                "JWT_SECRET is a known dev default or shorter than "
                f"{_MIN_JWT_LEN} chars — anyone can forge auth tokens. "
                "Generate one with: openssl rand -hex 64",
            )
        )

    litellm_key = s.litellm_master_key.get_secret_value()
    if _is_weak(litellm_key, _MIN_KEY_LEN):
        out.append(
            SecretFinding(
                "fatal",
                "LITELLM_MASTER_KEY",
                "LITELLM_MASTER_KEY is a known dev default or too short — it "
                "gates the LiteLLM admin API (/key/generate). Even bound to "
                "127.0.0.1 it should be strong. Set e.g. 'sk-' + openssl rand -hex 32.",
            )
        )

    hmac = s.ingest_hmac_secret.get_secret_value()
    if _is_weak(hmac, _MIN_HMAC_LEN):
        out.append(
            SecretFinding(
                "warn",
                "INGEST_HMAC_SECRET",
                "INGEST_HMAC_SECRET is a dev default — set a strong random "
                "value if webhook ingest is exposed.",
            )
        )

    if s.settings_encryption_key is None:
        out.append(
            SecretFinding(
                "warn",
                "SETTINGS_ENCRYPTION_KEY",
                "SETTINGS_ENCRYPTION_KEY is unset — stored LLM/integration "
                "secrets are encrypted with a key derived from JWT_SECRET, so "
                "rotating JWT_SECRET would orphan them. Set a dedicated Fernet key.",
            )
        )

    admin_pw = s.isoc_bootstrap_admin_password.get_secret_value()
    if admin_pw in WEAK_SECRETS:
        out.append(
            SecretFinding(
                "warn",
                "ISOC_BOOTSTRAP_ADMIN_PASSWORD",
                "ISOC_BOOTSTRAP_ADMIN_PASSWORD is the default — change it and "
                "rotate the bootstrap admin's password after first login.",
            )
        )

    return out


def assert_secrets_hardened(s: Settings, log=None) -> None:
    """Warn on weak secrets; in production, abort boot on any `fatal` finding.

    Called from the app lifespan before init_db. In a non-production posture
    (`isoc_env` = dev/anything else) nothing is raised — fatal findings are
    logged loudly so a developer sees them, but the boot proceeds.
    """
    if log is None:  # pragma: no cover - trivial default wiring
        from .logging_config import get_logger

        log = get_logger("isoc.hardening")

    findings = secret_findings(s)
    fatal = [f for f in findings if f.severity == "fatal"]
    warn = [f for f in findings if f.severity == "warn"]

    for f in warn:
        log.warning("security.weak_secret", key=f.key, detail=f.message)

    if s.is_production and fatal:
        summary = "; ".join(f"{f.key}: {f.message}" for f in fatal)
        raise RuntimeError(
            f"Refusing to boot in production (ISOC_ENV={s.isoc_env}) with weak "
            f"secrets. Fix these and restart: {summary}"
        )

    # Non-production, or production with no fatal finding: log fatals loudly so
    # they're visible during local dev without blocking the boot.
    for f in fatal:
        log.warning("security.weak_secret_dev", key=f.key, detail=f.message)


# ── Response security headers ────────────────────────────────────────────────
# Applied by the FastAPI middleware (main.py) and mirrored in the edge Caddyfile.
# Kept conservative so they can't break the Next.js UI:
#   • X-Frame-Options + CSP frame-ancestors 'none' → clickjacking protection.
#   • nosniff → block MIME sniffing.
#   • Referrer-Policy → don't leak full URLs cross-origin.
#   • Permissions-Policy → disable powerful features the app never uses.
#   • HSTS → force HTTPS once served over TLS (browsers ignore it over plain
#     http, so it's harmless on the local :80 setup).
# A full script-src CSP is intentionally NOT set here — Next.js needs inline/
# hydration scripts and a strict policy would break the UI; tune it at the edge
# later (see the commented template in config/Caddyfile).
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "frame-ancestors 'none'",
}
