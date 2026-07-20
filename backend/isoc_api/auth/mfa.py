"""TOTP (RFC 6238) helpers for optional per-user MFA (Stage 3b).

Thin, pure wrappers over `pyotp` that operate on the PLAINTEXT base32 secret.
Encryption at rest is the caller's job (routes/auth.py encrypts via
`llm.config_store.encrypt_secret` before storing, decrypts before verifying),
mirroring how the LLM/integration API keys are handled. Keeping this module pure
makes it trivially unit-testable and keeps `pyotp` out of the route code.
"""

from __future__ import annotations

import pyotp
import segno

# Issuer label shown in the authenticator app (Google Authenticator, Authy, …).
_ISSUER = "EKSIR"


def generate_secret() -> str:
    """A fresh random base32 TOTP secret (160 bits, pyotp default)."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_email: str) -> str:
    """`otpauth://` URI for the QR code / manual entry in an authenticator app."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_email, issuer_name=_ISSUER)


def qr_data_uri(otpauth_uri: str) -> str:
    """A scannable QR of the otpauth URI as an inline SVG `data:` URI.

    Generated on the backend (never sent to a third-party QR service) and served
    over the same authenticated channel that already returns the plaintext secret,
    so it adds no new exposure. Black-on-white for maximum scanner reliability;
    the frontend renders it on a white tile. `border=2` is the required quiet zone.
    """
    return segno.make(otpauth_uri, error="m").svg_data_uri(
        scale=4, border=2, dark="#000000", light="#ffffff"
    )


def verify_code(secret: str, code: str) -> bool:
    """True if `code` is valid for `secret` right now.

    `valid_window=1` accepts the adjacent 30s step on each side to tolerate
    clock skew between the server and the user's device. Any non-numeric / empty
    input returns False rather than raising.
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False
