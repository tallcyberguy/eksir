"""Typed credential/config field descriptors for the connector contract (ADR-0006).

The legacy `ConnectorSpec.fields` is a bare tuple of field *names* (`("api_key","region")`).
It cannot express type, masking, validation, help text, or docs, so it cannot drive a real
"Add connector" admin wizard as auth diversifies (SA-JSON textarea, PEM + passphrase, OAuth
scopes). This module is the self-describing replacement: a `Field` carries everything the UI
needs to render + validate one input, and `OAuthHints` carries the metadata a hosted-OAuth flow
advertises before it is built.

Everything here is pure (no I/O) and unit-tested — it is data, not behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FieldType(StrEnum):
    TEXT = "text"
    SECRET = "secret"  # pragma: allowlist secret  (enum member, not a credential)
    TEXTAREA = "textarea"  # multi-line (e.g. a pasted GCP service-account JSON blob)
    SELECT = "select"  # a fixed option list (e.g. region)
    NUMBER = "number"
    BOOLEAN = "boolean"


class AuthShape(StrEnum):
    """How a connector authenticates. The first two are modeled by `integration_store`
    today; the rest are declared now so the catalogue is honest, and land in ADR-0006 P2."""

    TOKEN = "token"  # single api_key (+ base_url/region)
    OAUTH_CLIENT_CREDS = "oauth_client_creds"  # client_id + client_secret (+ tenant)
    AWS_KEYS = "aws_keys"  # access-key + secret (+ IAM-role fallback) — not yet modeled
    GCP_SA_JSON = "gcp_sa_json"  # service-account JSON + local RS256 JWT — not yet modeled
    MTLS = "mtls"  # client cert + key — not yet modeled
    NONE = "none"  # listener-based (syslog/webhook), no stored secret


@dataclass(frozen=True, slots=True)
class Field:
    """One credential/config input the admin wizard renders and validates."""

    key: str
    label: str
    type: FieldType = FieldType.TEXT
    required: bool = True
    help: str | None = None
    placeholder: str | None = None
    options: tuple[str, ...] = ()  # for FieldType.SELECT
    docs_url: str | None = None

    @property
    def secret(self) -> bool:
        return self.type is FieldType.SECRET

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "type": self.type.value,
            "required": self.required,
            "secret": self.secret,
            "help": self.help,
            "placeholder": self.placeholder,
            "options": list(self.options),
            "docs_url": self.docs_url,
        }


@dataclass(frozen=True, slots=True)
class OAuthHints:
    """Forward-declared metadata for a hosted-OAuth flow. `{domain}` in a URL is substituted
    with the connector's configured domain/identifier. `supported_in_hosted` gates whether the
    UI offers the one-click flow or only manual client-credentials entry."""

    token_url: str
    authorize_url: str | None = None
    scopes: tuple[str, ...] = ()
    supported_in_hosted: bool = False

    def to_dict(self) -> dict:
        return {
            "token_url": self.token_url,
            "authorize_url": self.authorize_url,
            "scopes": list(self.scopes),
            "supported_in_hosted": self.supported_in_hosted,
        }


def validate_config(fields: tuple[Field, ...], config: dict) -> list[str]:
    """Return human-readable validation errors for `config` against `fields` (empty = valid).

    Pure. Checks required presence, SELECT membership, NUMBER/BOOLEAN coercibility. Unknown keys
    are ignored (forward-compatible), not rejected.
    """
    errors: list[str] = []
    for f in fields:
        present = f.key in config and config[f.key] not in (None, "")
        if f.required and not present:
            errors.append(f"missing required field '{f.key}' ({f.label})")
            continue
        if not present:
            continue
        val = config[f.key]
        if f.type is FieldType.SELECT and f.options and str(val) not in f.options:
            errors.append(f"'{f.key}' must be one of {list(f.options)}, got {val!r}")
        elif f.type is FieldType.NUMBER:
            try:
                float(val)
            except (TypeError, ValueError):
                errors.append(f"'{f.key}' must be a number, got {val!r}")
        elif f.type is FieldType.BOOLEAN and not isinstance(val, bool):
            if str(val).lower() not in ("true", "false", "1", "0"):
                errors.append(f"'{f.key}' must be a boolean, got {val!r}")
    return errors


# Reusable field presets so provider modules stay declarative and consistent.
API_KEY = Field("api_key", "API token", FieldType.SECRET, help="Bearer/API token.")
BASE_URL = Field("base_url", "Console host / base URL", FieldType.TEXT)
CLIENT_ID = Field("client_id", "OAuth client ID", FieldType.TEXT)
CLIENT_SECRET = Field("client_secret", "OAuth client secret", FieldType.SECRET)
OAUTH_TENANT_ID = Field("oauth_tenant_id", "Directory (tenant) ID", FieldType.TEXT)


def region_field(options: tuple[str, ...]) -> Field:
    return Field("region", "Region", FieldType.SELECT, options=options)
