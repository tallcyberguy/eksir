"""Connectors framework — the self-describing connector catalogue (ADR-0006 P0.2: the flip).

The catalogue is now BUILT FROM the typed `Connector` classes in `providers/` rather than a
hand-maintained tuple of `ConnectorSpec`s. This makes each connector a single source of truth (its
`Connector` subclass) and removes the concern-drift the old four-way split invited. `ConnectorSpec`
remains the projected, attribute-accessible shape every existing consumer reads (`routes/admin.py`
`_INTEGRATION_PROVIDERS`, `routes/connectors.py`, `health.py`), now as a backward-compatible
SUPERSET: the legacy fields are unchanged and new typed fields (`field_specs`, `capability_verbs`,
`auth_shape`, `oauth_hints`, `parser_source`) ride alongside for the new admin wizard.

Adding a connector = a new module under `providers/` + one line in `providers.ALL`. Nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import Connector
from .providers import ALL as _CONNECTOR_OBJECTS


@dataclass(frozen=True)
class ConnectorSpec:
    key: str  # matches Integration.provider
    label: str
    category: str  # edr | ti | recon (new categories arrive with ADR-0006 P1)
    capabilities: tuple[str, ...]  # coarse: enrich | respond | hunt (projected from fine verbs)
    fields: tuple[str, ...]  # legacy credential field NAMES the admin form renders
    region_options: tuple[str, ...]
    identifier_label: str  # what `Integration.identifier` means for this provider
    adapter_status: str  # live | planned
    docs_url: str | None = None
    # --- ADR-0006 typed superset (additive; legacy consumers ignore these) ---
    field_specs: tuple[dict, ...] = ()  # typed Field descriptors that drive the wizard
    capability_verbs: tuple[str, ...] = ()  # fine-grained capability verbs
    auth_shape: str = "token"  # token | oauth_client_creds | aws_keys | gcp_sa_json | mtls | none
    oauth_hints: dict | None = None
    parser_source: str | None = None  # declared vendored-parser source, if any


def _spec_from_connector(conn: Connector) -> ConnectorSpec:
    """Project a typed `Connector` onto the legacy-compatible `ConnectorSpec` dataclass."""
    d = conn.to_spec()
    return ConnectorSpec(
        key=d["key"],
        label=d["label"],
        category=d["category"],
        capabilities=tuple(d["capabilities"]),
        fields=tuple(d["fields"]),
        region_options=tuple(d["region_options"]),
        identifier_label=d["identifier_label"],
        adapter_status=d["adapter_status"],
        docs_url=d["docs_url"],
        field_specs=tuple(d["field_specs"]),
        capability_verbs=tuple(d["capability_verbs"]),
        auth_shape=d["auth_shape"],
        oauth_hints=d["oauth_hints"],
        parser_source=d["parser_source"],
    )


# The catalogue — built from the typed Connector classes (the flip). Order follows providers.ALL.
CONNECTORS: tuple[ConnectorSpec, ...] = tuple(_spec_from_connector(c) for c in _CONNECTOR_OBJECTS)

_BY_KEY = {c.key: c for c in CONNECTORS}
_OBJ_BY_KEY = {c.key: c for c in _CONNECTOR_OBJECTS}


def get_spec(key: str) -> ConnectorSpec | None:
    return _BY_KEY.get(key)


def get_connector(key: str) -> Connector | None:
    """The live `Connector` instance (for the future ingest/health unification, ADR-0006 P1)."""
    return _OBJ_BY_KEY.get(key)


def connectors() -> tuple[Connector, ...]:
    return _CONNECTOR_OBJECTS


def connector_keys() -> tuple[str, ...]:
    return tuple(c.key for c in CONNECTORS)


def capabilities_for(key: str) -> tuple[str, ...]:
    spec = _BY_KEY.get(key)
    return spec.capabilities if spec else ()


def _spec_dict(c: ConnectorSpec) -> dict:
    return {
        # legacy keys (unchanged)
        "key": c.key,
        "label": c.label,
        "category": c.category,
        "capabilities": list(c.capabilities),
        "fields": list(c.fields),
        "region_options": list(c.region_options),
        "identifier_label": c.identifier_label,
        "adapter_status": c.adapter_status,
        "docs_url": c.docs_url,
        # ADR-0006 typed superset
        "field_specs": [dict(f) for f in c.field_specs],
        "capability_verbs": list(c.capability_verbs),
        "auth_shape": c.auth_shape,
        "oauth_hints": c.oauth_hints,
        "parser_source": c.parser_source,
    }


def catalog() -> list[dict]:
    return [_spec_dict(c) for c in CONNECTORS]
