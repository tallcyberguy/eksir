"""The unified typed `Connector` contract (ADR-0006 decision #2).

Today a connector is four scattered pieces with nothing binding them: a `ConnectorSpec` in
`registry.py`, a `fetch()` adapter in `adapters/ingest/`, a tester in `health.py`, and a vendored
parser. Nothing enforces that they agree, so specs drift from adapters as the catalogue grows.

This class folds those four concerns behind one contract per connector: declarative metadata
(typed fields, fine capabilities, declared parser source) plus the runtime surface (`fetch`,
`test_connection`). `to_spec()` projects to the exact dict the current catalogue and admin UI
consume, as a *superset* — the legacy keys are unchanged, new typed keys are added — so the
registry can be flipped to build from `Connector` classes without breaking `routes/admin.py`,
`routes/connectors.py`, or the frontend. Migration is proven equivalent by
`tests/test_connector_framework.py`.

Metadata is classmethods (no instantiation needed to render the catalogue). `fetch`/`test_connection`
are async instance methods; provider modules register a singleton instance (mirroring the existing
`adapters/ingest` registry). Heavy transport imports (httpx, boto3) stay lazy inside those methods
so importing the catalogue stays cheap.
"""

from __future__ import annotations

from abc import ABC
from typing import Any

from ..ingest.base import FetchResult
from .capabilities import Capability, coarse_for
from .fields import AuthShape, Field, OAuthHints


class Connector(ABC):
    # --- identity / declarative metadata ---
    key: str  # matches Integration.provider + ingest_sources.provider
    label: str
    category: str  # edr|ti|recon|siem|identity|email|cloud|network|itsm|appsec
    identifier_label: str  # what Integration.identifier means for this provider
    adapter_status: str = "planned"  # "live" | "planned"
    auth_shape: AuthShape = AuthShape.TOKEN
    parser_source: str | None = None  # declared vendored-parser source; None => field_map/generic
    docs_url: str | None = None

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return ()

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return ()

    @classmethod
    def oauth_hints(cls) -> OAuthHints | None:
        return None

    @classmethod
    def region_options(cls) -> tuple[str, ...]:
        return ()

    # --- runtime surface (planned connectors leave these unimplemented) ---
    async def fetch(self, *, creds: Any, cursor: dict[str, Any], max_items: int) -> FetchResult:
        """Pull new alerts since `cursor`. Planned connectors raise until an adapter ships."""
        raise NotImplementedError(f"{self.key}: no pull adapter yet")

    async def test_connection(self, creds: Any) -> dict:
        """Read-only auth check. Planned connectors report `no_adapter` (stored, not testable)."""
        return {
            "ok": None,
            "status": "no_adapter",
            "detail": f"Credentials stored. Live testing for {self.label} arrives with its adapter.",
        }

    # --- projection to the legacy catalogue dict (backward-compatible superset) ---
    @classmethod
    def to_spec(cls) -> dict:
        oh = cls.oauth_hints()
        fields = cls.fields()
        caps = cls.capabilities()
        return {
            # legacy keys (unchanged shape — routes/admin + routes/connectors + UI read these)
            "key": cls.key,
            "label": cls.label,
            "category": cls.category,
            "capabilities": list(coarse_for(caps)),
            "fields": [f.key for f in fields],
            "region_options": list(cls.region_options()),
            "identifier_label": cls.identifier_label,
            "adapter_status": cls.adapter_status,
            "docs_url": cls.docs_url,
            # new typed keys (the wizard uses these; legacy consumers ignore them)
            "field_specs": [f.to_dict() for f in fields],
            "capability_verbs": [c.value for c in caps],
            "auth_shape": cls.auth_shape.value,
            "oauth_hints": oh.to_dict() if oh else None,
            "parser_source": cls.parser_source,
        }
