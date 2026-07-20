"""Palo Alto Cortex XDR (ADR-0006 reference port — PLANNED).

Metadata-only stub: credentials are storable and it is advertised, but `fetch`/`test_connection`
inherit the base "no adapter yet" behavior until the pull adapter + parser ship.
"""

from __future__ import annotations

from ..base import Connector
from ..capabilities import Capability
from ..fields import API_KEY, BASE_URL, AuthShape, Field


class CortexXdrConnector(Connector):
    key = "cortex_xdr"
    label = "Palo Alto Cortex XDR"
    category = "edr"
    identifier_label = "Tenant FQDN"
    adapter_status = "planned"
    auth_shape = AuthShape.TOKEN
    parser_source = None

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY, BASE_URL)

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.ENRICH_IOC, Capability.ISOLATE_HOST)
