"""Threat-intel + recon planned stubs (ADR-0006 reference ports — PLANNED).

Grouped because each is a trivial enrich-only, single-field-or-two stub with no live adapter yet.
Split a connector into its own module when it gains a real fetch/parse (the pattern the EDR
providers already follow). NOTE: the internal triage stack already calls MalwareBazaar / VirusTotal
/ ThreatFox / AbuseIPDB directly, and STIX/TAXII inbound ingest shipped as the threat_intel feature,
so several of these are low marginal value (see the portfolio) and are kept mainly for menu depth.
"""

from __future__ import annotations

from ..base import Connector
from ..capabilities import Capability
from ..fields import API_KEY, BASE_URL, AuthShape, Field

_ENRICH = (Capability.ENRICH_IOC,)


class _EnrichStub(Connector):
    """Shared base for enrich-only api_key stubs. Subclasses set identity + fields."""

    adapter_status = "planned"
    auth_shape = AuthShape.TOKEN
    parser_source = None

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return _ENRICH


class MispConnector(_EnrichStub):
    key = "misp"
    label = "MISP"
    category = "ti"
    identifier_label = "Instance URL"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY, BASE_URL)


class TaxiiConnector(_EnrichStub):
    key = "taxii"
    label = "TAXII 2.1"
    category = "ti"
    identifier_label = "Collection URL"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY, BASE_URL)


class OtxConnector(_EnrichStub):
    key = "otx"
    label = "AlienVault OTX"
    category = "ti"
    identifier_label = "Account"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY,)


class AbuseIpdbConnector(_EnrichStub):
    key = "abuseipdb"
    label = "AbuseIPDB"
    category = "ti"
    identifier_label = "Account"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY,)


class ShodanConnector(_EnrichStub):
    key = "shodan"
    label = "Shodan"
    category = "recon"
    identifier_label = "Account"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY,)


class CensysConnector(_EnrichStub):
    key = "censys"
    label = "Censys"
    category = "recon"
    identifier_label = "Account"

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY,)
