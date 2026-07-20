"""Connector provider modules expressed in the typed `Connector` contract (ADR-0006).

`ALL` is the ordered catalogue the registry builds from (ADR-0006 P0.2 — the flip). Order mirrors
the legacy `registry.CONNECTORS` (EDR first, then TI, then recon) so the catalogue the admin UI and
`connector_keys()` expose is unchanged. Adding a connector = a new module here + one line in `ALL`.
"""

from __future__ import annotations

from ..base import Connector
from .cortex_xdr import CortexXdrConnector
from .crowdstrike import CrowdStrikeConnector
from .guardduty import GuardDutyConnector
from .microsoft_defender import MicrosoftDefenderConnector
from .sentinelone import SentinelOneConnector
from .ti_recon import (
    AbuseIpdbConnector,
    CensysConnector,
    MispConnector,
    OtxConnector,
    ShodanConnector,
    TaxiiConnector,
)
from .vision_one import VisionOneConnector

# Legacy catalogue order (edr -> ti -> recon). The registry projects each to a ConnectorSpec.
ALL: tuple[Connector, ...] = (
    VisionOneConnector(),
    SentinelOneConnector(),
    CrowdStrikeConnector(),
    CortexXdrConnector(),
    MicrosoftDefenderConnector(),
    GuardDutyConnector(),
    MispConnector(),
    TaxiiConnector(),
    OtxConnector(),
    AbuseIpdbConnector(),
    ShodanConnector(),
    CensysConnector(),
)

__all__ = [
    "ALL",
    "Connector",
    "VisionOneConnector",
    "SentinelOneConnector",
    "CrowdStrikeConnector",
    "CortexXdrConnector",
    "MicrosoftDefenderConnector",
    "GuardDutyConnector",
    "MispConnector",
    "TaxiiConnector",
    "OtxConnector",
    "AbuseIpdbConnector",
    "ShodanConnector",
    "CensysConnector",
]
