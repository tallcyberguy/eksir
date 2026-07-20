"""AWS GuardDuty (ADR-0006 reference port — PLANNED).

Metadata-only stub. NOTE (ADR-0006 decision #7): the fields below (api_key + region) are the legacy
PLACEHOLDER shape and are NOT how AWS actually authenticates. `auth_shape` is left as `token` to
match those placeholder fields today; fixing this to the real AWS access-key/secret (+ IAM-role
fallback) shape is P2, at which point `fields()` and `auth_shape` change together and the category
moves edr -> cloud.
"""

from __future__ import annotations

from ..base import Connector
from ..capabilities import Capability
from ..fields import API_KEY, AuthShape, Field, region_field

AWS_REGIONS = ("us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1")


class GuardDutyConnector(Connector):
    key = "guardduty"
    label = "AWS GuardDuty"
    category = "edr"  # P2: move to "cloud" when the real AWS auth shape lands
    identifier_label = "AWS account"
    adapter_status = "planned"
    auth_shape = AuthShape.TOKEN  # placeholder; real shape is AWS_KEYS (ADR-0006 P2)
    parser_source = None

    @classmethod
    def fields(cls) -> tuple[Field, ...]:
        return (API_KEY, region_field(AWS_REGIONS))

    @classmethod
    def region_options(cls) -> tuple[str, ...]:
        return AWS_REGIONS

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.ENRICH_IOC)
