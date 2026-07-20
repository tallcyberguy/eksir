"""Pure correlation logic — the over-correlation guard (STRONG-signal test).

Only STRONG, low-fan-out entity signals may form a correlation edge. Weak or
high-fan-out types (an IP, a hostname, a MAC, a process, a network endpoint)
would over-correlate unrelated incidents, so they NEVER establish a link.

Kept pure + unit-tested (``tests/test_correlation.py``); the DB side lives in
``adapters/cluster_store.py``. The observable ``type_id`` numbers mirror
``pipeline/ocsf.py`` (OCSF Observable enum): username(4), email(5), url(6),
hash(8), cve/resource_uid(10). Excluded observables: hostname(1), ip(2),
mac(3), filename(7), process(9).
"""

from __future__ import annotations

# STRONG signals only. Weak/high-fan-out types NEVER form an edge.
STRONG_ENTITY_TYPES = {"file", "user", "device"}
STRONG_OBSERVABLE_TYPE_IDS = {4, 5, 6, 8, 10}  # username, email, url, hash, cve
# Excluded implicitly: network_endpoint, observable ip(2)/hostname(1)/mac(3)/process(9)/filename(7).


def is_strong_entity(entity_type: str, attributes: dict | None) -> bool:
    """True iff this entity is a STRONG correlation signal.

    ``file``/``user``/``device`` entities are always strong. An ``observable``
    is strong only when its OCSF ``type_id`` is one of the strong ids
    (username/email/url/hash/cve). Everything else is a weak signal.
    """
    if entity_type in STRONG_ENTITY_TYPES:
        return True
    if entity_type == "observable":
        return (attributes or {}).get("type_id") in STRONG_OBSERVABLE_TYPE_IDS
    return False
