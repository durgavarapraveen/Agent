"""Back-compat shim.

Several probes import ``from core.network.broker import NetworkBroker`` but the
implementation lives in ``core.network.network_broker``. Re-export the public
surface so both import paths work without touching every call site.
"""
from core.network.network_broker import (  # noqa: F401
    NetworkBroker,
    DNSResolver,
    RequestBudget,
    ResolvedTarget,
    NetworkDecision,
    EgressEvidence,
    get_network_broker,
)

__all__ = [
    "NetworkBroker",
    "DNSResolver",
    "RequestBudget",
    "ResolvedTarget",
    "NetworkDecision",
    "EgressEvidence",
    "get_network_broker",
]
