from core.domain.base import DomainModel
from core.domain.parameter import Parameter
from core.domain.identity import Identity
from pydantic import Field, validator
from typing import List, Dict, Optional
from enum import Enum


class DiscoveryState(str, Enum):
    DISCOVERED = "discovered"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"


class SchemaNode(DomainModel):
    """Recursive model to define expected response shapes."""
    type_name: str = Field(...)
    properties: Dict[str, 'SchemaNode'] = Field(default_factory=dict)
    is_array: bool = Field(default=False)

SchemaNode.update_forward_refs()


class Endpoint(DomainModel):
    endpoint_id: str = Field(...)
    url: str = Field(...)
    path: str = Field(...)
    method_set: List[str] = Field(...)
    parameters: List[Parameter] = Field(default_factory=list)
    response_schema: Dict[str, SchemaNode] = Field(default_factory=dict)

    # Extended fields (Phase 7)
    asset_id: str = Field(default="")
    application_id: str = Field(default="")
    scheme: str = Field(default="https")
    host: str = Field(default="")
    port: int = Field(default=443)
    content_type: str = Field(default="")
    auth_required: bool = Field(default=False)
    auth_state: str = Field(default="unknown")
    auth_contexts: List[Identity] = Field(default_factory=list)
    discovery_state: DiscoveryState = Field(default=DiscoveryState.DISCOVERED)
    evidence_ids: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = Field(default=None)
    last_seen: Optional[str] = Field(default=None)
    discovered_endpoints: int = Field(default=1)
    is_spa_catch_all: bool = Field(default=False)

    @validator('method_set')
    def validate_methods(cls, v):
        if not v:
            raise ValueError("Endpoint method_set must not be empty")
        return [m.upper() for m in v]

    def normalized_key(self) -> str:
        """Canonical dedup identity: scheme + host + port + methods + normalized path.

        Host/scheme are lowercased and a trailing slash on a non-root path is
        stripped, so ``https://H/a`` and ``https://h/a/`` collapse to one row
        instead of inflating the duplicate tally (P0.1). This is the single
        identity every store must dedup by.
        """
        methods = ",".join(sorted(m.upper() for m in self.method_set))
        scheme = (self.scheme or "https").lower()
        host = (self.host or "").lower()
        port = self.port or (443 if scheme == "https" else 80)
        path = self.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        return f"{scheme}://{host}:{port}/{methods}{path}"

    def canonical_id(self) -> str:
        """Stable content-addressed endpoint id derived from ``normalized_key``.

        Every feed path must use this instead of a random ``uuid4`` so an
        endpoint has ONE identity across all stores — otherwise the same URL is
        "new" in one store and "duplicate" in another and the transfer/dedup
        counts disagree by construction (P0.1).
        """
        import hashlib
        return "ep_" + hashlib.sha256(self.normalized_key().encode("utf-8")).hexdigest()[:24]


def canonical_endpoint_key(method: str, url: str) -> str:
    """The ONE endpoint identity used to dedup across every store (P0.1/P3).

    Normalizes method + scheme/host case, default ports, trailing slash and
    query-parameter order so ``https://H/a`` and ``https://h/a/?b=1&a=2`` collapse
    to a single row. Kept as a module-level function (leaf module, no imports of
    memory/attack_surface) so SharedContextV2, EndpointInventoryV2 and any other
    dict-keyed store share the same key instead of each rolling its own.
    """
    try:
        from urllib.parse import urlsplit, parse_qsl, urlencode
        m = (method or "GET").upper()
        sp = urlsplit(url)
        scheme = (sp.scheme or "https").lower()
        host = (sp.hostname or "").lower()
        port = f":{sp.port}" if sp.port and sp.port not in (80, 443) else ""
        path = sp.path or "/"
        if len(path) > 1:
            path = path.rstrip("/")
        q = urlencode(sorted(parse_qsl(sp.query, keep_blank_values=True)))
        return f"{m}:{scheme}://{host}{port}{path}" + (f"?{q}" if q else "")
    except Exception:
        return f"{(method or 'GET').upper()}:{url}"
