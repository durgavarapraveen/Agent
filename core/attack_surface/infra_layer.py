from __future__ import annotations

from enum import Enum
from typing import Dict


class InfraLayer(str, Enum):
    EDGE = "EDGE"            # CDN / reverse proxy / cache in front
    ORIGIN = "ORIGIN"        # origin web server
    APPLICATION = "APPLICATION"  # application framework behind the origin
    UNKNOWN = "UNKNOWN"


# Headers that only an edge/proxy/CDN layer emits (vendor-agnostic set).
_EDGE_HEADERS = (
    "cf-ray", "cf-cache-status", "x-amz-cf-id", "x-akamai-transformed",
    "fastly-debug-digest", "x-fastly-request-id", "x-served-by", "x-cache",
    "x-cache-hits", "via", "x-varnish", "x-proxy-cache", "x-edge-location",
)
_EDGE_SERVER_TOKENS = ("cloudflare", "cloudfront", "akamai", "fastly",
                       "varnish", "envoy", "haproxy", "squid")
_APP_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-rails", "x-django", "x-runtime")


def classify_layer(headers: Dict[str, str]) -> str:
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    if any(k in h for k in _EDGE_HEADERS):
        return InfraLayer.EDGE.value
    server = h.get("server", "")
    if any(tok in server for tok in _EDGE_SERVER_TOKENS):
        return InfraLayer.EDGE.value
    if any(k in h for k in _APP_HEADERS):
        return InfraLayer.APPLICATION.value
    if server:
        return InfraLayer.ORIGIN.value
    return InfraLayer.UNKNOWN.value
