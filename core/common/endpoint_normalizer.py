from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit


@dataclass
class CanonicalEndpoint:
    scheme: str
    host: str
    port: Optional[int]
    route: str
    parameters: List[str] = field(default_factory=list)
    sample_values: Dict[str, str] = field(default_factory=dict)

    @property
    def base(self) -> str:
        netloc = self.host + (f":{self.port}" if self.port else "")
        return urlunsplit((self.scheme, netloc, self.route, "", ""))

    def merge(self, other: "CanonicalEndpoint") -> "CanonicalEndpoint":
        for p in other.parameters:
            if p not in self.parameters:
                self.parameters.append(p)
        for k, v in other.sample_values.items():
            self.sample_values.setdefault(k, v)
        return self


_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_route(path: str) -> str:
    if not path:
        return "/"
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    # Collapse trailing slash unless it's just "/".
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    # Collapse double slashes.
    while "//" in path:
        path = path.replace("//", "/")
    return path


def normalize_url(url: str) -> CanonicalEndpoint:
    p = urlsplit(url.strip())
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    port = p.port
    if port and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    route = normalize_route(p.path)
    params: List[str] = []
    sample: Dict[str, str] = {}
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if k not in params:
            params.append(k)
            sample.setdefault(k, v)
    return CanonicalEndpoint(scheme=scheme, host=host, port=port,
                             route=route, parameters=params, sample_values=sample)


class EndpointDedupe:

    def __init__(self):
        self._items: Dict[Tuple[str, Optional[int], str], CanonicalEndpoint] = {}

    def add(self, url: str) -> CanonicalEndpoint:
        c = normalize_url(url)
        key = (c.host, c.port, c.route)
        existing = self._items.get(key)
        if existing:
            return existing.merge(c)
        self._items[key] = c
        return c

    def add_many(self, urls: List[str]) -> List[CanonicalEndpoint]:
        for u in urls:
            self.add(u)
        return list(self._items.values())

    def all(self) -> List[CanonicalEndpoint]:
        return list(self._items.values())
