from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Iterable, List, Optional, Set


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    auth_required: bool = False
    hypotheses: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class LiveService:
    host: str
    port: int = 443
    scheme: str = "https"
    technologies: Set[str] = field(default_factory=set)
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)

    def upsert_endpoint(self, url: str, method: str = "GET",
                        parameters: Iterable[str] = ()) -> Endpoint:
        k = f"{method.upper()} {url}"
        ep = self.endpoints.get(k)
        if ep is None:
            ep = Endpoint(url=url, method=method.upper(),
                          parameters=list(dict.fromkeys(parameters)))
            self.endpoints[k] = ep
        else:
            for p in parameters:
                if p not in ep.parameters:
                    ep.parameters.append(p)
        return ep


@dataclass
class Subdomain:
    fqdn: str
    services: Dict[str, LiveService] = field(default_factory=dict)  # "port/scheme" -> service


class AttackSurfaceGraph:
    def __init__(self):
        self._domains: Dict[str, Dict[str, Subdomain]] = defaultdict(dict)  # domain -> {sub -> Subdomain}
        self._lock = Lock()

    @staticmethod
    def _domain_of(fqdn: str) -> str:
        parts = (fqdn or "").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn

    def add_subdomain(self, fqdn: str) -> Subdomain:
        with self._lock:
            dom = self._domain_of(fqdn)
            if fqdn not in self._domains[dom]:
                self._domains[dom][fqdn] = Subdomain(fqdn=fqdn)
            return self._domains[dom][fqdn]

    def add_service(self, fqdn: str, port: int = 443, scheme: str = "https",
                    technologies: Iterable[str] = ()) -> LiveService:
        sub = self.add_subdomain(fqdn)
        key = f"{port}/{scheme}"
        svc = sub.services.get(key)
        if svc is None:
            svc = LiveService(host=fqdn, port=port, scheme=scheme,
                              technologies=set(technologies))
            sub.services[key] = svc
        else:
            svc.technologies.update(technologies)
        return svc

    def add_endpoint(self, fqdn: str, url: str, method: str = "GET",
                     parameters: Iterable[str] = (), port: int = 443,
                     scheme: str = "https", auth_required: bool = False) -> Endpoint:
        svc = self.add_service(fqdn, port=port, scheme=scheme)
        ep = svc.upsert_endpoint(url, method=method, parameters=parameters)
        ep.auth_required = auth_required or ep.auth_required
        return ep

    def attach_hypothesis(self, fqdn: str, url: str, method: str, hyp_id: str) -> None:
        ep = self.add_endpoint(fqdn, url, method)
        if hyp_id not in ep.hypotheses:
            ep.hypotheses.append(hyp_id)

    def attach_evidence(self, fqdn: str, url: str, method: str, evidence_id: str) -> None:
        ep = self.add_endpoint(fqdn, url, method)
        if evidence_id not in ep.evidence:
            ep.evidence.append(evidence_id)

    def endpoints(self) -> List[Endpoint]:
        with self._lock:
            out: List[Endpoint] = []
            for subs in self._domains.values():
                for sub in subs.values():
                    for svc in sub.services.values():
                        out.extend(svc.endpoints.values())
            return out

    def stats(self) -> Dict[str, int]:
        with self._lock:
            n_sub = sum(len(subs) for subs in self._domains.values())
            n_svc = sum(len(sub.services) for subs in self._domains.values()
                        for sub in subs.values())
            n_ep = sum(len(svc.endpoints) for subs in self._domains.values()
                       for sub in subs.values() for svc in sub.services.values())
            return {"domains": len(self._domains), "subdomains": n_sub,
                    "services": n_svc, "endpoints": n_ep}


_SINGLETON: Optional[AttackSurfaceGraph] = None


def get_graph() -> AttackSurfaceGraph:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = AttackSurfaceGraph()
    return _SINGLETON
