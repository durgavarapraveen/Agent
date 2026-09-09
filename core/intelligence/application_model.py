"""P1.1 — Unified ApplicationModel.

Single source of truth for everything known about the target application.
Merges discovery (AttackSurfaceState) and runtime (SharedContextV2) into
one typed, thread-safe, event-driven model that every agent, analyzer,
and reporter reads from.

Structure:
    ApplicationModel
    ├── hosts            — discovered hosts / IPs
    ├── services         — port/protocol/banner per host
    ├── technologies     — tech stack per host
    ├── endpoints        — HTTP/WS/GraphQL endpoints
    ├── parameters       — per-endpoint input vectors
    ├── schemas          — response/request shape models
    ├── identities       — credential sets / user personas
    ├── roles            — RBAC / privilege tiers
    ├── sessions         — authenticated session state
    ├── resources        — protected data objects
    ├── workflows        — multi-step business flows
    ├── state_transitions — observed state machine edges
    ├── trust_boundaries — network/auth/privilege lines
    ├── data_flows       — data movement between components
    ├── client_sinks     — browser-side injection points
    ├── server_sinks     — server-side injection points
    ├── dependencies     — external services / third-party
    ├── caches           — caching layers observed
    ├── queues           — async processing observed
    └── security_invariants — rules that must always hold
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ModelEvent(str, Enum):
    HOST_ADDED = "host_added"
    SERVICE_ADDED = "service_added"
    TECHNOLOGY_ADDED = "technology_added"
    ENDPOINT_ADDED = "endpoint_added"
    PARAMETER_ADDED = "parameter_added"
    SCHEMA_ADDED = "schema_added"
    IDENTITY_ADDED = "identity_added"
    ROLE_ADDED = "role_added"
    SESSION_ADDED = "session_added"
    RESOURCE_ADDED = "resource_added"
    WORKFLOW_ADDED = "workflow_added"
    STATE_TRANSITION_ADDED = "state_transition_added"
    TRUST_BOUNDARY_ADDED = "trust_boundary_added"
    DATA_FLOW_ADDED = "data_flow_added"
    CLIENT_SINK_ADDED = "client_sink_added"
    SERVER_SINK_ADDED = "server_sink_added"
    DEPENDENCY_ADDED = "dependency_added"
    CACHE_ADDED = "cache_added"
    QUEUE_ADDED = "queue_added"
    INVARIANT_ADDED = "invariant_added"
    INVARIANT_VIOLATED = "invariant_violated"


# ── Lightweight value types for concepts with no existing domain model ──


@dataclass
class ServiceInfo:
    host_id: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    banner: str = ""
    version: str = ""
    state: str = "open"
    source: str = "unknown"
    confidence: float = 1.0
    first_seen: str = ""
    last_seen: str = ""

    @property
    def key(self) -> str:
        return f"{self.host_id}:{self.port}/{self.protocol}"


@dataclass
class RoleInfo:
    role_id: str
    name: str
    privilege_level: int = 0
    permissions: List[str] = field(default_factory=list)
    identity_ids: List[str] = field(default_factory=list)
    source: str = "unknown"


@dataclass
class Resource:
    resource_id: str
    resource_type: str
    name: str
    owner_identity_id: str = ""
    endpoint_ids: List[str] = field(default_factory=list)
    access_control: str = ""
    sensitivity: str = "unknown"
    source: str = "unknown"


@dataclass
class StateTransition:
    from_state: str
    to_state: str
    trigger: str
    endpoint_id: str = ""
    method: str = ""
    requires_auth: bool = False
    side_effects: List[str] = field(default_factory=list)
    source: str = "unknown"

    @property
    def key(self) -> str:
        return f"{self.from_state}->{self.to_state}@{self.trigger}"


@dataclass
class TrustBoundary:
    boundary_id: str
    name: str
    boundary_type: str  # network, auth, privilege, process, data
    from_zone: str = ""
    to_zone: str = ""
    crossing_endpoints: List[str] = field(default_factory=list)
    controls: List[str] = field(default_factory=list)
    source: str = "unknown"


@dataclass
class DataFlow:
    flow_id: str
    name: str
    source_component: str
    destination_component: str
    data_type: str = ""
    classification: str = "unknown"
    encrypted: bool = True
    crosses_boundary: str = ""
    endpoint_ids: List[str] = field(default_factory=list)
    source: str = "unknown"


@dataclass
class SinkInfo:
    sink_id: str
    sink_type: str  # xss, redirect, eval, innerHTML, sql, command, file, template, ...
    location: str
    endpoint_id: str = ""
    parameter_name: str = ""
    context: str = ""
    sanitized: bool = False
    source: str = "unknown"

    @property
    def key(self) -> str:
        return f"{self.sink_type}:{self.location}:{self.parameter_name}"


@dataclass
class DependencyInfo:
    dep_id: str
    name: str
    dep_type: str  # api, cdn, saas, database, storage, auth_provider, ...
    url: str = ""
    host: str = ""
    version: str = ""
    internal: bool = False
    source: str = "unknown"


@dataclass
class CacheInfo:
    cache_id: str
    cache_type: str  # cdn, reverse_proxy, application, browser, ...
    location: str
    headers_observed: Dict[str, str] = field(default_factory=dict)
    cacheable_endpoints: List[str] = field(default_factory=list)
    source: str = "unknown"


@dataclass
class QueueInfo:
    queue_id: str
    queue_type: str  # message_queue, job_queue, webhook, event_stream, ...
    name: str = ""
    endpoint_ids: List[str] = field(default_factory=list)
    source: str = "unknown"


@dataclass
class SecurityInvariant:
    invariant_id: str
    description: str
    invariant_type: str  # auth, access_control, data_integrity, rate_limit, ...
    check_fn_name: str = ""
    endpoint_ids: List[str] = field(default_factory=list)
    status: str = "active"  # active, violated, unverified
    violations: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "unknown"


# ── Host model (extends the simple asset.Host) ──

@dataclass
class HostRecord:
    host_id: str
    hostname: str
    ip_addresses: List[str] = field(default_factory=list)
    os_fingerprint: str = ""
    is_target: bool = True
    first_seen: str = ""
    last_seen: str = ""
    source: str = "unknown"
    confidence: float = 1.0


# ── Main model ──

EventListener = Callable[[ModelEvent, str, Any], None]


class ApplicationModel:
    """Unified live model of the target application.

    Thread-safe: all mutations go through ``_lock``.
    Event-driven: register listeners via ``on()`` to react to changes.
    Singleton-per-scan: use ``get()`` / ``reset_for_tests()``.
    """

    _instance: Optional[ApplicationModel] = None
    _instance_lock = threading.Lock()

    def __init__(self, target: str = ""):
        self._lock = threading.RLock()
        self.target = target
        self._listeners: Dict[ModelEvent, List[EventListener]] = {}

        # ── Core stores ──
        self.hosts: Dict[str, HostRecord] = {}
        self.services: Dict[str, ServiceInfo] = {}
        self.technologies: Dict[str, List[Dict[str, str]]] = {}  # host -> [{name, version, category}]
        self.endpoints: Dict[str, Any] = {}  # endpoint_id -> Endpoint or dict
        self.parameters: Dict[str, List[Any]] = {}  # endpoint_id -> [Parameter]
        self.schemas: Dict[str, Any] = {}  # endpoint_id -> schema dict
        self.identities: Dict[str, Any] = {}  # identity_id -> Identity
        self.roles: Dict[str, RoleInfo] = {}
        self.sessions: Dict[str, Any] = {}  # session_id -> Session
        self.resources: Dict[str, Resource] = {}
        self.workflows: Dict[str, Any] = {}  # workflow_id -> Workflow or dict
        self.state_transitions: Dict[str, StateTransition] = {}
        self.trust_boundaries: Dict[str, TrustBoundary] = {}
        self.data_flows: Dict[str, DataFlow] = {}
        self.client_sinks: Dict[str, SinkInfo] = {}
        self.server_sinks: Dict[str, SinkInfo] = {}
        self.dependencies: Dict[str, DependencyInfo] = {}
        self.caches: Dict[str, CacheInfo] = {}
        self.queues: Dict[str, QueueInfo] = {}
        self.security_invariants: Dict[str, SecurityInvariant] = {}

    # ── Singleton ──

    @classmethod
    def get(cls, target: str = "") -> ApplicationModel:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(target)
            return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        with cls._instance_lock:
            cls._instance = None

    # ── Events ──

    def on(self, event: ModelEvent, listener: EventListener) -> None:
        self._listeners.setdefault(event, []).append(listener)

    def _emit(self, event: ModelEvent, key: str, data: Any = None) -> None:
        for fn in self._listeners.get(event, []):
            try:
                fn(event, key, data)
            except Exception:
                logger.debug("listener error for %s", event, exc_info=True)

    # ── Hosts ──

    def add_host(self, hostname: str, ip_addresses: Optional[List[str]] = None,
                 **kwargs) -> HostRecord:
        now = datetime.now(timezone.utc).isoformat()
        host_id = hostname.lower()
        with self._lock:
            if host_id in self.hosts:
                rec = self.hosts[host_id]
                rec.last_seen = now
                for ip in (ip_addresses or []):
                    if ip not in rec.ip_addresses:
                        rec.ip_addresses.append(ip)
                return rec
            rec = HostRecord(
                host_id=host_id, hostname=hostname,
                ip_addresses=ip_addresses or [],
                first_seen=now, last_seen=now, **kwargs,
            )
            self.hosts[host_id] = rec
        self._emit(ModelEvent.HOST_ADDED, host_id, rec)
        return rec

    # ── Services ──

    def add_service(self, host_id: str, port: int, protocol: str = "tcp",
                    **kwargs) -> ServiceInfo:
        svc = ServiceInfo(host_id=host_id, port=port, protocol=protocol, **kwargs)
        now = datetime.now(timezone.utc).isoformat()
        svc.first_seen = svc.first_seen or now
        svc.last_seen = now
        with self._lock:
            existing = self.services.get(svc.key)
            if existing:
                existing.last_seen = now
                if svc.banner and not existing.banner:
                    existing.banner = svc.banner
                if svc.version and not existing.version:
                    existing.version = svc.version
                return existing
            self.services[svc.key] = svc
        self._emit(ModelEvent.SERVICE_ADDED, svc.key, svc)
        return svc

    # ── Technologies ──

    def add_technology(self, host_id: str, name: str, version: str = "",
                       category: str = "") -> None:
        entry = {"name": name, "version": version, "category": category}
        with self._lock:
            techs = self.technologies.setdefault(host_id, [])
            for t in techs:
                if t["name"].lower() == name.lower():
                    if version and not t["version"]:
                        t["version"] = version
                    return
            techs.append(entry)
        self._emit(ModelEvent.TECHNOLOGY_ADDED, f"{host_id}:{name}", entry)

    # ── Endpoints ──

    def add_endpoint(self, endpoint_id: str, endpoint: Any, **kwargs) -> bool:
        with self._lock:
            if endpoint_id in self.endpoints:
                return False
            self.endpoints[endpoint_id] = endpoint
        self._emit(ModelEvent.ENDPOINT_ADDED, endpoint_id, endpoint)
        return True

    # ── Parameters ──

    def add_parameter(self, endpoint_id: str, parameter: Any) -> None:
        name = getattr(parameter, "name", "") or (parameter.get("name", "") if isinstance(parameter, dict) else "")
        with self._lock:
            params = self.parameters.setdefault(endpoint_id, [])
            for p in params:
                p_name = getattr(p, "name", "") or (p.get("name", "") if isinstance(p, dict) else "")
                if p_name == name:
                    return
            params.append(parameter)
        self._emit(ModelEvent.PARAMETER_ADDED, f"{endpoint_id}:{name}", parameter)

    # ── Schemas ──

    def add_schema(self, endpoint_id: str, schema: Any) -> None:
        with self._lock:
            self.schemas[endpoint_id] = schema
        self._emit(ModelEvent.SCHEMA_ADDED, endpoint_id, schema)

    # ── Identities ──

    def add_identity(self, identity_id: str, identity: Any) -> None:
        with self._lock:
            self.identities[identity_id] = identity
        self._emit(ModelEvent.IDENTITY_ADDED, identity_id, identity)

    # ── Roles ──

    def add_role(self, role: RoleInfo) -> None:
        with self._lock:
            self.roles[role.role_id] = role
        self._emit(ModelEvent.ROLE_ADDED, role.role_id, role)

    # ── Sessions ──

    def add_session(self, session_id: str, session: Any) -> None:
        with self._lock:
            self.sessions[session_id] = session
        self._emit(ModelEvent.SESSION_ADDED, session_id, session)

    # ── Resources ──

    def add_resource(self, resource: Resource) -> None:
        with self._lock:
            self.resources[resource.resource_id] = resource
        self._emit(ModelEvent.RESOURCE_ADDED, resource.resource_id, resource)

    # ── Workflows ──

    def add_workflow(self, workflow_id: str, workflow: Any) -> None:
        with self._lock:
            self.workflows[workflow_id] = workflow
        self._emit(ModelEvent.WORKFLOW_ADDED, workflow_id, workflow)

    # ── State transitions ──

    def add_state_transition(self, transition: StateTransition) -> None:
        with self._lock:
            self.state_transitions[transition.key] = transition
        self._emit(ModelEvent.STATE_TRANSITION_ADDED, transition.key, transition)

    # ── Trust boundaries ──

    def add_trust_boundary(self, boundary: TrustBoundary) -> None:
        with self._lock:
            self.trust_boundaries[boundary.boundary_id] = boundary
        self._emit(ModelEvent.TRUST_BOUNDARY_ADDED, boundary.boundary_id, boundary)

    # ── Data flows ──

    def add_data_flow(self, flow: DataFlow) -> None:
        with self._lock:
            self.data_flows[flow.flow_id] = flow
        self._emit(ModelEvent.DATA_FLOW_ADDED, flow.flow_id, flow)

    # ── Client sinks ──

    def add_client_sink(self, sink: SinkInfo) -> None:
        with self._lock:
            self.client_sinks[sink.sink_id] = sink
        self._emit(ModelEvent.CLIENT_SINK_ADDED, sink.sink_id, sink)

    # ── Server sinks ──

    def add_server_sink(self, sink: SinkInfo) -> None:
        with self._lock:
            self.server_sinks[sink.sink_id] = sink
        self._emit(ModelEvent.SERVER_SINK_ADDED, sink.sink_id, sink)

    # ── Dependencies ──

    def add_dependency(self, dep: DependencyInfo) -> None:
        with self._lock:
            self.dependencies[dep.dep_id] = dep
        self._emit(ModelEvent.DEPENDENCY_ADDED, dep.dep_id, dep)

    # ── Caches ──

    def add_cache(self, cache: CacheInfo) -> None:
        with self._lock:
            self.caches[cache.cache_id] = cache
        self._emit(ModelEvent.CACHE_ADDED, cache.cache_id, cache)

    # ── Queues ──

    def add_queue(self, queue: QueueInfo) -> None:
        with self._lock:
            self.queues[queue.queue_id] = queue
        self._emit(ModelEvent.QUEUE_ADDED, queue.queue_id, queue)

    # ── Security invariants ──

    def add_invariant(self, invariant: SecurityInvariant) -> None:
        with self._lock:
            self.security_invariants[invariant.invariant_id] = invariant
        self._emit(ModelEvent.INVARIANT_ADDED, invariant.invariant_id, invariant)

    def violate_invariant(self, invariant_id: str, violation: Dict[str, Any]) -> None:
        with self._lock:
            inv = self.security_invariants.get(invariant_id)
            if inv is None:
                return
            inv.status = "violated"
            violation["timestamp"] = datetime.now(timezone.utc).isoformat()
            inv.violations.append(violation)
        self._emit(ModelEvent.INVARIANT_VIOLATED, invariant_id, violation)

    def check_invariants(self) -> List[Tuple[str, str]]:
        results = []
        with self._lock:
            for iid, inv in self.security_invariants.items():
                results.append((iid, inv.status))
        return results

    # ── Hydration from SharedContextV2 ──

    def hydrate_from_shared_context(self, ctx: Any) -> None:
        """Populate the model from an existing SharedContextV2 instance."""
        if hasattr(ctx, "target") and ctx.target:
            self.target = ctx.target
            try:
                from urllib.parse import urlparse
                parsed = urlparse(ctx.target)
                hostname = parsed.hostname or ctx.target
                self.add_host(hostname, is_target=True)
            except Exception:
                pass

        if hasattr(ctx, "subdomains"):
            for sub in (ctx.subdomains or []):
                self.add_host(sub, source="recon")

        if hasattr(ctx, "ips"):
            for ip in (ctx.ips or []):
                self.add_host(ip, source="recon")

        if hasattr(ctx, "ports"):
            for p in (ctx.ports or []):
                if isinstance(p, dict) and "port" in p:
                    host = p.get("host", self.target or "")
                    self.add_service(
                        host_id=host, port=p["port"],
                        protocol=p.get("protocol", "tcp"),
                        service_name=p.get("service", ""),
                        state=p.get("state", "open"),
                        source="recon",
                    )

        if hasattr(ctx, "technologies"):
            for host, techs in (ctx.technologies or {}).items():
                for t in (techs if isinstance(techs, list) else [techs]):
                    name = t if isinstance(t, str) else (t.get("name", str(t)) if isinstance(t, dict) else str(t))
                    version = t.get("version", "") if isinstance(t, dict) else ""
                    self.add_technology(host, name, version)

        if hasattr(ctx, "endpoints"):
            eps = ctx.endpoints
            if isinstance(eps, dict):
                for eid, ep in eps.items():
                    self.add_endpoint(eid, ep)
            elif isinstance(eps, list):
                for ep in eps:
                    eid = getattr(ep, "endpoint_id", None) or (ep.get("endpoint_id", "") if isinstance(ep, dict) else str(ep))
                    self.add_endpoint(eid or str(ep), ep)

        if hasattr(ctx, "identities"):
            for iid, ident in (ctx.identities or {}).items():
                self.add_identity(iid, ident)

        if hasattr(ctx, "sessions"):
            for sid, sess in (ctx.sessions or {}).items():
                self.add_session(sid, sess)

        if hasattr(ctx, "external_dependencies"):
            for dep in (ctx.external_dependencies or []):
                if isinstance(dep, dict):
                    self.add_dependency(DependencyInfo(
                        dep_id=dep.get("host", dep.get("url", "")),
                        name=dep.get("host", ""),
                        dep_type="external",
                        url=dep.get("url", ""),
                        host=dep.get("host", ""),
                        source=dep.get("source", "recon"),
                    ))

        if hasattr(ctx, "headers"):
            for host, hdrs in (ctx.headers or {}).items():
                if isinstance(hdrs, dict):
                    cache_headers = {k: v for k, v in hdrs.items()
                                     if k.lower() in ("cache-control", "x-cache", "cf-cache-status",
                                                       "x-varnish", "age", "via", "cdn-cache")}
                    if cache_headers:
                        self.add_cache(CacheInfo(
                            cache_id=f"cache:{host}",
                            cache_type="inferred",
                            location=host,
                            headers_observed=cache_headers,
                            source="header_analysis",
                        ))

        if hasattr(ctx, "ssl_info"):
            for host, info in (ctx.ssl_info or {}).items():
                if isinstance(info, dict):
                    self.add_trust_boundary(TrustBoundary(
                        boundary_id=f"tls:{host}",
                        name=f"TLS boundary for {host}",
                        boundary_type="network",
                        from_zone="client",
                        to_zone=host,
                        controls=[f"TLS {info.get('protocol', '')}".strip()],
                        source="ssl_scan",
                    ))

        logger.info(
            "[P1.1] ApplicationModel hydrated: %d hosts, %d services, "
            "%d endpoints, %d identities, %d dependencies",
            len(self.hosts), len(self.services), len(self.endpoints),
            len(self.identities), len(self.dependencies),
        )

    # ── Query helpers ──

    def endpoints_crossing_boundary(self, boundary_id: str) -> List[str]:
        with self._lock:
            b = self.trust_boundaries.get(boundary_id)
            return list(b.crossing_endpoints) if b else []

    def sinks_for_endpoint(self, endpoint_id: str) -> Dict[str, List[SinkInfo]]:
        result: Dict[str, List[SinkInfo]] = {"client": [], "server": []}
        with self._lock:
            for s in self.client_sinks.values():
                if s.endpoint_id == endpoint_id:
                    result["client"].append(s)
            for s in self.server_sinks.values():
                if s.endpoint_id == endpoint_id:
                    result["server"].append(s)
        return result

    def services_for_host(self, host_id: str) -> List[ServiceInfo]:
        with self._lock:
            return [s for s in self.services.values() if s.host_id == host_id]

    def flows_crossing_boundary(self, boundary_id: str) -> List[DataFlow]:
        with self._lock:
            return [f for f in self.data_flows.values() if f.crosses_boundary == boundary_id]

    def get_attack_surface_summary(self) -> Dict[str, int]:
        with self._lock:
            return {
                "hosts": len(self.hosts),
                "services": len(self.services),
                "technologies": sum(len(v) for v in self.technologies.values()),
                "endpoints": len(self.endpoints),
                "parameters": sum(len(v) for v in self.parameters.values()),
                "schemas": len(self.schemas),
                "identities": len(self.identities),
                "roles": len(self.roles),
                "sessions": len(self.sessions),
                "resources": len(self.resources),
                "workflows": len(self.workflows),
                "state_transitions": len(self.state_transitions),
                "trust_boundaries": len(self.trust_boundaries),
                "data_flows": len(self.data_flows),
                "client_sinks": len(self.client_sinks),
                "server_sinks": len(self.server_sinks),
                "dependencies": len(self.dependencies),
                "caches": len(self.caches),
                "queues": len(self.queues),
                "security_invariants": len(self.security_invariants),
            }

    def summary(self) -> Dict[str, Any]:
        s = self.get_attack_surface_summary()
        s["target"] = self.target
        violated = sum(1 for inv in self.security_invariants.values() if inv.status == "violated")
        s["invariants_violated"] = violated
        return s
