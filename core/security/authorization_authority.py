from __future__ import annotations

import ipaddress
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class AuthorizationScope:
    hosts: Set[str] = field(default_factory=set)
    cidrs: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    paths: Set[str] = field(default_factory=set)
    methods: Set[str] = field(default_factory=set)
    identities: Set[str] = field(default_factory=set)
    capabilities: Set[str] = field(default_factory=set)
    time_window_start: float = 0.0
    time_window_end: float = 0.0
    request_budget: int = 0
    risk_level: str = ""
    verification_classes: Set[str] = field(default_factory=set)
    lab_mode: bool = False

    def canonicalize_host(self, host: str) -> str:
        if not host:
            return ""
        host = host.strip().lower()
        if "://" in host:
            host = host.split("://", 1)[1]
        if "/" in host:
            host = host.split("/", 1)[0]
        if ":" in host:
            host = host.split(":", 1)[0]
        return host

class AuthorizationAuthority:
    _instance: Optional['AuthorizationAuthority'] = None
    _lock = __import__("threading").RLock()

    @classmethod
    def get(cls) -> 'AuthorizationAuthority':
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._scopes: Dict[str, AuthorizationScope] = {}
        self._usage_counts: Dict[str, int] = {}
        self._lock = __import__("threading").RLock()

    def register_scope(self, auth_id: str, scope: AuthorizationScope) -> None:
        with self._lock:
            # Canonicalize hosts
            scope.hosts = {scope.canonicalize_host(h) for h in scope.hosts if h}
            self._scopes[auth_id] = scope
            if auth_id not in self._usage_counts:
                self._usage_counts[auth_id] = 0

    def get_scope(self, auth_id: str) -> Optional[AuthorizationScope]:
        with self._lock:
            return self._scopes.get(auth_id)

    def authorize_execution(self, auth_id: str, target: str, capability: str, identity: str) -> Tuple[bool, str]:
        with self._lock:
            scope = self._scopes.get(auth_id)
            if not scope:
                return False, f"Unknown authorization ID: {auth_id}"

            # 1. Time window
            now = time.time()
            if scope.time_window_start and now < scope.time_window_start:
                return False, "Execution outside allowed time window (too early)"
            if scope.time_window_end and now > scope.time_window_end:
                return False, "Execution outside allowed time window (too late)"

            # 2. Budget
            if scope.request_budget > 0 and self._usage_counts[auth_id] >= scope.request_budget:
                return False, "Authorization budget exceeded"

            # 3. Identity
            if scope.identities and identity not in scope.identities:
                return False, f"Identity {identity} not authorized"

            # 4. Capability
            if scope.capabilities and capability not in scope.capabilities:
                return False, f"Capability {capability} not authorized"

            # 5. Target parsing and validation
            parsed_target = target.strip().lower()
            if "://" in parsed_target:
                parsed = urlparse(target)
                target_host = parsed.hostname or ""
            else:
                target_host = scope.canonicalize_host(target)

            # Check wildcard / lab mode
            is_wildcard = any(h == "*" or h.startswith("*.") for h in scope.hosts)
            if is_wildcard and not scope.lab_mode:
                return False, "Wildcard targets only allowed in explicit lab mode"

            authorized_target = False

            # Check exact host match
            if target_host in scope.hosts:
                authorized_target = True

            # Check wildcard match if lab mode
            if not authorized_target and scope.lab_mode:
                for h in scope.hosts:
                    if h == "*":
                        authorized_target = True
                        break
                    if h.startswith("*."):
                        suffix = h[2:]
                        if target_host == suffix or target_host.endswith("." + suffix):
                            authorized_target = True
                            break

            # Check CIDR
            if not authorized_target and scope.cidrs:
                try:
                    target_ip = ipaddress.ip_address(target_host)
                    for cidr in scope.cidrs:
                        if target_ip in ipaddress.ip_network(cidr):
                            authorized_target = True
                            break
                except ValueError:
                    # target_host is not a valid IP, and it didn't match domain
                    pass

            if not authorized_target:
                return False, f"Target {target} not within authorized scope"

            # Success
            self._usage_counts[auth_id] += 1
            return True, "Authorized"
