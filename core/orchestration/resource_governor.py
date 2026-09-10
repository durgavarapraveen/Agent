"""Phase 17.2 — Backpressure, quotas, and resource governance.

CPU, memory, storage, network, request, browser-session, and tool quotas at
tenant, scan, experiment, worker, and identity levels. Budgets visible to
planner. Exhausted budgets produce controlled stop states.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ResourceType(str, Enum):
    CPU_SECONDS = "cpu_seconds"
    MEMORY_MB = "memory_mb"
    STORAGE_MB = "storage_mb"
    NETWORK_BYTES = "network_bytes"
    HTTP_REQUESTS = "http_requests"
    BROWSER_SESSIONS = "browser_sessions"
    TOOL_INVOCATIONS = "tool_invocations"
    LLM_TOKENS = "llm_tokens"
    CONCURRENT_TASKS = "concurrent_tasks"


class QuotaLevel(str, Enum):
    TENANT = "tenant"
    SCAN = "scan"
    EXPERIMENT = "experiment"
    WORKER = "worker"
    IDENTITY = "identity"


class QuotaState(str, Enum):
    OK = "ok"
    WARNING = "warning"
    EXHAUSTED = "exhausted"
    STOPPED = "stopped"


@dataclass
class QuotaSpec:
    resource: ResourceType
    level: QuotaLevel
    scope_id: str
    limit: float
    warning_threshold: float = 0.8
    current: float = 0.0
    state: QuotaState = QuotaState.OK
    last_updated: float = field(default_factory=time.time)

    def remaining(self) -> float:
        return max(0.0, self.limit - self.current)

    def utilization(self) -> float:
        return self.current / self.limit if self.limit > 0 else 0.0

    def _key(self) -> str:
        return f"{self.level.value}:{self.scope_id}:{self.resource.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource": self.resource.value,
            "level": self.level.value,
            "scope_id": self.scope_id,
            "limit": self.limit,
            "current": self.current,
            "remaining": self.remaining(),
            "utilization_pct": round(self.utilization() * 100, 1),
            "state": self.state.value,
        }


@dataclass
class QuotaViolation:
    violation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    resource: ResourceType = ResourceType.HTTP_REQUESTS
    level: QuotaLevel = QuotaLevel.SCAN
    scope_id: str = ""
    requested: float = 0.0
    available: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.violation_id,
            "resource": self.resource.value,
            "level": self.level.value,
            "scope_id": self.scope_id,
            "requested": self.requested,
            "available": self.available,
        }


DEFAULT_GOVERNOR_CONFIG: Dict[str, Any] = {
    "enforce_quotas": True,
    "warning_threshold": 0.8,
    "stop_on_exhaustion": True,
    "max_violations_log": 1000,
}


class ResourceGovernor:
    """Enforces resource quotas across all levels. No component can bypass."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_GOVERNOR_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._quotas: Dict[str, QuotaSpec] = {}
        self._violations: List[QuotaViolation] = []
        self._stopped_scopes: Set[str] = set()

    def set_quota(self, resource: ResourceType, level: QuotaLevel,
                  scope_id: str, limit: float,
                  warning_threshold: Optional[float] = None) -> str:
        spec = QuotaSpec(
            resource=resource, level=level, scope_id=scope_id, limit=limit,
            warning_threshold=warning_threshold or self._config["warning_threshold"],
        )
        key = spec._key()
        with self._lock:
            self._quotas[key] = spec
        return key

    def consume(self, resource: ResourceType, level: QuotaLevel,
                scope_id: str, amount: float) -> Tuple[bool, QuotaState]:
        key = f"{level.value}:{scope_id}:{resource.value}"
        with self._lock:
            spec = self._quotas.get(key)
            if not spec:
                if self._config["enforce_quotas"]:
                    return False, QuotaState.STOPPED
                return True, QuotaState.OK

            if spec.current + amount > spec.limit:
                violation = QuotaViolation(
                    resource=resource, level=level, scope_id=scope_id,
                    requested=amount, available=spec.remaining(),
                )
                self._violations.append(violation)
                if len(self._violations) > self._config["max_violations_log"]:
                    self._violations = self._violations[-self._config["max_violations_log"]:]

                spec.state = QuotaState.EXHAUSTED
                if self._config["stop_on_exhaustion"]:
                    spec.state = QuotaState.STOPPED
                    self._stopped_scopes.add(f"{level.value}:{scope_id}")
                spec.last_updated = time.time()
                return False, spec.state

            spec.current += amount
            spec.last_updated = time.time()

            if spec.utilization() >= spec.warning_threshold:
                spec.state = QuotaState.WARNING
            else:
                spec.state = QuotaState.OK

            return True, spec.state

    def check(self, resource: ResourceType, level: QuotaLevel,
              scope_id: str, amount: float = 0.0) -> Tuple[bool, QuotaState, float]:
        key = f"{level.value}:{scope_id}:{resource.value}"
        with self._lock:
            spec = self._quotas.get(key)
            if not spec:
                return not self._config["enforce_quotas"], QuotaState.OK, 0.0
            can = spec.current + amount <= spec.limit
            return can, spec.state, spec.remaining()

    def release(self, resource: ResourceType, level: QuotaLevel,
                scope_id: str, amount: float) -> bool:
        key = f"{level.value}:{scope_id}:{resource.value}"
        with self._lock:
            spec = self._quotas.get(key)
            if not spec:
                return False
            spec.current = max(0.0, spec.current - amount)
            if spec.utilization() < spec.warning_threshold:
                spec.state = QuotaState.OK
            scope_key = f"{level.value}:{scope_id}"
            self._stopped_scopes.discard(scope_key)
            spec.last_updated = time.time()
        return True

    def is_stopped(self, level: QuotaLevel, scope_id: str) -> bool:
        scope_key = f"{level.value}:{scope_id}"
        return scope_key in self._stopped_scopes

    def budget_summary(self, level: QuotaLevel, scope_id: str) -> List[Dict[str, Any]]:
        prefix = f"{level.value}:{scope_id}:"
        with self._lock:
            return [
                spec.to_dict() for key, spec in self._quotas.items()
                if key.startswith(prefix)
            ]

    def get_violations(self, scope_id: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            violations = self._violations
            if scope_id:
                violations = [v for v in violations if v.scope_id == scope_id]
            return [v.to_dict() for v in violations[-limit:]]

    def reset_quota(self, resource: ResourceType, level: QuotaLevel,
                    scope_id: str) -> bool:
        key = f"{level.value}:{scope_id}:{resource.value}"
        with self._lock:
            spec = self._quotas.get(key)
            if not spec:
                return False
            spec.current = 0.0
            spec.state = QuotaState.OK
            scope_key = f"{level.value}:{scope_id}"
            self._stopped_scopes.discard(scope_key)
            spec.last_updated = time.time()
        return True

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_state: Dict[str, int] = {}
            for spec in self._quotas.values():
                by_state[spec.state.value] = by_state.get(spec.state.value, 0) + 1
            return {
                "total_quotas": len(self._quotas),
                "by_state": by_state,
                "violations": len(self._violations),
                "stopped_scopes": len(self._stopped_scopes),
            }
