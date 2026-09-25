"""Engagement aggregate — the authoritative authorization boundary (spec §1, §2).

Hierarchy:  Organization → Project → Environment → Engagement → Run

The Engagement is a first-class domain object that carries *everything* the
deterministic security layer needs to decide whether an action is permitted:
authorized/excluded targets, allowed/forbidden operations, the active time
window, and rate limits. Scope host/ip/url matching is delegated to the
existing ``core.scope.manager.ScopeManager`` (no duplicate scope logic); the
Engagement adds exclusions, operation policy and the time window on top.

Authorization is **fail-closed**: any missing configuration, malformed input,
or unmet precondition denies. The LLM/agent layer never overrides these
decisions — it can only ask, and the answer is computed here deterministically.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import Field

from core.domain.base import DomainModel


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    EXPIRED = "expired"


class EnvironmentType(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    TEST = "test"
    LAB = "lab"
    UNKNOWN = "unknown"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Organization(DomainModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")


class Project(DomainModel):
    org_id: str
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")


class Environment(DomainModel):
    project_id: str
    name: str = Field(..., min_length=1, max_length=200)
    environment_type: EnvironmentType = Field(default=EnvironmentType.UNKNOWN)


class Run(DomainModel):
    engagement_id: str
    target: str = Field(default="")
    scan_id: str = Field(default="")
    status: RunStatus = Field(default=RunStatus.PENDING)
    tier: str = Field(default="POC")
    reason: str = Field(default="")


class Engagement(DomainModel):
    """Authoritative, fail-closed authorization aggregate for one engagement.

    Everything downstream (Scope Engine, Tool Broker, agents) binds to this.
    """

    # Lineage (optional so an Engagement can stand alone in simple deployments)
    org_id: Optional[str] = Field(default=None)
    project_id: Optional[str] = Field(default=None)
    environment_id: Optional[str] = Field(default=None)
    environment_type: EnvironmentType = Field(default=EnvironmentType.UNKNOWN)

    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")

    # Scope (positive)
    authorized_targets: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_ips: List[str] = Field(default_factory=list)
    allowed_urls: List[str] = Field(default_factory=list)
    # Future dimensions (cloud/k8s agents) — carried now so the boundary is
    # stable when those agents land; empty = nothing authorized there.
    allowed_cloud_accounts: List[str] = Field(default_factory=list)
    allowed_kubernetes_clusters: List[str] = Field(default_factory=list)

    # Scope (negative) — exclusions ALWAYS win over any allow rule.
    excluded_targets: List[str] = Field(default_factory=list)

    # Operation policy. If ``allowed_operations`` is non-empty it is an
    # allowlist (anything not listed is denied). ``forbidden_operations`` is a
    # denylist that always wins.
    allowed_operations: List[str] = Field(default_factory=list)
    forbidden_operations: List[str] = Field(default_factory=list)

    execution_mode: str = Field(default="PASSIVE")

    # Time window (UTC, naive — matches DomainModel.created_at). None = open end.
    start_time: Optional[datetime] = Field(default=None)
    end_time: Optional[datetime] = Field(default=None)

    # Rate limits
    rate_limit_rps: float = Field(default=5.0, ge=0.0)
    max_concurrent: int = Field(default=3, ge=1)

    data_handling_policy: str = Field(default="minimal")
    status: EngagementStatus = Field(default=EngagementStatus.DRAFT)

    # ── Scope helpers ────────────────────────────────────────────────────
    def _scope_manager(self):
        """Build a ScopeManager from this engagement (reuse, no duplication)."""
        from core.scope.manager import ScopeManager
        return ScopeManager(
            allowed_domains=list(self.allowed_domains),
            allowed_ips=list(self.allowed_ips),
            allowed_urls=list(self.allowed_urls),
            execution_mode=self.execution_mode,
        )

    def to_scope_manager(self):
        """Public accessor used by orchestration to bind the Scope Engine."""
        return self._scope_manager()

    @staticmethod
    def _host_of(target: str) -> str:
        from urllib.parse import urlparse
        cand = target if "://" in target else "http://" + target
        try:
            return (urlparse(cand).hostname or "").strip().lower()
        except ValueError:
            return ""

    def _is_excluded(self, target: str) -> bool:
        """A target is excluded if it, or its host, matches any exclusion.

        Exclusions are matched both as exact strings and by host so that
        ``https://admin.example.com/x`` is caught by an ``admin.example.com``
        exclusion. Fail-closed: an unparseable target is treated as excluded.
        """
        if not target:
            return True
        t = target.strip().lower()
        host = self._host_of(target)
        for ex in self.excluded_targets:
            e = (ex or "").strip().lower()
            if not e:
                continue
            if e == t or e == host:
                return True
            if host and (host == e or host.endswith("." + e)):
                return True
            if e in t:
                return True
        return False

    # ── Authorization primitives (spec §2) — all fail-closed ─────────────
    def is_time_window_valid(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.utcnow()
        if self.status not in (EngagementStatus.ACTIVE,):
            return False
        if self.start_time and now < self.start_time:
            return False
        if self.end_time and now > self.end_time:
            return False
        return True

    def is_target_authorized(self, target: str) -> bool:
        if not target:
            return False
        if self._is_excluded(target):
            return False
        # Exact authorized_targets membership is sufficient.
        if target.strip() in {t.strip() for t in self.authorized_targets}:
            return True
        # Otherwise defer to the reused ScopeManager (domain/ip/url matching).
        try:
            return bool(self._scope_manager().validate_url(
                target if "://" in target else "http://" + target))
        except Exception:
            return False

    def is_operation_authorized(self, operation: str) -> bool:
        if not operation:
            return False
        op = operation.strip().lower()
        if op in {o.strip().lower() for o in self.forbidden_operations}:
            return False
        if self.allowed_operations:
            return op in {o.strip().lower() for o in self.allowed_operations}
        return True  # no allowlist configured → operation not denied

    def is_resource_authorized(self, resource: str) -> bool:
        """Cloud/k8s/generic resource check. Empty allowlists deny non-target
        resources (fail-closed) unless the resource is an authorized target."""
        if not resource:
            return False
        pools = (self.allowed_cloud_accounts +
                 self.allowed_kubernetes_clusters)
        if pools and resource.strip() in {p.strip() for p in pools}:
            return True
        return self.is_target_authorized(resource)

    def authorize(self, target: str, operation: str = "",
                  now: Optional[datetime] = None) -> Tuple[bool, str]:
        """Single fail-closed gate. Returns (allowed, reason).

        Reason names the first failing check so denials are auditable.
        """
        if not self.is_time_window_valid(now):
            return False, "time_window_or_status_invalid"
        if not self.is_target_authorized(target):
            return False, "target_not_authorized"
        if operation and not self.is_operation_authorized(operation):
            return False, "operation_not_authorized"
        return True, "authorized"

    def summary(self) -> dict:
        return {
            "engagement_id": self.id,
            "name": self.name,
            "status": self.status.value,
            "environment_type": self.environment_type.value,
            "authorized_targets": list(self.authorized_targets),
            "excluded_targets": list(self.excluded_targets),
            "allowed_domains": list(self.allowed_domains),
            "allowed_ips": list(self.allowed_ips),
            "allowed_operations": list(self.allowed_operations),
            "forbidden_operations": list(self.forbidden_operations),
            "execution_mode": self.execution_mode,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "rate_limit_rps": self.rate_limit_rps,
            "max_concurrent": self.max_concurrent,
            "data_handling_policy": self.data_handling_policy,
        }
