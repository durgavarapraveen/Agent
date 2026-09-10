from __future__ import annotations

import contextvars
import logging
import threading
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

_current_tenant: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_tenant", default=""
)


class TenantIsolationViolation(Exception):
    """Raised when a tenant tries to access resources belonging to another tenant."""
    pass


def set_tenant(tenant_id: str) -> None:
    _current_tenant.set(tenant_id)


def get_tenant() -> str:
    return _current_tenant.get() or "default"


# Aliases
set_current_tenant = set_tenant
get_current_tenant = get_tenant


class TenantContext:
    """Context manager for running code within a scoped tenant boundary."""

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._token: Optional[contextvars.Token[str]] = None

    def __enter__(self) -> "TenantContext":
        self._token = _current_tenant.set(self.tenant_id)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._token is not None:
            _current_tenant.reset(self._token)


def enforce_tenant_boundary(owner_tenant: str, resource_id: str) -> None:
    """Check if the currently active tenant matches the owner_tenant."""
    current = get_current_tenant()
    if current != owner_tenant:
        raise TenantIsolationViolation(
            f"Tenant '{current}' attempted unauthorized access to resource '{resource_id}' owned by '{owner_tenant}'"
        )


class TenantBoundary:

    """Enforces tenant-scoped data boundaries.

    Every data access should be checked against the current tenant context.
    Cross-tenant access is denied and logged as a boundary violation.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tenant_scopes: Dict[str, Set[str]] = {}  # tenant_id -> set of resource_ids

    def register_resource(self, tenant_id: str, resource_id: str) -> None:
        with self._lock:
            if tenant_id not in self._tenant_scopes:
                self._tenant_scopes[tenant_id] = set()
            self._tenant_scopes[tenant_id].add(resource_id)

    def check_access(self, resource_id: str, requesting_tenant: Optional[str] = None) -> bool:
        tenant = requesting_tenant or get_tenant()
        if not tenant:
            logger.error("[TenantBoundary] No tenant context set — access denied")
            self._record_violation(tenant, resource_id)
            return False

        with self._lock:
            # Find the owner of this resource
            for owner_tenant, resources in self._tenant_scopes.items():
                if resource_id in resources:
                    if owner_tenant != tenant:
                        logger.error(
                            "[TenantBoundary] CROSS_TENANT_VIOLATION tenant=%s tried to access resource=%s owned by=%s",
                            tenant, resource_id, owner_tenant,
                        )
                        self._record_violation(tenant, resource_id)
                        return False
                    return True

        # Resource not registered — allow by default (not yet tenant-scoped)
        return True

    def _record_violation(self, tenant: str, resource_id: str) -> None:
        try:
            from core.observability.metrics import TENANT_BOUNDARY_VIOLATIONS
            TENANT_BOUNDARY_VIOLATIONS.inc()
        except ImportError:
            pass

    def get_resources(self, tenant_id: str) -> Set[str]:
        with self._lock:
            return set(self._tenant_scopes.get(tenant_id, set()))

    def delete_tenant_data(self, tenant_id: str) -> int:
        """Remove all resources scoped to a tenant. Returns count of removed resources."""
        with self._lock:
            resources = self._tenant_scopes.pop(tenant_id, set())
            count = len(resources)
            if count:
                logger.info("[TenantBoundary] Deleted %d resources for tenant=%s", count, tenant_id)
            return count


_SINGLETON: Optional[TenantBoundary] = None
_SINGLETON_LOCK = threading.Lock()


def get_tenant_boundary() -> TenantBoundary:
    global _SINGLETON
    with _SINGLETON_LOCK:
        if _SINGLETON is None:
            _SINGLETON = TenantBoundary()
        return _SINGLETON
