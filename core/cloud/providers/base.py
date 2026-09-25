"""Provider-independent cloud discovery interface (spec §17).

    CloudProvider
     ├── discover_accounts()
     ├── discover_identities()
     ├── discover_networks()
     ├── discover_compute()
     ├── discover_storage()
     ├── discover_databases()
     ├── discover_kubernetes()
     ├── discover_permissions()
     └── discover_attack_paths()

Discovery is read-only. Each provider reads from a ``CloudSource`` — either a
``SnapshotSource`` (an already-collected export, used offline and in tests) or a
live SDK-backed source (the integration point for a real engagement). Live
sources import their SDK lazily and return nothing when it is absent or
unauthenticated; they never fabricate resources (spec §50).

Cloud object metadata (names, tags) is UNTRUSTED data (spec §31).
"""
from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class CloudSource(Protocol):
    def get(self, kind: str) -> List[Dict[str, Any]]:
        """Return raw provider objects for ``kind`` (read-only)."""
        ...


class SnapshotSource:
    """Serve a collected cloud snapshot from memory (no live account).

    Snapshot shape: ``{"<kind>": [ <raw object dict>, ... ], ...}`` where kind is
    one of identities/networks/compute/storage/databases/kubernetes.
    """

    def __init__(self, snapshot: Dict[str, List[Dict[str, Any]]]):
        self._snap = snapshot or {}

    def get(self, kind: str) -> List[Dict[str, Any]]:
        return list(self._snap.get(kind, []) or [])


class CloudInventory:
    """Normalized, provider-agnostic inventory. Plain data."""

    def __init__(self, provider: str, account_id: str = ""):
        self.provider = provider
        self.account_id = account_id
        self.identities: List[Dict[str, Any]] = []
        self.networks: List[Dict[str, Any]] = []
        self.compute: List[Dict[str, Any]] = []
        self.storage: List[Dict[str, Any]] = []
        self.databases: List[Dict[str, Any]] = []
        self.kubernetes: List[Dict[str, Any]] = []

    def summary(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "identities": len(self.identities),
            "networks": len(self.networks),
            "compute": len(self.compute),
            "storage": len(self.storage),
            "databases": len(self.databases),
            "kubernetes": len(self.kubernetes),
        }


def cloud_path(objective: str, start: str, target: str, severity: str,
               steps: List[Dict[str, Any]], techniques: List[str],
               evidence: str, exploit_conf: float,
               detection_conf: float = 0.9) -> Dict[str, Any]:
    """Build an attack-path object (same shape as the k8s agent, spec §13)."""
    return {
        "attack_path_id": str(uuid.uuid4()),
        "objective": objective,
        "starting_position": start,
        "target": target,
        "severity": severity,
        "steps": steps,
        "techniques": techniques,
        "evidence": evidence,
        "detection_confidence": round(float(detection_conf), 2),
        "exploit_confidence": round(float(exploit_conf), 2),
        "status": "hypothesized",
        "source": "cloud_attack_path",
    }


class CloudProvider(ABC):
    """Base class: shared exposure reasoning + the discover_* contract.

    Subclasses implement ``_normalize_*`` for their raw object shapes and
    ``discover_attack_paths`` for provider-specific identity privesc; the
    internet-exposure paths are shared here.
    """

    name: str = "cloud"

    def __init__(self, source: CloudSource, account_id: str = "",
                 engagement: Optional[Any] = None):
        self.source = source
        self.account_id = account_id or "account"
        self.engagement = engagement

    # ── scope gate ────────────────────────────────────────────────────────
    def _authorized(self) -> bool:
        if self.engagement is None:
            return True
        try:
            return bool(self.engagement.is_resource_authorized(self.account_id))
        except Exception:
            return False  # fail closed

    # ── discovery (read-only) ─────────────────────────────────────────────
    def discover_accounts(self) -> List[str]:
        return [self.account_id]

    def discover_identities(self) -> List[Dict[str, Any]]:
        return [self._normalize_identity(o) for o in self.source.get("identities")]

    def discover_networks(self) -> List[Dict[str, Any]]:
        return [self._normalize_network(o) for o in self.source.get("networks")]

    def discover_compute(self) -> List[Dict[str, Any]]:
        return [self._normalize_compute(o) for o in self.source.get("compute")]

    def discover_storage(self) -> List[Dict[str, Any]]:
        return [self._normalize_storage(o) for o in self.source.get("storage")]

    def discover_databases(self) -> List[Dict[str, Any]]:
        return [self._normalize_database(o) for o in self.source.get("databases")]

    def discover_kubernetes(self) -> List[Dict[str, Any]]:
        return [self._normalize_kubernetes(o) for o in self.source.get("kubernetes")]

    def discover_permissions(self) -> Dict[str, List[str]]:
        return {i.get("id", i.get("name", "?")): i.get("permissions", [])
                for i in self.discover_identities()}

    def discover(self) -> CloudInventory:
        inv = CloudInventory(self.name, self.account_id)
        if not self._authorized():
            logger.warning("[cloud:%s] account %r not authorized by engagement; "
                           "empty inventory", self.name, self.account_id)
            return inv
        inv.identities = self.discover_identities()
        inv.networks = self.discover_networks()
        inv.compute = self.discover_compute()
        inv.storage = self.discover_storage()
        inv.databases = self.discover_databases()
        inv.kubernetes = self.discover_kubernetes()
        logger.info("[cloud:%s] discovered %s", self.name, inv.summary())
        return inv

    def run(self) -> Dict[str, Any]:
        inv = self.discover()
        paths = self.discover_attack_paths(inv)
        findings = self._exposure_findings(inv) + self._identity_findings(inv)
        return {
            "provider": self.name,
            "account_id": self.account_id,
            "inventory": inv.summary(),
            "findings": findings,
            "attack_paths": paths,
        }

    # ── shared internet-exposure reasoning ───────────────────────────────
    def _exposure_findings(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for s in inv.storage:
            if s.get("public"):
                sev = "CRITICAL" if not s.get("encrypted", True) else "HIGH"
                out.append(self._finding(
                    "CLOUD_PUBLIC_STORAGE", f"Public storage: {s.get('name')}",
                    sev, s.get("name", ""),
                    f"public={s.get('public')} encrypted={s.get('encrypted')}"))
        for d in inv.databases:
            if d.get("public"):
                out.append(self._finding(
                    "CLOUD_PUBLIC_DATABASE", f"Public database: {d.get('name')}",
                    "CRITICAL", d.get("name", ""),
                    f"engine={d.get('engine')} public=True encrypted={d.get('encrypted')}"))
        return out

    def _exposure_paths(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = []
        for s in inv.storage:
            if s.get("public"):
                paths.append(cloud_path(
                    objective="Read data from public storage",
                    start="internet", target=f"storage:{s.get('name')}",
                    severity="CRITICAL" if not s.get("encrypted", True) else "HIGH",
                    steps=[{"action": "access_public_bucket",
                            "target": s.get("name", ""),
                            "precondition": "bucket ACL/policy allows anonymous read",
                            "tool": "http", "result": "object_listing"}],
                    techniques=["ExposedStorage"],
                    evidence=f"{s.get('name')} public", exploit_conf=0.7))
        for d in inv.databases:
            if d.get("public"):
                paths.append(cloud_path(
                    objective="Reach a publicly exposed database",
                    start="internet", target=f"database:{d.get('name')}",
                    severity="CRITICAL",
                    steps=[{"action": "connect_public_db", "target": d.get("name", ""),
                            "precondition": "DB endpoint reachable from internet",
                            "tool": "db_client", "result": "auth_attempt_surface"}],
                    techniques=["ExposedService"],
                    evidence=f"{d.get('name')} public", exploit_conf=0.5))
        return paths

    @staticmethod
    def _finding(ftype: str, title: str, severity: str, location: str,
                 proof: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from core.cloud.iam_privesc import _finding
        return _finding(ftype, title, severity, location, proof,
                        "cloud_provider", extra)

    # ── provider-specific (subclasses) ───────────────────────────────────
    @abstractmethod
    def discover_attack_paths(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        ...

    def _identity_findings(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        return []

    # normalizers — subclasses override for their raw shapes; defaults assume
    # already-normalized dicts (so SnapshotSource can carry normalized data).
    def _normalize_identity(self, o: Dict[str, Any]) -> Dict[str, Any]:
        return o

    def _normalize_network(self, o: Dict[str, Any]) -> Dict[str, Any]:
        return o

    def _normalize_compute(self, o: Dict[str, Any]) -> Dict[str, Any]:
        return o

    def _normalize_storage(self, o: Dict[str, Any]) -> Dict[str, Any]:
        return o

    def _normalize_database(self, o: Dict[str, Any]) -> Dict[str, Any]:
        return o

    def _normalize_kubernetes(self, o: Dict[str, Any]) -> Dict[str, Any]:
        return o
