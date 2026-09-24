"""Kubernetes discovery (spec §3/§19) — read-only, Engagement-scoped.

Collects the cluster objects needed for RBAC/attack-path reasoning and
normalizes raw Kubernetes JSON into small, stable dicts. Fail-closed: when an
Engagement is supplied, the cluster must be an authorized resource or discovery
returns an empty inventory and refuses to touch the cluster.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.kubernetes.client import KubeClient

logger = logging.getLogger(__name__)


def _meta(obj: Dict[str, Any]) -> Dict[str, Any]:
    return obj.get("metadata", {}) or {}


def _name(obj: Dict[str, Any]) -> str:
    return _meta(obj).get("name", "") or ""


def _ns(obj: Dict[str, Any]) -> str:
    return _meta(obj).get("namespace", "") or ""


class Inventory:
    """Normalized, in-memory cluster inventory. Plain data, no behavior."""

    def __init__(self, cluster_id: str = ""):
        self.cluster_id = cluster_id
        self.namespaces: List[Dict[str, Any]] = []
        self.nodes: List[Dict[str, Any]] = []
        self.pods: List[Dict[str, Any]] = []
        self.service_accounts: List[Dict[str, Any]] = []
        self.roles: List[Dict[str, Any]] = []
        self.cluster_roles: List[Dict[str, Any]] = []
        self.role_bindings: List[Dict[str, Any]] = []
        self.cluster_role_bindings: List[Dict[str, Any]] = []
        self.secrets: List[Dict[str, Any]] = []            # names/types only
        self.config_maps: List[Dict[str, Any]] = []
        self.services: List[Dict[str, Any]] = []
        self.network_policies: List[Dict[str, Any]] = []

    def summary(self) -> Dict[str, int]:
        return {
            "cluster_id": self.cluster_id,
            "namespaces": len(self.namespaces),
            "nodes": len(self.nodes),
            "pods": len(self.pods),
            "service_accounts": len(self.service_accounts),
            "roles": len(self.roles),
            "cluster_roles": len(self.cluster_roles),
            "role_bindings": len(self.role_bindings),
            "cluster_role_bindings": len(self.cluster_role_bindings),
            "secrets": len(self.secrets),
        }


class KubernetesDiscovery:
    def __init__(self, client: KubeClient, cluster_id: str = "",
                 engagement: Optional[Any] = None):
        self.client = client
        self.cluster_id = cluster_id or "cluster"
        self.engagement = engagement

    def _authorized(self) -> bool:
        if self.engagement is None:
            return True  # no engagement bound → caller owns authorization
        try:
            return bool(self.engagement.is_resource_authorized(self.cluster_id))
        except Exception:
            return False  # fail closed

    def discover(self) -> Inventory:
        inv = Inventory(self.cluster_id)
        if not self._authorized():
            logger.warning("[k8s] cluster %r not authorized by engagement; "
                           "returning empty inventory", self.cluster_id)
            return inv

        inv.namespaces = [self._norm_named(o) for o in self.client.get("namespaces")]
        inv.nodes = [self._norm_node(o) for o in self.client.get("nodes")]
        inv.pods = [self._norm_pod(o) for o in self.client.get("pods")]
        inv.service_accounts = [self._norm_ns_named(o)
                                for o in self.client.get("serviceaccounts")]
        inv.roles = [self._norm_role(o) for o in self.client.get("roles")]
        inv.cluster_roles = [self._norm_role(o) for o in self.client.get("clusterroles")]
        inv.role_bindings = [self._norm_binding(o)
                             for o in self.client.get("rolebindings")]
        inv.cluster_role_bindings = [self._norm_binding(o)
                                     for o in self.client.get("clusterrolebindings")]
        inv.secrets = [self._norm_secret(o) for o in self.client.get("secrets")]
        inv.config_maps = [self._norm_ns_named(o) for o in self.client.get("configmaps")]
        inv.services = [self._norm_ns_named(o) for o in self.client.get("services")]
        inv.network_policies = [self._norm_ns_named(o)
                                for o in self.client.get("networkpolicies")]

        logger.info("[k8s] discovered %s", inv.summary())
        return inv

    # ── normalizers (raw k8s object → small dict) ────────────────────────
    @staticmethod
    def _norm_named(o: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": _name(o)}

    @staticmethod
    def _norm_ns_named(o: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": _name(o), "namespace": _ns(o)}

    @staticmethod
    def _norm_node(o: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": _name(o)}

    @staticmethod
    def _norm_secret(o: Dict[str, Any]) -> Dict[str, Any]:
        # Never carry secret values — name/namespace/type only (spec §22/§35).
        return {"name": _name(o), "namespace": _ns(o), "type": o.get("type", "")}

    @staticmethod
    def _norm_role(o: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": _name(o),
            "namespace": _ns(o),  # "" for ClusterRole
            "kind": o.get("kind", "Role"),
            "rules": o.get("rules", []) or [],
        }

    @staticmethod
    def _norm_binding(o: Dict[str, Any]) -> Dict[str, Any]:
        role_ref = o.get("roleRef", {}) or {}
        subjects = []
        for s in o.get("subjects", []) or []:
            subjects.append({
                "kind": s.get("kind", ""),
                "name": s.get("name", ""),
                "namespace": s.get("namespace", ""),
            })
        return {
            "name": _name(o),
            "namespace": _ns(o),  # "" for ClusterRoleBinding
            "kind": o.get("kind", "RoleBinding"),
            "role_ref": {"kind": role_ref.get("kind", ""),
                         "name": role_ref.get("name", "")},
            "subjects": subjects,
        }

    @staticmethod
    def _norm_pod(o: Dict[str, Any]) -> Dict[str, Any]:
        spec = o.get("spec", {}) or {}
        containers = []
        for c in spec.get("containers", []) or []:
            containers.append({
                "name": c.get("name", ""),
                "image": c.get("image", ""),
                "securityContext": c.get("securityContext", {}) or {},
            })
        return {
            "name": _name(o),
            "namespace": _ns(o),
            "service_account": (spec.get("serviceAccountName")
                                or spec.get("serviceAccount") or "default"),
            "host_pid": bool(spec.get("hostPID")),
            "host_network": bool(spec.get("hostNetwork")),
            "host_ipc": bool(spec.get("hostIPC")),
            "node_name": spec.get("nodeName", ""),
            "volumes": spec.get("volumes", []) or [],
            "containers": containers,
            "pod_security_context": spec.get("securityContext", {}) or {},
        }
