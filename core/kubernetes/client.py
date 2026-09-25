"""Read-only Kubernetes clients (spec §19).

Discovery is strictly read-only: the only verb ever issued is ``get``. Two
backends implement the same tiny surface:

* ``SnapshotKubeClient`` — serves an in-memory inventory dict. Used for offline
  analysis of a previously-collected snapshot and for deterministic tests. No
  cluster required.
* ``KubectlClient`` — shells ``kubectl get <resource> -o json`` against a live
  cluster. The verb is hard-coded; the class refuses to build any mutating
  command. This is the integration point for a real engagement — it does not
  fabricate data, it returns exactly what the cluster reports (or nothing).

Both return a list of raw Kubernetes object dicts (the ``items`` of a List),
which ``KubernetesDiscovery`` normalizes. Cluster content is UNTRUSTED data
(spec §31): names, annotations and labels may be attacker-controlled and are
never treated as instructions.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# Resource kinds discovery understands. Kept explicit so a client never issues
# an unbounded/ambiguous query.
RESOURCES = (
    "namespaces", "nodes", "pods", "serviceaccounts",
    "roles", "clusterroles", "rolebindings", "clusterrolebindings",
    "secrets", "configmaps", "services", "networkpolicies",
)


@runtime_checkable
class KubeClient(Protocol):
    def get(self, resource: str, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return the raw object dicts for ``resource`` (read-only)."""
        ...


class SnapshotKubeClient:
    """Serve a collected cluster snapshot from memory (no live cluster).

    Snapshot shape::

        {"<resource>": [ <raw k8s object dict>, ... ], ...}

    e.g. {"pods": [...], "clusterrolebindings": [...]}. Namespaced ``get`` with
    a ``namespace`` filters by ``metadata.namespace``.
    """

    def __init__(self, snapshot: Dict[str, List[Dict[str, Any]]]):
        self._snap = snapshot or {}

    def get(self, resource: str, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._snap.get(resource, []) or [])
        if namespace:
            items = [o for o in items
                     if (o.get("metadata", {}) or {}).get("namespace") == namespace]
        return items


class KubectlClient:
    """Live read-only client via the ``kubectl`` binary.

    Never constructs a mutating command — the subcommand is always ``get`` and
    the output format is JSON. Requires ``kubectl`` on PATH and a working
    kubeconfig/context; otherwise ``get`` returns an empty list and logs why.
    """

    def __init__(self, kubeconfig: Optional[str] = None,
                 context: Optional[str] = None, timeout: int = 60):
        self.kubeconfig = kubeconfig
        self.context = context
        self.timeout = max(5, int(timeout))

    def available(self) -> bool:
        return shutil.which("kubectl") is not None

    def _base_cmd(self) -> List[str]:
        cmd = ["kubectl"]
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        if self.context:
            cmd += ["--context", self.context]
        return cmd

    def get(self, resource: str, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        if resource not in RESOURCES:
            logger.debug("[kubectl] refusing unknown resource %r", resource)
            return []
        if not self.available():
            logger.warning("[kubectl] binary not found on PATH; cannot discover %s", resource)
            return []
        cmd = self._base_cmd() + ["get", resource, "-o", "json"]
        # Cluster-scoped resources reject --all-namespaces.
        cluster_scoped = {"namespaces", "nodes", "clusterroles", "clusterrolebindings"}
        if resource not in cluster_scoped:
            if namespace:
                cmd += ["-n", namespace]
            else:
                cmd += ["--all-namespaces"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("[kubectl] get %s failed: %s", resource, e)
            return []
        if proc.returncode != 0:
            logger.warning("[kubectl] get %s rc=%s: %s", resource,
                           proc.returncode, (proc.stderr or "").strip()[:300])
            return []
        try:
            doc = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            logger.warning("[kubectl] get %s: bad JSON: %s", resource, e)
            return []
        return list(doc.get("items", []) or [])
