"""Kubernetes red-team agent (spec §19) — deterministic, scope-gated.

Orchestrates read-only discovery → RBAC resolution → attack-path synthesis and
returns a structured result (spec §7: structured state, not natural language).
No LLM is in the core decision path; cluster content is treated as untrusted
data (spec §31). The agent never mutates the cluster.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.kubernetes.client import KubeClient, SnapshotKubeClient, KubectlClient
from core.kubernetes.discovery import KubernetesDiscovery
from core.kubernetes.rbac import KubernetesAttackPathAnalyzer

logger = logging.getLogger(__name__)


class KubernetesAgent:
    def __init__(self, client: KubeClient, cluster_id: str = "cluster",
                 engagement: Optional[Any] = None):
        self.client = client
        self.cluster_id = cluster_id
        self.engagement = engagement

    @classmethod
    def from_snapshot(cls, snapshot: Dict[str, Any], cluster_id: str = "cluster",
                      engagement: Optional[Any] = None) -> "KubernetesAgent":
        return cls(SnapshotKubeClient(snapshot), cluster_id, engagement)

    @classmethod
    def from_kubeconfig(cls, kubeconfig: Optional[str] = None,
                        context: Optional[str] = None, cluster_id: str = "cluster",
                        engagement: Optional[Any] = None) -> "KubernetesAgent":
        return cls(KubectlClient(kubeconfig=kubeconfig, context=context),
                   cluster_id, engagement)

    def run(self) -> Dict[str, Any]:
        """Discover + analyze. Returns findings, attack_paths, inventory summary."""
        discovery = KubernetesDiscovery(self.client, self.cluster_id, self.engagement)
        inv = discovery.discover()
        result = KubernetesAttackPathAnalyzer(inv).analyze()
        result["cluster_id"] = self.cluster_id
        logger.info("[k8s-agent] %s: %d findings, %d attack paths",
                    self.cluster_id, len(result["findings"]),
                    len(result["attack_paths"]))
        return result
