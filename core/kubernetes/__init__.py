"""Kubernetes red-team agent package (spec §19).

Read-only discovery + RBAC/attack-path reasoning over a cluster, Engagement
scope-gated and deterministic. Reuses core.cloud.iam_privesc primitives.
"""
from core.kubernetes.client import (
    KubeClient, SnapshotKubeClient, KubectlClient, RESOURCES,
)
from core.kubernetes.discovery import KubernetesDiscovery, Inventory
from core.kubernetes.rbac import RBACGraph, KubernetesAttackPathAnalyzer
from core.kubernetes.agent import KubernetesAgent

__all__ = [
    "KubeClient", "SnapshotKubeClient", "KubectlClient", "RESOURCES",
    "KubernetesDiscovery", "Inventory",
    "RBACGraph", "KubernetesAttackPathAnalyzer",
    "KubernetesAgent",
]
