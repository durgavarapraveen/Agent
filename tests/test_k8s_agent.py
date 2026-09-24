"""Kubernetes agent — discovery + RBAC attack-path synthesis (spec §19)."""
import pytest

from core.domain.engagement import Engagement, EngagementStatus
from core.kubernetes import KubernetesAgent, KubernetesDiscovery, SnapshotKubeClient


def _snapshot():
    """A small but realistic cluster covering each escalation class."""
    return {
        "namespaces": [
            {"metadata": {"name": "app"}},
            {"metadata": {"name": "kube-system"}},
        ],
        "nodes": [{"metadata": {"name": "node-1"}}],
        "serviceaccounts": [
            {"metadata": {"name": "ci", "namespace": "kube-system"}},
            {"metadata": {"name": "reader", "namespace": "app"}},
            {"metadata": {"name": "deployer", "namespace": "app"}},
            {"metadata": {"name": "node-agent", "namespace": "kube-system"}},
            {"metadata": {"name": "nobody", "namespace": "app"}},
        ],
        "clusterroles": [
            {"metadata": {"name": "cluster-admin"}, "kind": "ClusterRole",
             "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]},
        ],
        "roles": [
            {"metadata": {"name": "secret-reader", "namespace": "app"}, "kind": "Role",
             "rules": [{"verbs": ["get", "list"], "resources": ["secrets"]}]},
            {"metadata": {"name": "pod-creator", "namespace": "app"}, "kind": "Role",
             "rules": [{"verbs": ["create"], "resources": ["pods"]}]},
        ],
        "clusterrolebindings": [
            {"metadata": {"name": "ci-admin"}, "kind": "ClusterRoleBinding",
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "ServiceAccount", "name": "ci",
                           "namespace": "kube-system"}]},
        ],
        "rolebindings": [
            {"metadata": {"name": "reader-rb", "namespace": "app"}, "kind": "RoleBinding",
             "roleRef": {"kind": "Role", "name": "secret-reader"},
             "subjects": [{"kind": "ServiceAccount", "name": "reader"}]},
            {"metadata": {"name": "deployer-rb", "namespace": "app"}, "kind": "RoleBinding",
             "roleRef": {"kind": "Role", "name": "pod-creator"},
             "subjects": [{"kind": "ServiceAccount", "name": "deployer"}]},
        ],
        "pods": [
            {"metadata": {"name": "web", "namespace": "app"},
             "spec": {"serviceAccountName": "reader",
                      "containers": [{"name": "web", "image": "nginx"}]}},
            {"metadata": {"name": "agent", "namespace": "kube-system"},
             "spec": {"serviceAccountName": "node-agent",
                      "containers": [{"name": "agent", "image": "agent:1",
                                      "securityContext": {"privileged": True}}]}},
            {"metadata": {"name": "idle", "namespace": "app"},
             "spec": {"serviceAccountName": "nobody",
                      "containers": [{"name": "c", "image": "busybox"}]}},
        ],
        "secrets": [
            {"metadata": {"name": "db-creds", "namespace": "app"},
             "type": "Opaque", "data": {"password": "c2VjcmV0"}},
        ],
    }


def _run(engagement=None, cluster_id="prod-cluster"):
    agent = KubernetesAgent.from_snapshot(_snapshot(), cluster_id=cluster_id,
                                          engagement=engagement)
    return agent.run()


def _objectives(paths):
    return " | ".join(p["objective"] for p in paths)


def test_cluster_admin_binding_detected():
    res = _run()
    admin = [p for p in res["attack_paths"]
             if p["target"] == "cluster" and "ServiceAccount:kube-system/ci" == p["starting_position"]]
    assert admin, _objectives(res["attack_paths"])
    assert any(p["severity"] == "CRITICAL" for p in admin)


def test_secret_reader_path():
    res = _run()
    secret_paths = [p for p in res["attack_paths"] if p["target"] == "secrets"]
    assert secret_paths
    assert any("reader" in p["starting_position"] for p in secret_paths)


def test_create_pods_path_targets_node():
    res = _run()
    assert any(p["target"] == "node" and "deployer" in p["starting_position"]
               for p in res["attack_paths"]), _objectives(res["attack_paths"])


def test_privileged_pod_escape_to_node():
    res = _run()
    escapes = [p for p in res["attack_paths"]
               if p["target"] == "node" and p["starting_position"].startswith("pod:kube-system/agent")]
    assert escapes
    assert any(p["severity"] == "CRITICAL" for p in escapes)
    # And the reused ContainerEscapeChecker produced the finding.
    assert any(f["type"] == "CONTAINER_ESCAPE" for f in res["findings"])


def test_pod_running_privileged_sa_is_a_foothold():
    res = _run()
    # pod app/web runs SA reader (get secrets) → a path starting at that pod.
    assert any(p["starting_position"].startswith("pod:app/web")
               and p["target"] == "secrets" for p in res["attack_paths"])


def test_benign_subject_and_pod_yield_no_paths():
    res = _run()
    for p in res["attack_paths"]:
        assert "nobody" not in p["starting_position"]
        assert not p["starting_position"].startswith("pod:app/idle")


def test_confidence_is_deterministic_not_inflated():
    res = _run()
    for p in res["attack_paths"]:
        assert p["detection_confidence"] == 0.9
        assert 0.0 < p["exploit_confidence"] <= 0.9
        assert p["status"] == "hypothesized"


def test_secrets_never_carry_values():
    inv = KubernetesDiscovery(SnapshotKubeClient(_snapshot()), "c").discover()
    assert inv.secrets and all("data" not in s for s in inv.secrets)
    assert all(set(s.keys()) <= {"name", "namespace", "type"} for s in inv.secrets)


def test_engagement_scope_gate_denies_unauthorized_cluster():
    eng = Engagement(name="e", status=EngagementStatus.ACTIVE,
                     allowed_kubernetes_clusters=["other-cluster"])
    res = _run(engagement=eng, cluster_id="prod-cluster")
    assert res["attack_paths"] == []
    assert res["findings"] == []
    assert res["inventory"]["pods"] == 0


def test_engagement_scope_gate_allows_authorized_cluster():
    eng = Engagement(name="e", status=EngagementStatus.ACTIVE,
                     allowed_kubernetes_clusters=["prod-cluster"])
    res = _run(engagement=eng, cluster_id="prod-cluster")
    assert res["attack_paths"], "authorized cluster should be analyzed"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
