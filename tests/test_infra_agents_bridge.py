"""Infra-agents → planner bridge: config-driven collection + scope gating."""
import json

import pytest

from core.orchestration.infra_agents import collect_infra_findings


class FakeCfg:
    """Minimal settings-facade stand-in (get / get_bool)."""

    def __init__(self, values):
        self._v = values

    def get(self, key, default=None):
        return self._v.get(key, default)

    def get_bool(self, key, default=False):
        return bool(self._v.get(key, default))


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")
    return str(p)


def test_no_config_runs_nothing():
    res = collect_infra_findings(FakeCfg({}), {}, default_target="app")
    assert res == {"findings": [], "attack_paths": [], "ran": []}


def test_kubernetes_snapshot_wired(tmp_path):
    snap = {
        "clusterroles": [{"metadata": {"name": "cluster-admin"}, "kind": "ClusterRole",
                          "rules": [{"verbs": ["*"], "resources": ["*"]}]}],
        "clusterrolebindings": [{"metadata": {"name": "b"}, "kind": "ClusterRoleBinding",
                                 "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                                 "subjects": [{"kind": "ServiceAccount", "name": "ci",
                                               "namespace": "kube-system"}]}],
    }
    cfg = FakeCfg({"K8S_SNAPSHOT_FILE": _write(tmp_path, "k8s.json", snap),
                   "K8S_CLUSTER_ID": "prod-cluster"})
    res = collect_infra_findings(cfg, {}, default_target="app")
    assert "kubernetes" in res["ran"]
    assert any(p["target"] == "cluster" for p in res["attack_paths"])


def test_cloud_snapshot_wired(tmp_path):
    snap = {"identities": [{"id": "u", "name": "dev", "type": "user",
                            "permissions": ["iam:createpolicyversion"]}]}
    cfg = FakeCfg({"CLOUD_PROVIDER": "aws",
                   "CLOUD_SNAPSHOT_FILE": _write(tmp_path, "aws.json", snap),
                   "CLOUD_ACCOUNT_ID": "acct-1"})
    res = collect_infra_findings(cfg, {}, default_target="app")
    assert "cloud" in res["ran"]
    assert any("privilege escalation" in p["objective"].lower() for p in res["attack_paths"])


def test_sca_wired(tmp_path):
    pom = ("<dependency><groupId>org.apache</groupId><artifactId>log4j-core</artifactId>"
           "<version>2.14.1</version></dependency>")
    advs = [{"id": "CVE-2021-44228", "ecosystem": "Maven",
             "package": "org.apache:log4j-core", "severity": "CRITICAL",
             "ranges": [{"introduced": "2.0.0", "fixed": "2.17.0"}]}]
    cfg = FakeCfg({
        "SCA_FILES": _write(tmp_path, "pom.xml", pom),
        "SCA_ADVISORIES_FILE": _write(tmp_path, "advs.json", advs),
        "SCA_TARGET": "repo-1",
    })
    res = collect_infra_findings(cfg, {}, default_target="app")
    assert "sca" in res["ran"]
    assert any(f["type"] == "VULNERABLE_DEPENDENCY" for f in res["findings"])


def test_all_agents_merge_together(tmp_path):
    k = _write(tmp_path, "k8s.json", {"pods": []})
    a = _write(tmp_path, "aws.json", {"storage": [{"id": "b", "name": "b",
                                                   "public": True, "encrypted": False}]})
    cfg = FakeCfg({"K8S_SNAPSHOT_FILE": k, "K8S_CLUSTER_ID": "c",
                   "CLOUD_PROVIDER": "aws", "CLOUD_SNAPSHOT_FILE": a,
                   "CLOUD_ACCOUNT_ID": "acct"})
    res = collect_infra_findings(cfg, {}, default_target="app")
    assert set(res["ran"]) == {"kubernetes", "cloud"}
    assert any(p["target"] == "storage:b" for p in res["attack_paths"])


def test_empty_snapshot_yields_nothing(tmp_path):
    # The engagement built by the bridge authorizes the configured cluster id, so
    # the agent runs; an empty snapshot simply produces no findings/paths.
    empty = _write(tmp_path, "empty.json", {})
    cfg = FakeCfg({"K8S_SNAPSHOT_FILE": empty, "K8S_CLUSTER_ID": "c"})
    res = collect_infra_findings(cfg, {"domains": ["good.com"]}, default_target="good.com")
    assert res["ran"] == ["kubernetes"]
    assert res["attack_paths"] == [] and res["findings"] == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
