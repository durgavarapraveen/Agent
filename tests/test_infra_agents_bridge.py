"""Infra-agents → planner bridge: config-driven collection + scope gating."""
import json

import pytest

from core.orchestration.infra_agents import collect_infra_findings, to_attack_chains


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


def test_to_attack_chains_is_report_and_repo_shaped():
    paths = [{
        "attack_path_id": "p1", "objective": "Obtain cluster-admin",
        "starting_position": "ServiceAccount:kube-system/ci", "target": "cluster",
        "severity": "CRITICAL", "status": "hypothesized",
        "steps": [{"action": "assume_subject", "target": "ci"},
                  {"action": "abuse_grant", "target": "cluster"}],
        "techniques": ["K8sRBACAbuse"], "evidence": "e",
        "detection_confidence": 0.9, "exploit_confidence": 0.8,
        "source": "k8s_attack_path",
    }]
    chains = to_attack_chains(paths)
    c = chains[0]
    # AttackGraphRepo.bulk_upsert fields
    assert c["chain_id"] == "p1" and c["score"] == 9.5 and c["status"] == "hypothesized"
    # report _attack_path_svg reads steps[].title; first=start, last=objective
    titles = [s["title"] for s in c["steps"]]
    assert titles[0] == "ServiceAccount:kube-system/ci" and titles[-1] == "cluster"
    assert "assume_subject" in titles


def test_collected_paths_convert_to_chains(tmp_path):
    snap = {"clusterroles": [{"metadata": {"name": "cluster-admin"}, "kind": "ClusterRole",
                              "rules": [{"verbs": ["*"], "resources": ["*"]}]}],
            "clusterrolebindings": [{"metadata": {"name": "b"}, "kind": "ClusterRoleBinding",
                                     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                                     "subjects": [{"kind": "ServiceAccount", "name": "ci",
                                                   "namespace": "kube-system"}]}]}
    cfg = FakeCfg({"K8S_SNAPSHOT_FILE": _write(tmp_path, "k8s.json", snap),
                   "K8S_CLUSTER_ID": "c"})
    res = collect_infra_findings(cfg, {}, default_target="app")
    chains = to_attack_chains(res["attack_paths"])
    assert chains and all(ch["steps"] and ch["chain_id"] for ch in chains)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
