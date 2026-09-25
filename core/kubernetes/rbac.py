"""Kubernetes RBAC resolution + attack-path synthesis (spec §13/§14/§19).

The existing ``core.cloud.iam_privesc`` analyzers flag dangerous grants on a
*single* role's rules and escapes on a *single* pod spec, in isolation. This
module adds the reasoning a red-team agent actually needs:

1. Resolve RoleBindings / ClusterRoleBindings so we know which SUBJECT
   (ServiceAccount / user / group) effectively holds which rules.
2. Correlate pods → their ServiceAccount → that subject's effective grants.
3. Synthesize multi-step attack paths toward high-value targets: secrets,
   cluster-admin, and the node (via container escape), following
   Pod → ServiceAccount → RBAC → Secrets/API → Node.

Every conclusion is deterministic and derived from the inventory (spec §26):
the grant either exists in the resolved rules or it does not. Detection
confidence is high (the grant is present); exploit confidence is lower because
static analysis does not execute the escalation — validation is a later stage.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from core.cloud.iam_privesc import K8sRBACAnalyzer, ContainerEscapeChecker
from core.kubernetes.discovery import Inventory

logger = logging.getLogger(__name__)

# Grant → (objective, target, exploit_confidence). Keyed by (verb, resource)
# using the same normalization as _K8S_DANGEROUS.
_GRANT_IMPACT: Dict[Tuple[str, str], Tuple[str, str, float]] = {
    ("*", "*"): ("Obtain cluster-admin", "cluster", 0.8),
    ("*", "secrets"): ("Read all secrets", "secrets", 0.8),
    ("get", "secrets"): ("Read secrets → credentials", "secrets", 0.75),
    ("list", "secrets"): ("Enumerate secrets → credentials", "secrets", 0.7),
    ("create", "pods"): ("Run a workload as any ServiceAccount", "node", 0.6),
    ("create", "pods/exec"): ("Exec into running pods", "workload", 0.7),
    ("create", "daemonsets"): ("Run a pod on every node", "node", 0.6),
    ("create", "serviceaccounts/token"): ("Mint ServiceAccount tokens", "identity", 0.7),
    ("escalate", "roles"): ("Grant self arbitrary permissions", "cluster", 0.85),
    ("bind", "roles"): ("Bind a privileged role to self", "cluster", 0.85),
    ("impersonate", "users"): ("Impersonate other users/groups", "identity", 0.75),
    ("create", "clusterrolebindings"): ("Bind cluster-admin to self", "cluster", 0.9),
}


def _subject_key(kind: str, name: str, namespace: str) -> str:
    ns = namespace or "-"
    return f"{kind}:{ns}/{name}"


class RBACGraph:
    """Resolve which subjects effectively hold which RBAC rules."""

    def __init__(self, inv: Inventory):
        self.inv = inv
        # (name, namespace) → rules  for Roles; (name, "") for ClusterRoles.
        self._roles: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for r in inv.roles:
            self._roles[(r["name"], r.get("namespace", ""))] = r.get("rules", [])
        self._cluster_roles: Dict[str, List[Dict[str, Any]]] = {
            r["name"]: r.get("rules", []) for r in inv.cluster_roles
        }
        # subject_key → list of {rules, scope, via}
        self.subject_grants: Dict[str, List[Dict[str, Any]]] = {}
        self._resolve()

    def _rules_for_ref(self, ref: Dict[str, Any], binding_ns: str) -> List[Dict[str, Any]]:
        kind = (ref.get("kind") or "").strip()
        name = ref.get("name") or ""
        if kind == "ClusterRole":
            return self._cluster_roles.get(name, [])
        # Role reference resolves within the binding's namespace.
        return self._roles.get((name, binding_ns), [])

    def _resolve(self) -> None:
        bindings = (self.inv.role_bindings + self.inv.cluster_role_bindings)
        for b in bindings:
            is_cluster = b.get("kind") == "ClusterRoleBinding"
            binding_ns = "" if is_cluster else b.get("namespace", "")
            rules = self._rules_for_ref(b.get("role_ref", {}), binding_ns)
            if not rules:
                continue
            scope = "cluster" if is_cluster else f"namespace:{binding_ns}"
            for s in b.get("subjects", []):
                skind = s.get("kind", "")
                sname = s.get("name", "")
                # SA subject namespace: explicit, else the binding's namespace.
                sns = s.get("namespace", "") or (binding_ns if skind == "ServiceAccount" else "")
                key = _subject_key(skind, sname, sns)
                self.subject_grants.setdefault(key, []).append({
                    "rules": rules, "scope": scope,
                    "via_binding": b.get("name", ""),
                    "via_role": b.get("role_ref", {}).get("name", ""),
                })

    def effective_rules(self, subject_key: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for g in self.subject_grants.get(subject_key, []):
            out.extend(g["rules"])
        return out


class KubernetesAttackPathAnalyzer:
    """Turn a resolved RBACGraph + inventory into findings and attack paths."""

    def __init__(self, inv: Inventory):
        self.inv = inv
        self.graph = RBACGraph(inv)
        self._rbac = K8sRBACAnalyzer()
        self._escape = ContainerEscapeChecker()

    # ── public ───────────────────────────────────────────────────────────
    def analyze(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        paths: List[Dict[str, Any]] = []

        subj_findings, subj_paths = self._analyze_subjects()
        findings.extend(subj_findings)
        paths.extend(subj_paths)

        pod_findings, pod_paths = self._analyze_pods()
        findings.extend(pod_findings)
        paths.extend(pod_paths)

        return {
            "findings": findings,
            "attack_paths": paths,
            "inventory": self.inv.summary(),
        }

    # ── subjects (RBAC) ───────────────────────────────────────────────────
    def _analyze_subjects(self):
        findings: List[Dict[str, Any]] = []
        paths: List[Dict[str, Any]] = []
        for skey in self.graph.subject_grants:
            rules = self.graph.effective_rules(skey)
            dangerous = self._rbac.analyze_rules(rules, subject=skey)
            if not dangerous:
                continue
            findings.extend(dangerous)
            for f in dangerous:
                verb = f.get("verb", "")
                res = f.get("resource", "")
                objective, target, exploit_conf = _GRANT_IMPACT.get(
                    (verb, res), ("Escalate privileges", "cluster", 0.5))
                paths.append(self._path(
                    objective=objective,
                    start=skey,
                    target=target,
                    severity=f.get("severity", "HIGH"),
                    exploit_conf=exploit_conf,
                    steps=[
                        {"action": "assume_subject", "target": skey,
                         "precondition": "control a token/pod for this subject",
                         "tool": "k8s_rbac", "result": "subject_context"},
                        {"action": "abuse_grant", "target": target,
                         "precondition": f"{verb} {res}",
                         "tool": "kubectl", "result": objective},
                    ],
                    techniques=["ValidAccounts", "K8sRBACAbuse"],
                    evidence=f.get("proof", ""),
                ))
        return findings, paths

    # ── pods (SA linkage + escape) ────────────────────────────────────────
    def _analyze_pods(self):
        findings: List[Dict[str, Any]] = []
        paths: List[Dict[str, Any]] = []
        for pod in self.inv.pods:
            ns = pod.get("namespace", "")
            sa = pod.get("service_account", "default")
            sa_key = _subject_key("ServiceAccount", sa, ns)

            # 1) Container escape → node.
            escaped = self._pod_escapes(pod)
            findings.extend(escaped)
            if escaped:
                worst = max(escaped, key=lambda e: _sev_rank(e.get("severity")))
                paths.append(self._path(
                    objective="Escape container to the node",
                    start=f"pod:{ns}/{pod.get('name','')}",
                    target="node",
                    severity=worst.get("severity", "HIGH"),
                    exploit_conf=0.6,
                    steps=[
                        {"action": "exploit_pod", "target": pod.get("name", ""),
                         "precondition": "code execution in the pod",
                         "tool": "container_escape", "result": "node_root"},
                        {"action": "harvest_node", "target": "node",
                         "precondition": "node access",
                         "tool": "kubelet", "result": "all pods' secrets on node"},
                    ],
                    techniques=["EscapeToHost", "CredentialsFromNode"],
                    evidence="; ".join(e.get("proof", "") for e in escaped),
                ))

            # 2) Pod's ServiceAccount already holds dangerous grants → the pod
            #    is a ready foothold for that escalation.
            if self.graph.effective_rules(sa_key):
                dangerous = self._rbac.analyze_rules(
                    self.graph.effective_rules(sa_key), subject=sa_key)
                if dangerous:
                    worst = max(dangerous, key=lambda e: _sev_rank(e.get("severity")))
                    obj = _GRANT_IMPACT.get(
                        (worst.get("verb", ""), worst.get("resource", "")),
                        ("Escalate via pod ServiceAccount", "cluster", 0.6))
                    paths.append(self._path(
                        objective=f"{obj[0]} via pod ServiceAccount",
                        start=f"pod:{ns}/{pod.get('name','')}",
                        target=obj[1],
                        severity=worst.get("severity", "HIGH"),
                        exploit_conf=min(0.7, obj[2]),
                        steps=[
                            {"action": "read_sa_token", "target": sa_key,
                             "precondition": "code execution in the pod",
                             "tool": "kubectl", "result": "serviceaccount_token"},
                            {"action": "abuse_grant", "target": obj[1],
                             "precondition": worst.get("proof", ""),
                             "tool": "kubectl", "result": obj[0]},
                        ],
                        techniques=["StealSAToken", "K8sRBACAbuse"],
                        evidence=f"pod {pod.get('name','')} runs SA {sa_key}: "
                                 + worst.get("proof", ""),
                    ))
        return findings, paths

    def _pod_escapes(self, pod: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Merge pod-level host* / volumes with each container's securityContext
        and run the reused ContainerEscapeChecker."""
        out: List[Dict[str, Any]] = []
        pod_name = pod.get("name", "container")
        base = {
            "hostPID": pod.get("host_pid"),
            "hostNetwork": pod.get("host_network"),
            "volumes": pod.get("volumes", []),
        }
        for c in pod.get("containers", []) or [{}]:
            spec = dict(base)
            spec["securityContext"] = c.get("securityContext", {}) or {}
            name = f"{pod_name}/{c.get('name','')}".rstrip("/")
            out.extend(self._escape.analyze_spec(spec, name=name))
        return out

    # ── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _path(objective: str, start: str, target: str, severity: str,
              exploit_conf: float, steps: List[Dict[str, Any]],
              techniques: List[str], evidence: str) -> Dict[str, Any]:
        return {
            "attack_path_id": str(uuid.uuid4()),
            "objective": objective,
            "starting_position": start,
            "target": target,
            "severity": severity,
            "steps": steps,
            "techniques": techniques,
            "evidence": evidence,
            # Detection is certain (grant present); exploit is inferred, not run.
            "detection_confidence": 0.9,
            "exploit_confidence": round(float(exploit_conf), 2),
            "status": "hypothesized",
            "source": "k8s_attack_path",
        }


_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _sev_rank(sev: Optional[str]) -> int:
    return _SEV_ORDER.get((sev or "").upper(), 0)
