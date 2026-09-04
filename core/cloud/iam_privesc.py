"""
Cloud IAM / RBAC privilege-escalation analysis.

IAMPrivescAnalyzer detects the well-documented AWS IAM privilege-escalation
methods (Rhino Security Labs taxonomy) from a principal's effective permissions.
K8sRBACAnalyzer flags dangerous Kubernetes RBAC permissions. ContainerEscapeChecker
applies container-escape heuristics to a container/pod spec (or the live container
the agent runs in). Each returns findings in the pipeline's standard dict shape.

Inputs are data-driven: pass exported policy/RBAC/spec JSON so no live cloud
credentials are required. When boto3 + AWS credentials are present, the analyzer
can also enumerate the current principal's permissions directly.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


def _finding(ftype, title, severity, location, proof, source, extra=None):
    f = {
        "type": ftype, "title": title, "severity": severity, "location": location,
        "proof": str(proof)[:1200], "tool": source, "source": source,
        "confidence_score": 0.85,
    }
    if extra:
        f.update(extra)
    return f


# AWS IAM privilege-escalation methods: name -> (required permissions, severity, note).
# Each entry's permission set is sufficient to escalate; wildcards match via fnmatch.
_AWS_PRIVESC_METHODS: List[Dict[str, Any]] = [
    {"name": "CreatePolicyVersion", "perms": ["iam:createpolicyversion"], "sev": "CRITICAL",
     "note": "Set a new default policy version granting admin."},
    {"name": "SetExistingDefaultPolicyVersion", "perms": ["iam:setdefaultpolicyversion"], "sev": "HIGH",
     "note": "Roll back to a more-permissive existing policy version."},
    {"name": "CreateAccessKey", "perms": ["iam:createaccesskey"], "sev": "HIGH",
     "note": "Create access keys for a more privileged user."},
    {"name": "CreateLoginProfile", "perms": ["iam:createloginprofile"], "sev": "HIGH",
     "note": "Set a console password for another user."},
    {"name": "UpdateLoginProfile", "perms": ["iam:updateloginprofile"], "sev": "HIGH",
     "note": "Reset another user's console password."},
    {"name": "AttachUserPolicy", "perms": ["iam:attachuserpolicy"], "sev": "CRITICAL",
     "note": "Attach AdministratorAccess to self."},
    {"name": "AttachGroupPolicy", "perms": ["iam:attachgrouppolicy"], "sev": "CRITICAL",
     "note": "Attach admin policy to a group you are in."},
    {"name": "AttachRolePolicy", "perms": ["iam:attachrolepolicy", "sts:assumerole"], "sev": "CRITICAL",
     "note": "Attach admin policy to an assumable role."},
    {"name": "PutUserPolicy", "perms": ["iam:putuserpolicy"], "sev": "CRITICAL",
     "note": "Inline an admin policy onto self."},
    {"name": "PutGroupPolicy", "perms": ["iam:putgrouppolicy"], "sev": "CRITICAL",
     "note": "Inline an admin policy onto your group."},
    {"name": "PutRolePolicy", "perms": ["iam:putrolepolicy", "sts:assumerole"], "sev": "CRITICAL",
     "note": "Inline an admin policy onto an assumable role."},
    {"name": "AddUserToGroup", "perms": ["iam:addusertogroup"], "sev": "HIGH",
     "note": "Add self to a privileged group."},
    {"name": "PassRole+EC2", "perms": ["iam:passrole", "ec2:runinstances"], "sev": "CRITICAL",
     "note": "Launch EC2 with a privileged instance profile."},
    {"name": "PassRole+Lambda+Invoke", "perms": ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"],
     "sev": "CRITICAL", "note": "Create/invoke a Lambda with a privileged role."},
    {"name": "PassRole+Lambda+EventTrigger", "perms": ["iam:passrole", "lambda:createfunction",
     "lambda:createeventsourcemapping"], "sev": "CRITICAL", "note": "Trigger a privileged Lambda via events."},
    {"name": "PassRole+CloudFormation", "perms": ["iam:passrole", "cloudformation:createstack"],
     "sev": "CRITICAL", "note": "Deploy a CFN stack with a privileged role."},
    {"name": "PassRole+Glue", "perms": ["iam:passrole", "glue:createdevendpoint"], "sev": "HIGH",
     "note": "Create a Glue dev endpoint assuming a privileged role."},
    {"name": "UpdateFunctionCode", "perms": ["lambda:updatefunctioncode"], "sev": "HIGH",
     "note": "Overwrite a privileged Lambda's code."},
    {"name": "AssumeRolePolicyUpdate", "perms": ["iam:updateassumerolepolicy", "sts:assumerole"],
     "sev": "CRITICAL", "note": "Rewrite a role's trust policy to assume it."},
]

# Kubernetes RBAC permission -> (severity, description). (verb, resource) pairs.
_K8S_DANGEROUS = [
    (("*", "*"), "CRITICAL", "Wildcard verb on wildcard resource = cluster admin"),
    (("create", "pods"), "HIGH", "Create pods (can mount secrets / run privileged)"),
    (("create", "pods/exec"), "CRITICAL", "Exec into pods"),
    (("get", "secrets"), "HIGH", "Read secrets"),
    (("list", "secrets"), "HIGH", "Enumerate secrets"),
    (("create", "serviceaccounts/token"), "HIGH", "Mint service-account tokens"),
    (("escalate", "roles"), "CRITICAL", "RBAC escalate grants arbitrary permissions"),
    (("bind", "roles"), "CRITICAL", "RBAC bind attaches privileged roles"),
    (("impersonate", "users"), "CRITICAL", "Impersonate other users/groups"),
    (("create", "clusterrolebindings"), "CRITICAL", "Bind cluster-admin to self"),
    (("*", "secrets"), "CRITICAL", "Full control over secrets"),
    (("create", "daemonsets"), "HIGH", "DaemonSets run on every node"),
]


class IAMPrivescAnalyzer:
    def analyze_permissions(self, permissions: List[str], principal: str = "current-principal") -> List[Dict[str, Any]]:
        """Given a flat list of allowed IAM actions, return privesc-path findings."""
        allowed = {p.lower() for p in permissions}
        findings: List[Dict[str, Any]] = []

        def _has(perm: str) -> bool:
            if perm in allowed:
                return True
            for a in allowed:
                if ("*" in a) and fnmatch.fnmatch(perm, a):
                    return True
            return False

        for method in _AWS_PRIVESC_METHODS:
            if all(_has(p) for p in method["perms"]):
                findings.append(_finding(
                    "IAM_PRIVESC",
                    f"AWS IAM privilege escalation: {method['name']}",
                    method["sev"], principal,
                    f"{method['note']} Requires: {', '.join(method['perms'])}",
                    "iam_privesc",
                    extra={"method": method["name"], "required_permissions": method["perms"]},
                ))
        if findings:
            logger.warning(f"[IAMPrivesc] {len(findings)} escalation paths for {principal}")
        return findings

    def analyze_policy_document(self, policy: Dict[str, Any], principal: str = "current-principal") -> List[Dict[str, Any]]:
        """Extract Allow actions from an IAM policy JSON and analyze them."""
        perms: Set[str] = set()
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if str(stmt.get("Effect", "")).lower() != "allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            perms.update(a.lower() for a in actions)
        return self.analyze_permissions(sorted(perms), principal)

    def analyze_live(self) -> List[Dict[str, Any]]:
        """Enumerate the current principal's permissions via boto3 (if available)."""
        try:
            import boto3  # type: ignore
        except Exception:
            logger.debug("[IAMPrivesc] boto3 not installed — skipping live enumeration")
            return []
        try:
            iam = boto3.client("iam")
            sts = boto3.client("sts")
            ident = sts.get_caller_identity()
            arn = ident.get("Arn", "current-principal")
            user = arn.split("/")[-1]
            perms: Set[str] = set()
            for pol in iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", []):
                ver = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=pol["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
                perms.update(self._doc_actions(doc))
            for name in iam.list_user_policies(UserName=user).get("PolicyNames", []):
                doc = iam.get_user_policy(UserName=user, PolicyName=name)["PolicyDocument"]
                perms.update(self._doc_actions(doc))
            return self.analyze_permissions(sorted(perms), arn)
        except Exception as e:
            logger.debug(f"[IAMPrivesc] live enumeration failed: {e}")
            return []

    @staticmethod
    def _doc_actions(doc: Dict[str, Any]) -> Set[str]:
        out: Set[str] = set()
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for s in stmts:
            if str(s.get("Effect", "")).lower() != "allow":
                continue
            acts = s.get("Action", [])
            if isinstance(acts, str):
                acts = [acts]
            out.update(a.lower() for a in acts)
        return out


class K8sRBACAnalyzer:
    def analyze_rules(self, rules: List[Dict[str, Any]], subject: str = "role") -> List[Dict[str, Any]]:
        """Analyze a list of RBAC policyRules ({verbs, resources}) for dangerous grants."""
        findings: List[Dict[str, Any]] = []
        for rule in rules or []:
            verbs = [str(v).lower() for v in (rule.get("verbs") or [])]
            resources = [str(r).lower() for r in (rule.get("resources") or [])]
            for (dverb, dres), sev, desc in _K8S_DANGEROUS:
                verb_ok = (dverb == "*" and "*" in verbs) or dverb in verbs or "*" in verbs
                res_ok = (dres == "*" and "*" in resources) or dres in resources or "*" in resources
                if verb_ok and res_ok:
                    findings.append(_finding(
                        "K8S_RBAC_PRIVESC",
                        f"Dangerous Kubernetes RBAC grant: {dverb} {dres}",
                        sev, subject,
                        f"{desc}. Rule verbs={verbs} resources={resources}",
                        "k8s_rbac",
                        extra={"verb": dverb, "resource": dres},
                    ))
        seen, unique = set(), []
        for f in findings:
            k = (f["title"], f["location"])
            if k not in seen:
                seen.add(k)
                unique.append(f)
        if unique:
            logger.warning(f"[K8sRBAC] {len(unique)} dangerous RBAC grants for {subject}")
        return unique


class ContainerEscapeChecker:
    def analyze_spec(self, spec: Dict[str, Any], name: str = "container") -> List[Dict[str, Any]]:
        """Heuristics over a container/pod spec dict for escape-prone configuration."""
        findings: List[Dict[str, Any]] = []
        sc = spec.get("securityContext", {}) or {}

        if sc.get("privileged"):
            findings.append(_finding("CONTAINER_ESCAPE", "Privileged container",
                                     "CRITICAL", name, "securityContext.privileged=true",
                                     "container_escape"))
        if sc.get("allowPrivilegeEscalation"):
            findings.append(_finding("CONTAINER_ESCAPE", "allowPrivilegeEscalation enabled",
                                     "HIGH", name, "securityContext.allowPrivilegeEscalation=true",
                                     "container_escape"))
        caps = (sc.get("capabilities", {}) or {}).get("add", []) or []
        dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH"}
        risky = [c for c in caps if str(c).upper() in dangerous_caps]
        if risky:
            findings.append(_finding("CONTAINER_ESCAPE", f"Dangerous capabilities: {risky}",
                                     "HIGH", name, f"capabilities.add={caps}", "container_escape"))
        if spec.get("hostPID"):
            findings.append(_finding("CONTAINER_ESCAPE", "hostPID namespace shared",
                                     "HIGH", name, "hostPID=true", "container_escape"))
        if spec.get("hostNetwork"):
            findings.append(_finding("CONTAINER_ESCAPE", "hostNetwork namespace shared",
                                     "MEDIUM", name, "hostNetwork=true", "container_escape"))

        for vol in spec.get("volumes", []) or []:
            hp = (vol.get("hostPath", {}) or {}).get("path", "")
            if hp in ("/", "/var/run/docker.sock", "/proc", "/var/lib/kubelet"):
                findings.append(_finding("CONTAINER_ESCAPE", f"Sensitive hostPath mount: {hp}",
                                         "CRITICAL" if ("docker.sock" in hp or hp == "/") else "HIGH",
                                         name, f"hostPath volume mounts {hp}", "container_escape"))
        return findings

    def analyze_live(self) -> List[Dict[str, Any]]:
        """Best-effort checks from inside the container the agent runs in."""
        findings: List[Dict[str, Any]] = []
        try:
            if os.path.exists("/var/run/docker.sock"):
                findings.append(_finding("CONTAINER_ESCAPE", "docker.sock present in container",
                                         "CRITICAL", "self", "/var/run/docker.sock is mounted",
                                         "container_escape"))
        except Exception as e:
            logger.debug(f"[ContainerEscape] live check error: {e}")
        return findings


class CloudPrivescScanner:
    """Runs whichever cloud analyses have input available and returns findings."""

    def __init__(self):
        self.iam = IAMPrivescAnalyzer()
        self.k8s = K8sRBACAnalyzer()
        self.container = ContainerEscapeChecker()

    def scan(
        self,
        iam_policy_file: Optional[str] = None,
        iam_permissions: Optional[List[str]] = None,
        k8s_rbac_file: Optional[str] = None,
        container_spec_file: Optional[str] = None,
        enumerate_live: bool = False,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if iam_permissions:
            findings.extend(self.iam.analyze_permissions(iam_permissions))
        if iam_policy_file and os.path.exists(iam_policy_file):
            try:
                with open(iam_policy_file, "r", encoding="utf-8") as f:
                    findings.extend(self.iam.analyze_policy_document(json.load(f)))
            except Exception as e:
                logger.warning(f"[CloudPrivesc] IAM policy file error: {e}")
        if k8s_rbac_file and os.path.exists(k8s_rbac_file):
            try:
                with open(k8s_rbac_file, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                rules = doc.get("rules") or doc.get("Rules") or []
                findings.extend(self.k8s.analyze_rules(rules, subject=doc.get("metadata", {}).get("name", "role")))
            except Exception as e:
                logger.warning(f"[CloudPrivesc] K8s RBAC file error: {e}")
        if container_spec_file and os.path.exists(container_spec_file):
            try:
                with open(container_spec_file, "r", encoding="utf-8") as f:
                    findings.extend(self.container.analyze_spec(json.load(f)))
            except Exception as e:
                logger.warning(f"[CloudPrivesc] container spec file error: {e}")
        if enumerate_live:
            findings.extend(self.iam.analyze_live())
            findings.extend(self.container.analyze_live())

        if findings:
            logger.info(f"[CloudPrivesc] {len(findings)} cloud privilege-escalation findings")
        return findings
