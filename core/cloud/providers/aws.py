"""AWS provider adapter (spec §17).

Identity privilege-escalation reasoning reuses the existing
``core.cloud.iam_privesc.IAMPrivescAnalyzer`` (permission-level AWS privesc
methods) — no duplicated rule table. Adds assume-role chaining and shared
internet-exposure paths.

Sources emit the provider-agnostic normalized identity shape::

    {"id", "name", "type": user|role, "permissions": [str],
     "can_assume": [role_id], "arn"}

``Boto3Source`` is the live integration point: read-only IAM/S3/EC2/RDS/EKS
calls, best-effort, importing boto3 lazily. It returns nothing when boto3 is
absent or the caller is unauthenticated — it never invents resources.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.cloud.iam_privesc import IAMPrivescAnalyzer
from core.cloud.providers.base import CloudProvider, CloudInventory, cloud_path

logger = logging.getLogger(__name__)


class AwsProvider(CloudProvider):
    name = "aws"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._iam = IAMPrivescAnalyzer()

    def _identity_findings(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for ident in inv.identities:
            perms = ident.get("permissions", []) or []
            if perms:
                out.extend(self._iam.analyze_permissions(
                    perms, principal=ident.get("name", ident.get("id", "?"))))
        return out

    def discover_attack_paths(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = list(self._exposure_paths(inv))

        by_id = {i.get("id"): i for i in inv.identities}
        for ident in inv.identities:
            name = ident.get("name", ident.get("id", "?"))
            perms = ident.get("permissions", []) or []

            # 1) IAM privesc via reused analyzer.
            for f in self._iam.analyze_permissions(perms, principal=name):
                paths.append(cloud_path(
                    objective=f"AWS IAM privilege escalation: {f.get('title','')}",
                    start=f"identity:{name}", target="account-admin",
                    severity=f.get("severity", "HIGH"),
                    steps=[{"action": "abuse_iam_permission", "target": "IAM",
                            "precondition": f.get("proof", ""),
                            "tool": "aws-cli", "result": "elevated_privileges"}],
                    techniques=["CloudIAMPrivesc"],
                    evidence=f.get("proof", ""), exploit_conf=0.7))

            # 2) Assume-role chain to a privileged role.
            for target_id in ident.get("can_assume", []) or []:
                tgt = by_id.get(target_id)
                if not tgt:
                    continue
                if self._is_privileged(tgt):
                    paths.append(cloud_path(
                        objective="Assume a privileged role",
                        start=f"identity:{name}",
                        target=f"role:{tgt.get('name', target_id)}",
                        severity="HIGH",
                        steps=[{"action": "sts_assume_role",
                                "target": tgt.get("name", target_id),
                                "precondition": "sts:AssumeRole permitted + trust allows",
                                "tool": "aws-cli", "result": "privileged_session"}],
                        techniques=["ValidAccounts", "AssumeRole"],
                        evidence=f"{name} can assume {tgt.get('name', target_id)}",
                        exploit_conf=0.6))
        return paths

    def _is_privileged(self, ident: Dict[str, Any]) -> bool:
        if ident.get("privileged"):
            return True
        perms = {p.lower() for p in (ident.get("permissions", []) or [])}
        return "*" in perms or "iam:*" in perms or "*:*" in perms

    # ── normalizers: accept normalized dicts OR raw boto3-ish shapes ──────
    def _normalize_identity(self, o: Dict[str, Any]) -> Dict[str, Any]:
        if "permissions" in o or "type" in o:
            return o  # already normalized
        name = o.get("UserName") or o.get("RoleName") or o.get("name", "")
        return {
            "id": o.get("Arn") or o.get("arn") or name,
            "name": name,
            "arn": o.get("Arn", ""),
            "type": "role" if o.get("RoleName") else "user",
            "permissions": [],
            "can_assume": [],
        }


class Boto3Source:
    """Live, read-only AWS discovery via boto3 (integration point).

    Best-effort: each resource kind is independent and returns [] on any error
    (missing SDK, no creds, denied API). Emits normalized dicts.
    """

    def __init__(self, session: Any = None, region: str = "us-east-1"):
        self._session = session
        self.region = region

    def _client(self, service: str):
        import boto3  # lazy — soft dependency
        if self._session is not None:
            return self._session.client(service, region_name=self.region)
        return boto3.client(service, region_name=self.region)

    def get(self, kind: str) -> List[Dict[str, Any]]:
        try:
            fn = getattr(self, f"_get_{kind}", None)
            return fn() if fn else []
        except Exception as e:  # never let one API break discovery
            logger.warning("[aws] live get %s failed: %s", kind, e)
            return []

    def _get_identities(self) -> List[Dict[str, Any]]:
        iam = self._client("iam")
        out: List[Dict[str, Any]] = []
        for u in iam.list_users().get("Users", []):
            out.append({"id": u.get("Arn"), "name": u.get("UserName"),
                        "arn": u.get("Arn"), "type": "user",
                        "permissions": self._user_perms(iam, u.get("UserName")),
                        "can_assume": []})
        for r in iam.list_roles().get("Roles", []):
            out.append({"id": r.get("Arn"), "name": r.get("RoleName"),
                        "arn": r.get("Arn"), "type": "role",
                        "permissions": [], "can_assume": []})
        return out

    @staticmethod
    def _user_perms(iam, user: str) -> List[str]:
        perms: set = set()
        try:
            for pol in iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", []):
                meta = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
                doc = iam.get_policy_version(
                    PolicyArn=pol["PolicyArn"],
                    VersionId=meta["DefaultVersionId"])["PolicyVersion"]["Document"]
                perms.update(IAMPrivescAnalyzer._doc_actions(doc))
        except Exception as e:
            logger.debug("[aws] user perms %s: %s", user, e)
        return sorted(perms)

    def _get_storage(self) -> List[Dict[str, Any]]:
        s3 = self._client("s3")
        out: List[Dict[str, Any]] = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b.get("Name", "")
            public = False
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                public = not all(cfg.get(k) for k in (
                    "BlockPublicAcls", "IgnorePublicAcls",
                    "BlockPublicPolicy", "RestrictPublicBuckets"))
            except Exception:
                public = True  # no block config → treat as potentially public
            out.append({"id": name, "name": name, "public": public,
                        "encrypted": True})
        return out

    def _get_databases(self) -> List[Dict[str, Any]]:
        rds = self._client("rds")
        out: List[Dict[str, Any]] = []
        for db in rds.describe_db_instances().get("DBInstances", []):
            out.append({
                "id": db.get("DBInstanceIdentifier"),
                "name": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine", ""),
                "public": bool(db.get("PubliclyAccessible")),
                "encrypted": bool(db.get("StorageEncrypted")),
            })
        return out

    def _get_kubernetes(self) -> List[Dict[str, Any]]:
        eks = self._client("eks")
        return [{"id": c, "name": c} for c in eks.list_clusters().get("clusters", [])]

    def _get_compute(self) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2")
        out: List[Dict[str, Any]] = []
        for res in ec2.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                out.append({
                    "id": inst.get("InstanceId"),
                    "name": inst.get("InstanceId"),
                    "public_ip": inst.get("PublicIpAddress", ""),
                    "identity": (inst.get("IamInstanceProfile", {}) or {}).get("Arn", ""),
                })
        return out

    def _get_networks(self) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2")
        return [{"id": v.get("VpcId"), "name": v.get("VpcId"),
                 "cidr": v.get("CidrBlock", "")}
                for v in ec2.describe_vpcs().get("Vpcs", [])]
