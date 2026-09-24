"""GCP provider adapter (spec §17).

Escalation is reasoned from IAM role bindings (GCP role ids carried in the
normalized identity's ``permissions``). ``SdkSource`` is the live integration
point; it imports the google-cloud SDK lazily and returns nothing when absent —
the tested path is the snapshot. No fabricated resources.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.cloud.providers.base import CloudProvider, CloudInventory, cloud_path

logger = logging.getLogger(__name__)

# GCP roles that grant project/org control or well-known privesc primitives.
_DANGEROUS_ROLES: Dict[str, str] = {
    "roles/owner": "CRITICAL",
    "roles/editor": "HIGH",
    "roles/iam.securityadmin": "CRITICAL",
    "roles/iam.serviceaccountadmin": "HIGH",
    "roles/iam.serviceaccounttokencreator": "HIGH",
    "roles/iam.serviceaccountuser": "MEDIUM",
    "roles/iam.workloadidentityuser": "HIGH",
    "roles/resourcemanager.projectiamadmin": "CRITICAL",
}


class GcpProvider(CloudProvider):
    name = "gcp"

    def _dangerous(self, roles: List[str]):
        out = []
        for r in roles or []:
            sev = _DANGEROUS_ROLES.get(str(r).strip().lower())
            if sev:
                out.append((r, sev))
        return out

    def _identity_findings(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for ident in inv.identities:
            for role, sev in self._dangerous(ident.get("permissions", [])):
                out.append(self._finding(
                    "CLOUD_IAM_PRIVESC",
                    f"GCP high-privilege role: {role}", sev,
                    ident.get("name", ident.get("id", "?")),
                    f"binding '{role}' grants broad control",
                    extra={"role": role, "provider": "gcp"}))
        return out

    def discover_attack_paths(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = list(self._exposure_paths(inv))
        for ident in inv.identities:
            name = ident.get("name", ident.get("id", "?"))
            for role, sev in self._dangerous(ident.get("permissions", [])):
                # Token-creator / SA-user enable impersonation of other SAs.
                if role.lower() in ("roles/iam.serviceaccounttokencreator",
                                    "roles/iam.serviceaccountuser",
                                    "roles/iam.workloadidentityuser"):
                    objective = "Impersonate a service account"
                    target = "service-account"
                    techniques = ["ServiceAccountImpersonation"]
                else:
                    objective = f"Escalate via GCP role '{role}'"
                    target = "project" if sev != "CRITICAL" else "organization"
                    techniques = ["CloudIAMPrivesc"]
                paths.append(cloud_path(
                    objective=objective, start=f"identity:{name}",
                    target=target, severity=sev,
                    steps=[{"action": "abuse_iam_binding", "target": target,
                            "precondition": f"holds '{role}'",
                            "tool": "gcloud", "result": "elevated_privileges"}],
                    techniques=techniques,
                    evidence=f"{name} holds '{role}'", exploit_conf=0.65))
        return paths


class SdkSource:
    """Live read-only GCP discovery (integration point).

    Returns [] until wired to google-cloud-* SDKs with credentials. Provide a
    SnapshotSource for offline analysis.
    """

    def __init__(self, credentials: Any = None, project: str = ""):
        self.credentials = credentials
        self.project = project

    def get(self, kind: str) -> List[Dict[str, Any]]:
        try:
            import google.auth  # noqa: F401  lazy soft dependency
        except Exception:
            logger.debug("[gcp] SDK not installed — provide a snapshot instead")
            return []
        logger.info("[gcp] live %s discovery not yet wired; returning []", kind)
        return []
