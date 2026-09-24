"""Azure provider adapter (spec §17).

Identity escalation is reasoned from role assignments (Azure RBAC role names
carried in the normalized identity's ``permissions``). ``SdkSource`` is the live
integration point; it imports the Azure SDK lazily and returns nothing when the
SDK is absent — the tested path is the snapshot. No fabricated resources.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.cloud.providers.base import CloudProvider, CloudInventory, cloud_path

logger = logging.getLogger(__name__)

# Azure built-in roles that grant (or can be leveraged into) tenant/sub control.
_DANGEROUS_ROLES: Dict[str, str] = {
    "owner": "CRITICAL",
    "contributor": "HIGH",
    "user access administrator": "CRITICAL",
    "role based access control administrator": "CRITICAL",
    "key vault administrator": "HIGH",
    "storage account contributor": "HIGH",
    "global administrator": "CRITICAL",
}


class AzureProvider(CloudProvider):
    name = "azure"

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
                    f"Azure high-privilege role: {role}", sev,
                    ident.get("name", ident.get("id", "?")),
                    f"role assignment '{role}' grants broad control",
                    extra={"role": role, "provider": "azure"}))
        return out

    def discover_attack_paths(self, inv: CloudInventory) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = list(self._exposure_paths(inv))
        for ident in inv.identities:
            name = ident.get("name", ident.get("id", "?"))
            for role, sev in self._dangerous(ident.get("permissions", [])):
                target = "tenant" if sev == "CRITICAL" else "subscription"
                paths.append(cloud_path(
                    objective=f"Escalate via Azure role '{role}'",
                    start=f"identity:{name}", target=target, severity=sev,
                    steps=[{"action": "abuse_role_assignment", "target": target,
                            "precondition": f"holds role '{role}'",
                            "tool": "az-cli", "result": "elevated_privileges"}],
                    techniques=["CloudIAMPrivesc"],
                    evidence=f"{name} holds '{role}'", exploit_conf=0.65))
        return paths


class SdkSource:
    """Live read-only Azure discovery (integration point).

    Returns [] until wired to azure-identity / azure-mgmt-* SDKs with a
    credential. Provide a SnapshotSource for offline analysis.
    """

    def __init__(self, credential: Any = None, subscription_id: str = ""):
        self.credential = credential
        self.subscription_id = subscription_id

    def get(self, kind: str) -> List[Dict[str, Any]]:
        try:
            import azure.identity  # noqa: F401  lazy soft dependency
        except Exception:
            logger.debug("[azure] SDK not installed — provide a snapshot instead")
            return []
        # Integration point: map azure-mgmt-* results to the normalized shape.
        logger.info("[azure] live %s discovery not yet wired; returning []", kind)
        return []
