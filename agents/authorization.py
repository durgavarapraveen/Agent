"""
Authorization & Audit Layer - Required for all exploitations
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class ExploitTier(Enum):
    """Exploitation tiers by impact"""
    POC = 1          # Read-only proof, no side effects
    SHALLOW = 2      # Low impact, reversible (test accounts, temp files)
    DEEP = 3         # High impact, irreversible (RCE, data exfil)


class AuthorizationManager:
    """
    Verifies authorization before ANY exploitation.
    Maintains audit trail for compliance.
    """

    def __init__(self, scope_file: str = ".pentest_scope.json", audit_dir: str = ".audit_logs"):
        self.scope_file = Path(scope_file)
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(exist_ok=True)
        self.scope = self._load_scope()

    def _load_scope(self) -> Dict:
        """Load authorized domains and scopes"""
        if not self.scope_file.exists():
            logger.warning(f"Scope file not found: {self.scope_file}")
            return {}

        try:
            with open(self.scope_file, 'r') as f:
                scope = json.load(f)
                logger.info(f"Loaded scope: {len(scope.get('domains', []))} authorized domains")
                return scope
        except Exception as e:
            logger.error(f"Failed to load scope: {e}")
            return {}

    def verify_domain(self, domain: str) -> bool:
        """Check if domain is authorized"""
        authorized = self.scope.get("domains", [])
        for auth_domain in authorized:
            if domain.endswith(auth_domain):
                return True
        logger.warning(f"Domain NOT authorized: {domain}")
        return False

    def verify_tier(self, tier: ExploitTier) -> bool:
        """Check if tier is allowed"""
        allowed = self.scope.get("max_tier", "POC")
        allowed_num = {"POC": 1, "SHALLOW": 2, "DEEP": 3}.get(allowed, 1)
        return tier.value <= allowed_num

    async def authorize_exploit(
        self,
        domain: str,
        vuln_type: str,
        tier: ExploitTier,
        payload: str,
        require_approval: bool = True
    ) -> bool:
        """
        Full authorization check before exploitation.
        Logs intent even if denied.
        """

        # 1. Check domain
        if not self.verify_domain(domain):
            self._log_denied(domain, vuln_type, tier, "Domain not in scope")
            return False

        # 2. Check tier
        if not self.verify_tier(tier):
            self._log_denied(domain, vuln_type, tier, "Tier exceeds authorization")
            return False

        # 3. Manual approval for high-impact
        if require_approval and tier == ExploitTier.DEEP:
            user_input = input(f"\n⚠️  DEEP EXPLOITATION REQUIRED\n"
                               f"Domain: {domain}\n"
                               f"Vuln: {vuln_type}\n"
                               f"Payload: {payload[:100]}...\n"
                               f"\nType 'AUTHORIZE' to proceed: ").strip()
            if user_input != "AUTHORIZE":
                self._log_denied(domain, vuln_type, tier, "User rejected")
                return False

        # 4. Log approval
        self._log_approved(domain, vuln_type, tier, payload)
        return True

    def _log_approved(self, domain: str, vuln_type: str, tier: ExploitTier, payload: str):
        """Log approved exploit"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "APPROVED",
            "domain": domain,
            "vuln_type": vuln_type,
            "tier": tier.name,
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "payload_preview": payload[:200],
        }
        self._write_audit_log(entry)
        logger.info(f"✓ Exploit AUTHORIZED: {domain} / {vuln_type} ({tier.name})")

    def _log_denied(self, domain: str, vuln_type: str, tier: ExploitTier, reason: str):
        """Log denied exploit"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "DENIED",
            "domain": domain,
            "vuln_type": vuln_type,
            "tier": tier.name,
            "reason": reason,
        }
        self._write_audit_log(entry)
        logger.warning(f"✗ Exploit DENIED: {domain} / {reason}")

    def log_exploit_execution(self, domain: str, vuln_id: str, payload: str, result: Dict):
        """Log actual exploit execution"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "EXECUTED",
            "domain": domain,
            "vuln_id": vuln_id,
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "result": result,
            "success": result.get("success", False),
        }
        self._write_audit_log(entry)
        logger.info(f"Exploit executed: {vuln_id} → {result.get('success', False)}")

    def _write_audit_log(self, entry: Dict):
        """Append to audit log file"""
        ts = datetime.now().strftime("%Y%m%d")
        log_file = self.audit_dir / f"exploits_{ts}.jsonl"
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry, default=str) + "\n")

    @staticmethod
    def create_scope_file(
        domains: List[str],
        max_tier: str = "POC",
        output_file: str = ".pentest_scope.json"
    ):
        """Create scope file for authorized testing"""
        scope = {
            "created": datetime.now().isoformat(),
            "domains": domains,
            "max_tier": max_tier,  # POC, SHALLOW, DEEP
            "note": "Authorized domains for penetration testing",
        }
        with open(output_file, 'w') as f:
            json.dump(scope, f, indent=2)
        print(f"Scope file created: {output_file}")
        print(f"Domains: {domains}")
        print(f"Max tier: {max_tier}")


# Example usage
if __name__ == "__main__":
    # Create scope file
    AuthorizationManager.create_scope_file(
        domains=["example.com", "test.example.com", "preview.owasp-juice.shop"],
        max_tier="SHALLOW",  # Can test, but no RCE
    )

    # Use in agents
    auth = AuthorizationManager()
    print(auth.verify_domain("api.example.com"))  # True
    print(auth.verify_domain("attacker.com"))     # False