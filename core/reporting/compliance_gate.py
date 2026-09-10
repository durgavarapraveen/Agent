
import logging
from typing import Dict, List, Optional, Any

from core.security.legal_validator import LegalValidator
from core.security.audit_logger import AuditLogger
from core.memory.retention_policy import RetentionPolicy
from core.security.encryption import encrypt, decrypt
from core.reporting.compliance_mapper import ComplianceMapper

logger = logging.getLogger(__name__)


class ComplianceGate:

    def __init__(self):
        self.legal_validator = LegalValidator()
        self.audit_logger = AuditLogger()
        self.retention_policy = RetentionPolicy()
        self.compliance_mapper = ComplianceMapper()

    def pre_scan_gate(self, target_ip: str, target_domain: Optional[str] = None, force_expired: bool = False) -> bool:
        logger.info(f"[ComplianceGate] Pre-scan legal validation for target: {target_ip}")
        return self.legal_validator.validate_target(
            target_ip=target_ip,
            target_domain=target_domain,
            force_expired=force_expired
        )

    def log_scan_action(self, action: str, target: str, details: str, user: str = "system@antigravity") -> Dict[str, Any]:
        return self.audit_logger.log_event(action=action, target=target, details=details, user=user)

    def post_scan_compliance_assessment(
        self,
        vulnerabilities: List[Dict[str, Any]],
        primary_framework: str = "PCI-DSS"
    ) -> Dict[str, Any]:
        # Enrich generic vulnerabilities with Reference CVEs/CWEs first
        enriched_vulns = self.compliance_mapper.attach_cves(vulnerabilities)
        
        gaps = self.compliance_mapper.detect_compliance_gaps(enriched_vulns)
        scorecards = self.compliance_mapper.generate_scorecard(enriched_vulns)
        action_plan = self.compliance_mapper.prioritize_for_framework(enriched_vulns, primary_framework)
        evidence = self.compliance_mapper.collect_audit_evidence(vulnerabilities)

        return {
            "gap_statements": gaps,
            "scorecards": scorecards,
            "action_plan": action_plan,
            "evidence_statements": evidence
        }

    def encrypt_storage_payload(self, payload: str) -> bytes:
        return encrypt(payload.encode("utf-8"))

    def decrypt_storage_payload(self, encrypted_bytes: bytes) -> str:
        return decrypt(encrypted_bytes).decode("utf-8", errors="ignore")

    def run_scheduled_retention(self) -> Dict[str, Any]:
        return self.retention_policy.run_auto_cleanup()
