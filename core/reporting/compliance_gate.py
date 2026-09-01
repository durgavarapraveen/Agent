"""
Phase 6 Master Orchestrator: Compliance Gate (core/compliance_gate.py)

Wraps the entire AntiGravity scanning pipeline:
1. Pre-Scan: Call legal_validator.validate_target() – abort if out of scope or expired SOW.
2. During Scan: Audit log every action via audit_logger.log_event().
3. Post-Scan: Pass findings through compliance_mapper for gap detection & scorecards.
4. Storage: Encrypt data via encryption.encrypt() before storing.
5. Scheduled: Execute retention_policy.run_auto_cleanup().
"""

import logging
from typing import Dict, List, Optional, Any

from core.security.legal_validator import LegalValidator
from core.security.audit_logger import AuditLogger
from core.memory.retention_policy import RetentionPolicy
from core.security.encryption import encrypt, decrypt
from core.reporting.compliance_mapper import ComplianceMapper

logger = logging.getLogger(__name__)


class ComplianceGate:
    """Phase 6 Master Governance Orchestrator."""

    def __init__(self):
        self.legal_validator = LegalValidator()
        self.audit_logger = AuditLogger()
        self.retention_policy = RetentionPolicy()
        self.compliance_mapper = ComplianceMapper()

    def pre_scan_gate(self, target_ip: str, target_domain: Optional[str] = None, force_expired: bool = False) -> bool:
        """
        Pre-Scan Gate: Validate target against legal SOW scope.
        Aborts immediately with ScopeViolationException if out of scope or expired.
        """
        logger.info(f"[ComplianceGate] Pre-scan legal validation for target: {target_ip}")
        return self.legal_validator.validate_target(
            target_ip=target_ip,
            target_domain=target_domain,
            force_expired=force_expired
        )

    def log_scan_action(self, action: str, target: str, details: str, user: str = "system@antigravity") -> Dict[str, Any]:
        """During Scan: Log tamper-evident audit event."""
        return self.audit_logger.log_event(action=action, target=target, details=details, user=user)

    def post_scan_compliance_assessment(
        self,
        vulnerabilities: List[Dict[str, Any]],
        primary_framework: str = "PCI-DSS"
    ) -> Dict[str, Any]:
        """
        Post-Scan: Run compliance gap detection, generate scorecards per framework,
        build framework action plans, and collect audit-ready evidence statements.
        """
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
        """Storage: AES-256-GCM authenticated encryption for database payloads."""
        return encrypt(payload.encode("utf-8"))

    def decrypt_storage_payload(self, encrypted_bytes: bytes) -> str:
        """Storage: AES-256-GCM authenticated decryption for database payloads."""
        return decrypt(encrypted_bytes).decode("utf-8", errors="ignore")

    def run_scheduled_retention(self) -> Dict[str, Any]:
        """Scheduled: Execute data retention auto-cleanup."""
        return self.retention_policy.run_auto_cleanup()
