
import logging
from typing import Dict, Any, Optional

from core.defensive.network_audit import NetworkAuditor
from core.defensive.credential_hardening import CredentialHardeningAuditor, SecretScanner
from core.defensive.persistence_monitor import PersistenceMonitor

logger = logging.getLogger(__name__)


class DefensiveRiskAssessor:

    def __init__(self, ctx: Optional[Any] = None, root_dir: str = "."):
        self.ctx = ctx
        self.root_dir = root_dir
        self.network_auditor = NetworkAuditor()
        self.cred_auditor = CredentialHardeningAuditor()
        self.secret_scanner = SecretScanner(root_dir=root_dir)
        self.persistence_monitor = PersistenceMonitor()
    def run_full_assessment(self) -> Dict[str, Any]:
        logger.info("[DefensiveRiskAssessor] Starting Defensive Architecture Audit...")

        # 1. Internal Visibility & Network Audit
        network_findings = self.network_auditor.run_full_audit()

        # 2. Credential Protection Audit
        shadow_audit = self.cred_auditor.audit_shadow_permissions()
        cred_guard_audit = self.cred_auditor.audit_windows_credential_guard()

        # 3. Secret Scanning Engine
        secret_findings = self.secret_scanner.scan_directory(max_files=300)

        # 4. Persistence Vector Monitoring & Rules
        ssh_findings = self.persistence_monitor.audit_ssh_authorized_keys()
        webshell_findings = self.persistence_monitor.audit_webshell_fim(search_dir=self.root_dir)
        sigma_rule = self.persistence_monitor.generate_sigma_rules()
        auditd_rule = self.persistence_monitor.generate_auditd_rules()

        assessment_result = {
            "network_exposure": {
                "count": len(network_findings),
                "findings": network_findings,
            },
            "credential_protection": {
                "shadow_audit": shadow_audit,
                "cred_guard_audit": cred_guard_audit,
                "secrets_detected": len(secret_findings),
                "secrets": secret_findings[:20],  # Limit output
            },
            "persistence_monitoring": {
                "ssh_findings": ssh_findings,
                "webshell_findings": webshell_findings,
                "generated_rules": {
                    "sigma_event_4698": sigma_rule,
                    "auditd_cron_rules": auditd_rule,
                }
            }
        }

        # Sync into SharedContext if present
        if self.ctx and hasattr(self.ctx, "add_vulnerability"):
            for f in network_findings:
                self.ctx.add_vulnerability({
                    "type": f.get("category", "defensive_finding"),
                    "title": f.get("title", "Defensive Finding"),
                    "severity": f.get("severity", "MEDIUM"),
                    "proof": f.get("description", ""),
                    "details": str(f.get("details", {})),
                    "remediation": f.get("remediation", ""),
                    "tool": "defensive_auditor"
                })

        logger.info(f"[DefensiveRiskAssessor] Completed assessment: "
                    f"{len(network_findings)} network risks, "
                    f"{len(secret_findings)} secrets, "
                    f"{len(webshell_findings)} webshell indicators.")

        return assessment_result
