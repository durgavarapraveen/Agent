"""
Phase 6 Module 6.5: Framework-Specific Compliance Mapper (core/compliance_mapper.py)

YAML control mapping loader, automated gap detection, per-framework compliance scorecards,
primary framework prioritization, and audit-ready evidence collection statements.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

DEFAULT_COMPLIANCE_MAPPINGS = {
    "GDPR": [
        {"control": "Art. 32 - Security of Processing", "finding_types": ["Open S3 Bucket", "No Encryption", "Weak Password", "SQLI", "RCE"]},
        {"control": "Art. 33 - Breach Notification", "finding_types": ["Data Leak", "Exposed PII", "LFI", "INFO_DISCLOSURE"]}
    ],
    "HIPAA": [
        {"control": "164.312(a) - Access Control", "finding_types": ["Weak Authentication", "Default Credentials", "AUTH", "MISCONFIGURATION"]},
        {"control": "164.312(e) - Encryption", "finding_types": ["Missing TLS", "HTTP Not HTTPS", "HEADER", "NO_ENCRYPTION"]}
    ],
    "PCI-DSS": [
        {"control": "Requirement 3.2 - Protect Cardholder Data", "finding_types": ["Credit Card in Logs", "No Encryption", "EXPOSED_PII"]},
        {"control": "Requirement 6.6 - WAF/Code Review", "finding_types": ["SQLI", "XSS", "RCE", "LFI"]}
    ],
    "ISO-27001": [
        {"control": "A.12.6.1 - Management of Technical Vulnerabilities", "finding_types": ["Outdated Software", "Missing Patch", "SQLI", "RCE"]},
        {"control": "A.9.4.2 - Secure Log-on Procedures", "finding_types": ["Default Credentials", "No MFA", "AUTH"]}
    ]
}


class ComplianceMapper:
    """Framework-specific compliance mapper and evidence generator."""

    def __init__(self, mapping_file_path: str = "data/compliance_mappings.yaml"):
        self.mapping_file_path = Path(mapping_file_path)
        self.mappings = self._load_mappings()

    def _load_mappings(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load YAML compliance mapping file if available."""
        if self.mapping_file_path.exists():
            try:
                import yaml
                with open(self.mapping_file_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                    if loaded:
                        return loaded
            except Exception as e:
                logger.warning(f"[ComplianceMapper] YAML load error: {e}")
        return DEFAULT_COMPLIANCE_MAPPINGS

    def map_finding(self, finding: Dict[str, Any], framework: str = "PCI-DSS") -> Dict[str, str]:
        """Map a single finding to a specific framework requirement."""
        fw_clean = framework.upper().replace("-", "")
        for fw_key, controls in self.mappings.items():
            if fw_clean in fw_key.upper().replace("-", ""):
                vtype = str(finding.get("type") or finding.get("title") or "").upper()
                for c in controls:
                    types = [t.upper() for t in c.get("finding_types", [])]
                    if any(t in vtype for t in types):
                        return {
                            "framework": fw_key,
                            "control_id": c["control"],
                            "description": f"Violates {c['control']} control requirement."
                        }
                first_control = controls[0]["control"] if controls else "General Control"
                return {"framework": fw_key, "control_id": first_control, "description": f"Violates {first_control}"}

        return {"framework": framework, "control_id": "General Security Control", "description": "General vulnerability"}

    def detect_compliance_gaps(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Generate automated gap statements per finding:
        e.g., "CVE-2023-12345 (SQLi) violates PCI-DSS Requirement 6.6, GDPR Art. 32, ISO-27001 A.12.6.1."
        """
        gap_statements = []
        for v in vulnerabilities:
            cve = v.get("cve") or v.get("id") or "VULN"
            vtype = v.get("type") or v.get("title") or "Security Finding"
            violated = []

            for fw, controls in self.mappings.items():
                for c in controls:
                    types = [t.upper() for t in c.get("finding_types", [])]
                    if any(t in str(vtype).upper() for t in types):
                        violated.append(f"{fw} {c['control']}")

            if violated:
                gap_statements.append(f"{cve} ({vtype}) violates {', '.join(set(violated))}.")
            else:
                gap_statements.append(f"{cve} ({vtype}) violates PCI-DSS Requirement 6.6, GDPR Art. 32.")

        return gap_statements

    def generate_scorecard(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Compliance Scorecard (Per Framework):
          total_controls_tested
          controls_passed
          controls_failed
          compliance_percentage = (passed / tested) * 100
        """
        scorecards = {}
        vuln_types = set(str(v.get("type") or v.get("title") or "").upper() for v in vulnerabilities)

        for fw, controls in self.mappings.items():
            total_tested = len(controls)
            failed_count = 0
            passed_count = 0

            for c in controls:
                ftypes = [t.upper() for t in c.get("finding_types", [])]
                if any(any(t in vt for vt in vuln_types) for t in ftypes):
                    failed_count += 1
                else:
                    passed_count += 1

            pct = round((passed_count / max(1, total_tested)) * 100.0) if total_tested > 0 else 100
            scorecards[fw] = {
                "framework": fw,
                "total_controls_tested": total_tested,
                "controls_passed": passed_count,
                "controls_failed": failed_count,
                "compliance_percentage": pct,
                "display_text": f"{fw} Compliance: {pct}% ({passed_count} of {total_tested} controls passed)."
            }

        return scorecards

    def prioritize_for_framework(self, vulnerabilities: List[Dict[str, Any]], primary_framework: str = "PCI-DSS") -> List[str]:
        """
        Generate primary framework prioritized action plan:
        e.g., "PCI-DSS Violations: Fix SQLi (Requirement 6.6), implement encryption (Requirement 3.2)."
        """
        fw_scorecard = self.generate_scorecard(vulnerabilities).get(primary_framework, {})
        action_plan = []
        action_plan.append(f"== {primary_framework} PRIORITIZED COMPLIANCE ACTION PLAN ==")

        for v in vulnerabilities:
            vtype = str(v.get("type") or v.get("title") or "VULN")
            mapping = self.map_finding(v, primary_framework)
            action_plan.append(f"- Fix {vtype} to remediate {primary_framework} {mapping['control_id']}")

        return action_plan

    def collect_audit_evidence(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Audit-Ready Evidence Collection:
        For passing controls (no findings), generate boilerplate evidence statement:
        "Control A.12.6.1 (Patch Management) was tested on 2026-08-28. No out-of-date critical software detected."
        """
        today_str = datetime.now().strftime("%Y-%m-%d")
        evidence = []
        scorecards = self.generate_scorecard(vulnerabilities)

        for fw, controls in self.mappings.items():
            vuln_types = set(str(v.get("type") or v.get("title") or "").upper() for v in vulnerabilities)
            for c in controls:
                ftypes = [t.upper() for t in c.get("finding_types", [])]
                if not any(any(t in vt for vt in vuln_types) for t in ftypes):
                    stmt = f"Control {c['control']} was tested on {today_str}. No related security gaps or compliance violations detected."
                    evidence.append(stmt)

        return evidence
