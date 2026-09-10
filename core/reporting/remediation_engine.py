
import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

FALLBACK_REMEDIATION_MAP = {
    "SQLI": "Use parameterized queries or prepared statements. Apply input validation.",
    "SQL_INJECTION": "Use parameterized queries or prepared statements. Apply input validation.",
    "XSS": "Implement output encoding (HTML entity encoding) and Content Security Policy (CSP).",
    "CROSS_SITE_SCRIPTING": "Implement output encoding (HTML entity encoding) and Content Security Policy (CSP).",
    "RCE": "Apply the latest vendor patch immediately. Restrict execution of untrusted code.",
    "REMOTE_CODE_EXECUTION": "Apply the latest vendor patch immediately. Restrict execution of untrusted code.",
    "LFI": "Sanitize file path inputs using basename verification and restrict access permissions.",
    "HEADER": "Configure missing HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
    "MISCONFIGURATION": "Review system configuration guidelines and enforce least-privilege security posture.",
}

FALLBACK_EFFORT_MAP = {
    "configuration_change": 1,
    "header": 1,
    "misconfiguration": 1,
    "library_update": 4,
    "dependency": 4,
    "application_code_fix": 16,
    "sqli": 16,
    "xss": 16,
    "rce": 16,
    "kernel_update": 40,
    "privilege_escalation": 40,
}


class RemediationEngine:

    def __init__(
        self,
        remediation_map_path: str = "data/remediation_map.csv",
        patch_effort_path: str = "data/patch_effort.csv",
        workarounds_path: str = "data/workarounds.csv",
        playbooks_dir: str = "data/playbooks",
    ):
        self.remediation_map_path = Path(remediation_map_path)
        self.patch_effort_path = Path(patch_effort_path)
        self.workarounds_path = Path(workarounds_path)
        self.playbooks_dir = Path(playbooks_dir)

        self._remediation_db: Dict[str, Dict[str, str]] = {}
        self._patch_effort_db: Dict[str, int] = {}
        self._workarounds_db: Dict[str, str] = {}

        self._load_databases()

    def _load_databases(self):
        # 1. Remediation Map
        if self.remediation_map_path.exists():
            try:
                with open(self.remediation_map_path, mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        cve = row.get("cve_id", "").strip()
                        if cve:
                            self._remediation_db[cve.upper()] = {
                                "remediation_text": row.get("remediation_text", ""),
                                "patch_version": row.get("patch_version", ""),
                                "patch_url": row.get("patch_url", ""),
                            }
            except Exception as e:
                logger.warning(f"[RemediationEngine] Remediation map load failed: {e}")

        # 2. Patch Effort
        if self.patch_effort_path.exists():
            try:
                with open(self.patch_effort_path, mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        cve = row.get("cve_id", "").strip()
                        hours = row.get("estimated_hours", "").strip()
                        if cve and hours.isdigit():
                            self._patch_effort_db[cve.upper()] = int(hours)
            except Exception as e:
                logger.warning(f"[RemediationEngine] Patch effort load failed: {e}")

        # 3. Workarounds
        if self.workarounds_path.exists():
            try:
                with open(self.workarounds_path, mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        cve = row.get("cve_id", "").strip()
                        workaround = row.get("workaround", row.get("details", "")).strip()
                        if cve and workaround:
                            self._workarounds_db[cve.upper()] = workaround
            except Exception as e:
                logger.warning(f"[RemediationEngine] Workarounds load failed: {e}")

    def get_industry_override(self, vulnerability_type: str, industry: str) -> Optional[str]:
        if not industry:
            return None

        ind_clean = industry.strip().lower()
        override_file = self.playbooks_dir / ind_clean / "remediation_override.csv"
        if not override_file.exists():
            return None

        try:
            vuln_upper = vulnerability_type.upper()
            default_override = None
            with open(override_file, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    vtype = row.get("vulnerability_type", "").strip().upper()
                    rec = row.get("override_recommendation", "").strip()
                    if vtype == "DEFAULT":
                        default_override = rec
                    elif vtype in vuln_upper or vuln_upper in vtype:
                        return rec
            return default_override
        except Exception as e:
            logger.warning(f"[RemediationEngine] Playbook load failed for {industry}: {e}")
            return None

    def get_remediation_text(self, finding: Dict[str, Any], industry: Optional[str] = None) -> str:
        vuln_type = str(finding.get("type") or finding.get("title") or "MISCONFIGURATION")

        # Industry playbook override
        if industry:
            override = self.get_industry_override(vuln_type, industry)
            if override:
                return override

        # CVE database lookup
        cve = str(finding.get("cve") or finding.get("cve_id") or "").strip().upper()
        if cve and cve in self._remediation_db:
            return self._remediation_db[cve]["remediation_text"]

        # Vulnerability type fallback
        vuln_upper = vuln_type.upper()
        for key, text in FALLBACK_REMEDIATION_MAP.items():
            if key in vuln_upper:
                return text

        return "Apply vendor security patch and implement input validation and least-privilege security controls."

    def estimate_patch_effort(self, finding: Dict[str, Any]) -> int:
        cve = str(finding.get("cve") or finding.get("cve_id") or "").strip().upper()
        if cve and cve in self._patch_effort_db:
            return self._patch_effort_db[cve]

        fix_type = str(finding.get("fix_type") or finding.get("type") or finding.get("title") or "").lower()

        for key, hours in FALLBACK_EFFORT_MAP.items():
            if key in fix_type:
                return hours

        sev = str(finding.get("severity", "MEDIUM")).upper()
        if sev == "CRITICAL":
            return 16
        elif sev == "HIGH":
            return 8
        elif sev == "MEDIUM":
            return 4
        return 1

    def calculate_total_remediation_hours(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        return sum(self.estimate_patch_effort(v) for v in vulnerabilities)

    def check_workaround(self, finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
        patch_available = finding.get("patch_available", True)
        cve = str(finding.get("cve") or finding.get("cve_id") or "").strip().upper()
        is_zero_day = finding.get("is_zero_day") or "zero-day" in str(finding.get("details", "")).lower()

        if not patch_available or is_zero_day or (cve and cve in self._workarounds_db):
            workaround_text = self._workarounds_db.get(cve) or finding.get("workaround") or "Apply temporary firewall rules and restrict network access to affected service."
            return {
                "workaround": workaround_text,
                "warning": "WARNING: No vendor patch available. Use workaround as temporary mitigation.",
                "is_zero_day": is_zero_day
            }

        return None

    def enrich_finding_remediation(self, finding: Dict[str, Any], industry: Optional[str] = None) -> Dict[str, Any]:
        item = dict(finding)
        item["remediation"] = self.get_remediation_text(item, industry=industry)
        item["estimated_hours"] = self.estimate_patch_effort(item)
        workaround_info = self.check_workaround(item)
        if workaround_info:
            item["workaround_info"] = workaround_info
        return item
