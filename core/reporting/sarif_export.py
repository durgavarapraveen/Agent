"""
SARIF/DAST Export — converts findings to SARIF 2.1.0 format for CI/CD integration.
Supports GitHub Security tab, GitLab SAST, Azure DevOps, and generic SARIF viewers.
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

SEVERITY_TO_SECURITY_SEVERITY = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "4.0",
    "LOW": "2.0",
    "INFO": "1.0",
}


class SARIFExporter:
    """Exports vulnerability findings in SARIF 2.1.0 format."""

    def __init__(self, tool_name: str = "AntiGravity", tool_version: str = "2.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def _make_rule_id(self, finding: Dict) -> str:
        vuln_type = (finding.get("type") or "UNKNOWN").upper().replace(" ", "_")
        cwe = finding.get("cwe_id") or ""
        if cwe:
            return f"{vuln_type}/{cwe}"
        return vuln_type

    def _make_fingerprint(self, finding: Dict) -> str:
        """Deterministic SARIF-partial fingerprint. Full SHA-256 hex is
        returned (64 chars) — the 32-char truncation used previously invited
        collisions on scans with thousands of findings and broke the
        partial-fingerprint equality semantics SARIF consumers rely on for
        result stability across runs."""
        parts = [
            finding.get("title", ""),
            finding.get("type", ""),
            finding.get("target", ""),
            finding.get("location", ""),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def _build_rules(self, findings: List[Dict]) -> List[Dict]:
        seen = {}
        rules = []
        for f in findings:
            rule_id = self._make_rule_id(f)
            if rule_id in seen:
                continue
            seen[rule_id] = True

            severity = (f.get("severity") or "INFO").upper()
            rule = {
                "id": rule_id,
                "name": (f.get("type") or "Unknown").replace("_", " ").title(),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": f.get("details") or f.get("title", "")},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note")
                },
                "properties": {
                    "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(severity, "1.0"),
                    "tags": ["security"],
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f['cwe_id'].replace('CWE-', '')}.html" if f.get("cwe_id") else "",
            }

            if f.get("cwe_id"):
                rule["properties"]["tags"].append(f["cwe_id"])
            if f.get("remediation"):
                rule["help"] = {"text": f["remediation"], "markdown": f["remediation"]}

            rules.append(rule)
        return rules

    def _build_result(self, finding: Dict, index: int) -> Dict:
        severity = (finding.get("severity") or "INFO").upper()
        target = finding.get("target") or finding.get("location") or ""

        result = {
            "ruleId": self._make_rule_id(finding),
            "ruleIndex": index,
            "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
            "message": {
                "text": finding.get("details") or finding.get("title", "No description"),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target,
                        "uriBaseId": "TARGETROOT",
                    },
                },
                "logicalLocations": [{
                    "name": finding.get("title", ""),
                    "fullyQualifiedName": target,
                    "kind": "url",
                }],
            }],
            "fingerprints": {
                "antigravity/v1": self._make_fingerprint(finding),
            },
            "partialFingerprints": {
                "primaryLocationUri": target,
            },
            "properties": {
                "confidence": finding.get("confidence_score", 0.5),
                "status": finding.get("status", "UNCONFIRMED"),
                "tool_source": finding.get("tool", ""),
            },
        }

        if finding.get("proof"):
            result["codeFlows"] = [{
                "message": {"text": "Evidence"},
                "threadFlows": [{
                    "locations": [{
                        "location": {
                            "message": {"text": str(finding["proof"])[:1000]},
                            "physicalLocation": {
                                "artifactLocation": {"uri": target},
                            },
                        },
                    }],
                }],
            }]

        if finding.get("remediation"):
            result["fixes"] = [{
                "description": {"text": finding["remediation"]},
            }]

        if finding.get("cve_id"):
            result["properties"]["cve"] = finding["cve_id"]

        return result

    def export(self, findings: List[Dict], target: str = "",
               scan_id: str = "", output_path: Optional[str] = None) -> Dict:
        """Export findings to SARIF 2.1.0 format."""
        rules = self._build_rules(findings)
        rule_id_to_index = {r["id"]: i for i, r in enumerate(rules)}

        results = []
        for f in findings:
            rule_id = self._make_rule_id(f)
            idx = rule_id_to_index.get(rule_id, 0)
            results.append(self._build_result(f, idx))

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/antigravity-security",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
                "originalUriBaseIds": {
                    "TARGETROOT": {
                        "uri": target or "https://unknown",
                        "description": {"text": "Scan target root URL"},
                    },
                },
                "properties": {
                    "scan_id": scan_id,
                    "target": target,
                    "total_findings": len(findings),
                },
            }],
        }

        if output_path:
            path = Path(output_path)
            path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
            logger.info(f"[SARIF] Exported {len(results)} findings to {output_path}")

        return sarif

    def export_gitlab_dast(self, findings: List[Dict], target: str = "",
                           scan_id: str = "", output_path: Optional[str] = None) -> Dict:
        """Export findings in GitLab DAST report format."""
        gl_vulns = []
        for f in findings:
            severity_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
            sev = severity_map.get((f.get("severity") or "INFO").upper(), "Unknown")
            vuln = {
                "id": self._make_fingerprint(f),
                "category": "dast",
                "name": f.get("title", "Unknown"),
                "message": f.get("details") or f.get("title", ""),
                "description": f.get("details", ""),
                "severity": sev,
                "confidence": "Confirmed" if f.get("status") == "CONFIRMED" else "Experimental",
                "solution": f.get("remediation", ""),
                "scanner": {"id": "antigravity", "name": self.tool_name},
                "location": {
                    "hostname": target,
                    "url": f.get("target") or f.get("location", ""),
                },
                "identifiers": [],
            }
            if f.get("cwe_id"):
                vuln["identifiers"].append({
                    "type": "cwe",
                    "name": f["cwe_id"],
                    "value": f["cwe_id"].replace("CWE-", ""),
                    "url": f"https://cwe.mitre.org/data/definitions/{f['cwe_id'].replace('CWE-', '')}.html",
                })
            if f.get("cve_id"):
                vuln["identifiers"].append({
                    "type": "cve",
                    "name": f["cve_id"],
                    "value": f["cve_id"],
                    "url": f"https://nvd.nist.gov/vuln/detail/{f['cve_id']}",
                })
            gl_vulns.append(vuln)

        report = {
            "version": "15.0.0",
            "vulnerabilities": gl_vulns,
            "scan": {
                "scanner": {"id": "antigravity", "name": self.tool_name, "version": self.tool_version},
                "type": "dast",
                "status": "success",
                "start_time": datetime.now(timezone.utc).isoformat(),
                "end_time": datetime.now(timezone.utc).isoformat(),
            },
        }

        if output_path:
            Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
            logger.info(f"[GitLabDAST] Exported {len(gl_vulns)} findings to {output_path}")

        return report
