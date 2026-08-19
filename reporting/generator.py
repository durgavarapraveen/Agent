import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from core.models import Finding

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates security assessment reports."""
    
    def __init__(self, context: Any, findings: List[Finding], discoveries: List[Dict[str, Any]]):
        self.context = context
        self.findings = findings
        self.discoveries = discoveries
        self.report_dir = Path("reports")
    
    async def generate(self):
        """Generate all report formats."""
        self.report_dir.mkdir(exist_ok=True)
        
        # Generate JSON report
        json_report = self._generate_json_report()
        await self._save_json_report(json_report)
        
        # Generate Markdown report
        md_report = self._generate_markdown_report()
        await self._save_markdown_report(md_report)
        
        logger.info(f"Reports generated in {self.report_dir}/")
    
    def _generate_json_report(self) -> Dict[str, Any]:
        """Generate JSON report structure."""
        return {
            "metadata": {
                "title": "Security Assessment Report",
                "assessor": self.context.assessor_name,
                "version": self.context.version,
                "target": self.context.target,
                "mode": self.context.mode,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": self.context.get_duration_seconds()
            },
            "executive_summary": {
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f.severity.value == "CRITICAL"]),
                "high": len([f for f in self.findings if f.severity.value == "HIGH"]),
                "medium": len([f for f in self.findings if f.severity.value == "MEDIUM"]),
                "low": len([f for f in self.findings if f.severity.value == "LOW"]),
                "info": len([f for f in self.findings if f.severity.value == "INFO"])
            },
            "scope": {
                "target": self.context.target,
                "mode": self.context.mode,
                "objectives": [self.context.objective]
            },
            "findings": [f.to_dict() for f in self.findings],
            "discoveries": self.discoveries,
            "methodology": "Autonomous multi-agent cybersecurity assessment",
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_markdown_report(self) -> str:
        """Generate Markdown report."""
        report = []
        
        report.append("# Security Assessment Report\n")
        
        report.append("## Executive Summary\n")
        report.append(f"**Target:** {self.context.target}\n")
        report.append(f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"**Assessor:** {self.context.assessor_name}\n\n")
        
        findings_summary = {
            "CRITICAL": len([f for f in self.findings if f.severity.value == "CRITICAL"]),
            "HIGH": len([f for f in self.findings if f.severity.value == "HIGH"]),
            "MEDIUM": len([f for f in self.findings if f.severity.value == "MEDIUM"]),
            "LOW": len([f for f in self.findings if f.severity.value == "LOW"]),
            "INFO": len([f for f in self.findings if f.severity.value == "INFO"])
        }
        
        report.append(f"**Total Findings:** {len(self.findings)}\n\n")
        report.append("| Severity | Count |\n")
        report.append("|----------|-------|\n")
        for severity, count in findings_summary.items():
            report.append(f"| {severity} | {count} |\n")
        
        report.append("\n## Findings\n\n")
        
        # Group findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings_for_severity = [f for f in self.findings if f.severity.value == severity]
            if not findings_for_severity:
                continue
            
            report.append(f"\n### {severity} Severity ({len(findings_for_severity)})\n\n")
            
            for finding in findings_for_severity:
                report.append(f"#### {finding.title}\n\n")
                report.append(f"**Description:** {finding.description}\n\n")
                report.append(f"**Confidence:** {finding.confidence * 100:.0f}%\n\n")
                
                if finding.affected_asset:
                    report.append(f"**Affected Asset:** {finding.affected_asset}\n\n")
                
                if finding.affected_endpoint:
                    report.append(f"**Affected Endpoint:** {finding.affected_endpoint}\n\n")
                
                if finding.cwe:
                    report.append(f"**CWE:** {finding.cwe}\n\n")
                
                if finding.cve:
                    report.append(f"**CVE:** {finding.cve}\n\n")
                
                if finding.remediation:
                    report.append(f"**Remediation:** {finding.remediation}\n\n")
                
                report.append("---\n\n")
        
        report.append("\n## Methodology\n\n")
        report.append("This assessment was conducted using an autonomous multi-agent cybersecurity framework.\n\n")
        report.append(f"**Assessment Duration:** {self.context.get_duration_seconds():.1f} seconds\n\n")
        
        report.append("\n## Recommendations\n\n")
        for i, rec in enumerate(self._generate_recommendations(), 1):
            report.append(f"{i}. {rec}\n")
        
        report.append("\n---\n")
        report.append(f"Report generated: {datetime.now().isoformat()}\n")
        
        return "".join(report)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        critical_count = len([f for f in self.findings if f.severity.value == "CRITICAL"])
        high_count = len([f for f in self.findings if f.severity.value == "HIGH"])
        
        if critical_count > 0:
            recommendations.append(
                f"Immediately address {critical_count} critical findings. "
                "These require urgent remediation to prevent system compromise."
            )
        
        if high_count > 0:
            recommendations.append(
                f"Prioritize remediation of {high_count} high-severity findings. "
                "These pose significant security risks and should be addressed within days."
            )
        
        if len(self.findings) > 0:
            recommendations.append(
                "Develop a comprehensive vulnerability management program with regular "
                "assessments to identify and remediate security issues."
            )
        
        recommendations.append(
            "Implement security awareness training for all developers and system administrators."
        )
        
        recommendations.append(
            "Establish a bug bounty or responsible disclosure program to encourage "
            "external security research."
        )
        
        return recommendations
    
    async def _save_json_report(self, report: Dict[str, Any]):
        """Save JSON report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.report_dir / f"report_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {filename}")
    
    async def _save_markdown_report(self, report: str):
        """Save Markdown report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.report_dir / f"report_{timestamp}.md"
        
        with open(filename, "w") as f:
            f.write(report)
        
        logger.info(f"Markdown report saved to {filename}")
