import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.models import Finding
from reporting.recon_report import ReconnaissanceReportGenerator

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates security assessment reports with reconnaissance data."""
    
    def __init__(self, context: Any, findings: List[Finding], discoveries: List[Dict[str, Any]]):
        self.context = context
        self.findings = findings
        self.discoveries = discoveries
        self.report_dir = Path("reports")
        self.recon_generator = ReconnaissanceReportGenerator()
    
    async def generate(self):
        """Generate all report formats."""
        self.report_dir.mkdir(exist_ok=True)
        
        # Calculate duration
        duration = getattr(self.context, 'get_duration_seconds', lambda: 0)()
        
        # Generate reconnaissance report
        recon_report = self.recon_generator.generate_report(
            target=self.context.target,
            mode=self.context.mode,
            discoveries=self.discoveries,
            findings=self.findings,
            duration=duration
        )
        
        # Generate JSON report (original)
        json_report = self._generate_json_report()
        
        # Merge reconnaissance report into JSON report
        json_report["reconnaissance"] = recon_report
        json_report["methodology"] = recon_report.get("methodology", json_report.get("methodology"))
        json_report["recommendations"] = recon_report.get("recommendations", self._generate_recommendations())
        
        await self._save_json_report(json_report)
        
        # Generate Markdown report
        md_report = self._generate_markdown_report()
        await self._save_markdown_report(md_report)
        
        logger.info(f"Reports generated in {self.report_dir}/")
    
    def _generate_json_report(self) -> Dict[str, Any]:
        """Generate JSON report structure."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for finding in self.findings:
            severity = getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO'
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        discovery_categories = {}
        for discovery in self.discoveries:
            category = discovery.get("type", "unknown")
            discovery_categories[category] = discovery_categories.get(category, 0) + 1
        
        return {
            "metadata": {
                "title": f"Security Assessment Report - {self.context.target}",
                "assessor": "AutonomousSecurityAgent",
                "version": "2.0.0",
                "target": self.context.target,
                "mode": self.context.mode,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": getattr(self.context, 'get_duration_seconds', lambda: 0)()
            },
            "executive_summary": {
                "total_findings": len(self.findings),
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
                "info": severity_counts["INFO"],
                "total_discoveries": len(self.discoveries),
                "discovery_categories": discovery_categories
            },
            "scope": {
                "target": self.context.target,
                "mode": self.context.mode,
                "objectives": self._get_assessment_objectives()
            },
            "findings": [self._format_finding(f) for f in self.findings],
            "discoveries": self.discoveries,
            "methodology": "Autonomous multi-agent cybersecurity assessment",
            "recommendations": self._generate_recommendations()
        }
    
    def _format_finding(self, finding: Finding) -> Dict[str, Any]:
        """Format a finding for JSON output."""
        return {
            "title": getattr(finding, 'title', 'Unknown'),
            "description": getattr(finding, 'description', ''),
            "severity": getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO',
            "confidence": getattr(finding, 'confidence', 0.5),
            "category": getattr(finding, 'category', 'uncategorized'),
            "affected_asset": getattr(finding, 'affected_asset', 'N/A'),
            "status": getattr(finding, 'status', 'CANDIDATE').name if hasattr(finding, 'status') else 'CANDIDATE'
        }
    
    def _generate_markdown_report(self) -> str:
        """Generate Markdown report."""
        report = []
        
        report.append("# Security Assessment Report\n")
        report.append(f"**Target:** {self.context.target}\n")
        report.append(f"**Assessment Mode:** {self.context.mode}\n")
        report.append(f"**Date:** {datetime.now().isoformat()}\n\n")
        
        # Executive Summary
        report.append("## Executive Summary\n\n")
        severity_counts = {
            "CRITICAL": sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'CRITICAL'),
            "HIGH": sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'HIGH'),
            "MEDIUM": sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'MEDIUM'),
            "LOW": sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'LOW')
        }
        
        report.append(f"**Total Findings:** {len(self.findings)}\n")
        report.append(f"- Critical: {severity_counts['CRITICAL']}\n")
        report.append(f"- High: {severity_counts['HIGH']}\n")
        report.append(f"- Medium: {severity_counts['MEDIUM']}\n")
        report.append(f"- Low: {severity_counts['LOW']}\n\n")
        
        report.append(f"**Total Discoveries:** {len(self.discoveries)}\n\n")
        
        # Findings
        report.append("## Findings\n\n")
        
        for idx, finding in enumerate(self.findings, 1):
            title = getattr(finding, 'title', 'Unknown')
            severity = getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO'
            description = getattr(finding, 'description', '')
            
            report.append(f"### {idx}. {title}\n\n")
            report.append(f"**Severity:** {severity}\n\n")
            report.append(f"**Description:** {description}\n\n")
        
        # Recommendations
        report.append("## Recommendations\n\n")
        for rec in self._generate_recommendations():
            report.append(f"- {rec}\n")
        
        return "".join(report)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        # Count by severity
        critical_count = sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'CRITICAL')
        high_count = sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'HIGH')
        medium_count = sum(1 for f in self.findings if getattr(f, 'severity', 'INFO').name == 'MEDIUM')
        
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical findings immediately (within 24-48 hours)")
        
        if high_count > 0:
            recommendations.append(f"Address {high_count} high-severity findings within 1 week")
        
        if medium_count > 0:
            recommendations.append(f"Address {medium_count} medium-severity findings within 30 days")
        
        recommendations.extend([
            "Implement security monitoring and alerting",
            "Conduct regular security assessments",
            "Apply security patches and updates",
            "Establish incident response procedures",
            "Implement security awareness training"
        ])
        
        return recommendations
    
    def _get_assessment_objectives(self) -> List[str]:
        """Get assessment objectives based on mode."""
        mode_objectives = {
            "SAFE_PASSIVE": [
                "Passive reconnaissance only",
                "No active scanning",
                "Minimal detection risk"
            ],
            "SAFE_ACTIVE": [
                "Active scanning with safeguards",
                "Port scanning and service enumeration",
                "Moderate detection risk"
            ],
            "FULL_AUTHORIZED": [
                "Comprehensive security assessment",
                "Full attack surface mapping",
                "High detection risk - authorized testing only"
            ]
        }
        
        return mode_objectives.get(self.context.mode, ["Security assessment"])
    
    async def _save_json_report(self, report: Dict[str, Any]):
        """Save JSON report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.report_dir / f"report_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"JSON report saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")
    
    async def _save_markdown_report(self, report: str):
        """Save Markdown report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.report_dir / f"report_{timestamp}.md"
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Markdown report saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save Markdown report: {e}")