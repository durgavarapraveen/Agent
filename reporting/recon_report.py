"""
Detailed Reconnaissance Report Generator
Comprehensive A-Z reporting of what was done, found, and recommendations
"""

import json
from datetime import datetime
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class ReconnaissanceReportGenerator:
    """Generate detailed reconnaissance reports"""
    
    def __init__(self):
        self.report = {
            "metadata": {},
            "executive_summary": {},
            "methodology": {},
            "findings_by_category": {},
            "detailed_findings": [],
            "recommendations": [],
            "appendix": {}
        }
    
    def generate_report(
        self,
        target: str,
        mode: str,
        discoveries: List[Dict],
        findings: List,
        duration: float
    ) -> Dict[str, Any]:
        """Generate comprehensive reconnaissance report"""
        
        # 1. METADATA
        self._generate_metadata(target, mode, duration)
        
        # 2. EXECUTIVE SUMMARY
        self._generate_executive_summary(discoveries, findings)
        
        # 3. METHODOLOGY (What Was Done)
        self._generate_methodology(discoveries)
        
        # 4. FINDINGS CATEGORIZED
        self._generate_categorized_findings(findings)
        
        # 5. DETAILED FINDINGS (What Was Found)
        self._generate_detailed_findings(findings)
        
        # 6. RECOMMENDATIONS (What To Do)
        self._generate_recommendations(findings)
        
        # 7. APPENDIX (Supporting Data)
        self._generate_appendix(discoveries)
        
        return self.report
    
    def _generate_metadata(self, target: str, mode: str, duration: float):
        """Generate metadata section"""
        self.report["metadata"] = {
            "title": f"Comprehensive Reconnaissance Report - {target}",
            "target": target,
            "assessment_mode": mode,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "assessor": "Autonomous Reconnaissance Framework",
            "version": "1.0.0"
        }
    
    def _generate_executive_summary(self, discoveries: List[Dict], findings: List):
        """Generate executive summary"""
        
        # Count findings by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for finding in findings:
            severity = getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO'
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Count discoveries by category
        discovery_categories = {}
        for discovery in discoveries:
            category = discovery.get("type", "unknown")
            discovery_categories[category] = discovery_categories.get(category, 0) + 1
        
        self.report["executive_summary"] = {
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
            "total_discoveries": len(discoveries),
            "discovery_categories": discovery_categories,
            "risk_level": self._calculate_risk_level(severity_counts),
            "assessment_status": "COMPLETE",
            "key_findings": self._extract_key_findings(findings)
        }
    
    def _generate_methodology(self, discoveries: List[Dict]):
        """Generate methodology section (What Was Done)"""
        
        tools_used = set()
        phases_executed = []
        
        for discovery in discoveries:
            discovery_type = discovery.get("type", "")
            tools = discovery.get("tools_used", [])
            tools_used.update(tools)
            
            if discovery_type not in phases_executed:
                phases_executed.append(discovery_type)
        
        methodology = {
            "overview": "Comprehensive passive and active reconnaissance assessment",
            "phases": self._describe_phases(phases_executed),
            "tools_used": sorted(list(tools_used)),
            "tool_count": len(tools_used),
            "risk_posture": "Active and Aggressive scanning enabled",
            "scope": "Full attack surface discovery"
        }
        
        # Detailed phase descriptions
        methodology["detailed_phases"] = {
            "Phase 1: Target Discovery & Scope Mapping": {
                "description": "Initial identification of target organization scope and attack surface",
                "tools": ["Amass", "Subfinder", "Assetfinder", "ShuffledDNS", "Dnsx"],
                "objectives": [
                    "Identify all subdomains and related assets",
                    "Map DNS infrastructure",
                    "Discover registered domains",
                    "Enumerate cloud assets",
                    "Identify organizational relationships"
                ],
                "output": "Domain list, DNS records, IP ranges"
            },
            "Phase 2: Port & Service Scanning": {
                "description": "Network-level reconnaissance to identify accessible services",
                "tools": ["Nmap", "Masscan", "Naabu", "Httpx"],
                "objectives": [
                    "Discover open ports on discovered hosts",
                    "Identify running services and versions",
                    "Detect service banners",
                    "Map network topology",
                    "Identify protocol versions"
                ],
                "output": "Port listings, service versions, HTTP responses"
            },
            "Phase 3: Content & Directory Discovery": {
                "description": "Enumeration of web application structure and hidden resources",
                "tools": ["Gobuster", "FFUF", "Dirsearch"],
                "objectives": [
                    "Discover hidden directories",
                    "Identify backup/configuration files",
                    "Find administrative interfaces",
                    "Enumerate API endpoints",
                    "Locate sensitive information exposure"
                ],
                "output": "Directory listing, file enumeration, endpoint paths"
            },
            "Phase 4: Technology Stack Detection": {
                "description": "Identification of web technologies and potential vulnerabilities",
                "tools": ["Wappalyzer", "WhatWeb", "Nuclei", "TlsX"],
                "objectives": [
                    "Identify web frameworks and libraries",
                    "Detect CMS platforms",
                    "Extract SSL/TLS certificate information",
                    "Identify server software versions",
                    "Detect web application firewalls",
                    "Find common CVEs in identified technologies"
                ],
                "output": "Technology stack, software versions, known CVEs"
            },
            "Phase 5: Visual Reconnaissance": {
                "description": "Visual assessment of web applications for UI/UX reconnaissance",
                "tools": ["Gowitness", "EyeWitness"],
                "objectives": [
                    "Capture visual representation of web applications",
                    "Identify page structure and content",
                    "Detect authentication mechanisms",
                    "Identify input fields for further testing",
                    "Gather branding and organizational information"
                ],
                "output": "Screenshots, visual analysis"
            },
            "Phase 6: Vulnerability Detection": {
                "description": "Automated vulnerability scanning and detection",
                "tools": ["Nuclei", "Nikto"],
                "objectives": [
                    "Detect OWASP Top 10 vulnerabilities",
                    "Identify security misconfigurations",
                    "Find known CVEs",
                    "Detect missing security headers",
                    "Identify credential exposure"
                ],
                "output": "Vulnerability findings, CVE references, security scores"
            }
        }
        
        self.report["methodology"] = methodology
    
    def _generate_categorized_findings(self, findings: List):
        """Organize findings by category"""
        
        categorized = {}
        
        for finding in findings:
            category = getattr(finding, 'category', 'uncategorized')
            if category not in categorized:
                categorized[category] = []
            
            categorized[category].append({
                "title": getattr(finding, 'title', 'Unknown'),
                "severity": getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO',
                "confidence": getattr(finding, 'confidence', 0.5),
                "description": getattr(finding, 'description', '')
            })
        
        self.report["findings_by_category"] = categorized
    
    def _generate_detailed_findings(self, findings: List):
        """Generate detailed findings section (What Was Found)"""
        
        detailed = []
        
        for idx, finding in enumerate(findings, 1):
            severity = getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO'
            
            detail = {
                "id": f"FINDING-{idx:03d}",
                "title": getattr(finding, 'title', 'Unknown Finding'),
                "severity": severity,
                "confidence": getattr(finding, 'confidence', 0.5),
                "category": getattr(finding, 'category', 'uncategorized'),
                "affected_asset": getattr(finding, 'affected_asset', 'N/A'),
                "description": getattr(finding, 'description', ''),
                "impact": self._describe_impact(severity),
                "affected_users": self._get_affected_users(severity),
                "exploitability": self._assess_exploitability(finding),
                "remediation": self._get_remediation(finding)
            }
            
            detailed.append(detail)
        
        self.report["detailed_findings"] = detailed
    
    def _generate_recommendations(self, findings: List):
        """Generate recommendations section (What To Do)"""
        
        recommendations = []
        severity_counts = {}
        
        for finding in findings:
            severity = getattr(finding, 'severity', 'INFO').name if hasattr(finding, 'severity') else 'INFO'
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Critical findings
        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append({
                "priority": "IMMEDIATE",
                "action": "Address all CRITICAL findings immediately",
                "timeframe": "24-48 hours",
                "impact": "System compromise possible",
                "details": [
                    "Patch all critical vulnerabilities",
                    "Disable vulnerable services",
                    "Implement WAF rules for known exploits",
                    "Conduct incident response if exploitation suspected"
                ]
            })
        
        # High findings
        if severity_counts.get("HIGH", 0) > 0:
            recommendations.append({
                "priority": "URGENT",
                "action": "Address all HIGH findings within 1 week",
                "timeframe": "1 week",
                "impact": "Data breach or unauthorized access possible",
                "details": [
                    "Patch identified vulnerabilities",
                    "Implement security controls",
                    "Monitor for exploitation attempts"
                ]
            })
        
        # Medium findings
        if severity_counts.get("MEDIUM", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "action": "Address all MEDIUM findings within 30 days",
                "timeframe": "30 days",
                "impact": "Potential security degradation",
                "details": [
                    "Prioritize based on exploitability",
                    "Implement compensating controls",
                    "Plan remediation activities"
                ]
            })
        
        # General recommendations
        recommendations.extend([
            {
                "priority": "ONGOING",
                "action": "Implement Security Monitoring",
                "timeframe": "Continuous",
                "details": [
                    "Enable WAF logging and alerting",
                    "Deploy IDS/IPS systems",
                    "Implement SIEM for threat detection",
                    "Monitor for indicators of compromise"
                ]
            },
            {
                "priority": "ONGOING",
                "action": "Regular Security Assessments",
                "timeframe": "Quarterly",
                "details": [
                    "Conduct regular penetration testing",
                    "Perform vulnerability scans",
                    "Update threat model",
                    "Review security controls"
                ]
            },
            {
                "priority": "ONGOING",
                "action": "Security Hardening",
                "timeframe": "Ongoing",
                "details": [
                    "Apply security patches monthly",
                    "Disable unnecessary services",
                    "Implement least privilege access",
                    "Use security frameworks (CIS, NIST)"
                ]
            },
            {
                "priority": "ONGOING",
                "action": "Security Awareness",
                "timeframe": "Continuous",
                "details": [
                    "Train developers on secure coding",
                    "Conduct phishing awareness training",
                    "Establish incident response procedures",
                    "Document security policies"
                ]
            }
        ])
        
        self.report["recommendations"] = recommendations
    
    def _generate_appendix(self, discoveries: List):
        """Generate appendix with raw data"""
        
        appendix = {
            "discovery_summary": {
                "total_discoveries": len(discoveries),
                "discovery_types": list(set(d.get("type") for d in discoveries))
            },
            "technical_data": {
                "subdomains": self._extract_subdomains(discoveries),
                "ports_found": self._extract_ports(discoveries),
                "technologies": self._extract_technologies(discoveries),
                "directories": self._extract_directories(discoveries)
            }
        }
        
        self.report["appendix"] = appendix
    
    # Helper methods
    
    def _calculate_risk_level(self, severity_counts: Dict) -> str:
        """Calculate overall risk level"""
        if severity_counts["CRITICAL"] > 0:
            return "CRITICAL"
        elif severity_counts["HIGH"] > 3:
            return "HIGH"
        elif severity_counts["MEDIUM"] > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_key_findings(self, findings: List) -> List[str]:
        """Extract key findings"""
        key = []
        for finding in findings[:5]:  # Top 5
            title = getattr(finding, 'title', 'Finding')
            severity = getattr(finding, 'severity', 'INFO').name
            key.append(f"[{severity}] {title}")
        return key
    
    def _describe_phases(self, phases: List[str]) -> List[str]:
        """Describe executed phases"""
        phase_map = {
            "subdomains": "Target Discovery & Scope Mapping",
            "port_scan": "Port & Service Scanning",
            "directory_bruteforce": "Content & Directory Discovery",
            "technology_stack": "Technology Stack Detection",
            "visual_reconnaissance": "Visual Reconnaissance",
            "vulnerability_detection": "Vulnerability Detection"
        }
        return [phase_map.get(p, p) for p in phases]
    
    def _describe_impact(self, severity: str) -> str:
        """Describe finding impact"""
        impacts = {
            "CRITICAL": "System compromise, data breach, complete system takeover",
            "HIGH": "Significant data loss, unauthorized access, service disruption",
            "MEDIUM": "Information disclosure, partial compromise, access to sensitive data",
            "LOW": "Minimal impact, information gathering aid, minor security weakness",
            "INFO": "Informational, potential future impact"
        }
        return impacts.get(severity, "Unknown impact")
    
    def _get_affected_users(self, severity: str) -> str:
        """Get affected user count estimate"""
        impacts = {
            "CRITICAL": "All users and systems",
            "HIGH": "Multiple users and systems",
            "MEDIUM": "Specific users and systems",
            "LOW": "Limited users",
            "INFO": "N/A"
        }
        return impacts.get(severity, "Unknown")
    
    def _assess_exploitability(self, finding) -> str:
        """Assess exploitability"""
        confidence = getattr(finding, 'confidence', 0.5)
        if confidence > 0.8:
            return "Highly Exploitable"
        elif confidence > 0.6:
            return "Exploitable"
        else:
            return "Requires Additional Verification"
    
    def _get_remediation(self, finding) -> str:
        """Get remediation for finding"""
        category = getattr(finding, 'category', '')
        
        remediations = {
            "technology": "Update to latest secure version, apply patches",
            "security": "Implement security controls, follow security best practices",
            "configuration": "Review and correct misconfiguration",
            "vulnerability": "Apply security patch, implement workaround",
            "exposure": "Restrict access, implement access controls",
            "default": "Investigate finding and implement appropriate control"
        }
        
        return remediations.get(category, remediations["default"])
    
    def _extract_subdomains(self, discoveries: List) -> List[str]:
        """Extract subdomains from discoveries"""
        for discovery in discoveries:
            if discovery.get("type") == "subdomains":
                return discovery.get("discovered_domains", [])
        return []
    
    def _extract_ports(self, discoveries: List) -> Dict:
        """Extract ports from discoveries"""
        for discovery in discoveries:
            if discovery.get("type") == "port_scan":
                return discovery.get("discovered_ports", {})
        return {}
    
    def _extract_technologies(self, discoveries: List) -> List[str]:
        """Extract technologies from discoveries"""
        for discovery in discoveries:
            if discovery.get("type") == "technology_stack":
                return discovery.get("technologies", [])
        return []
    
    def _extract_directories(self, discoveries: List) -> List[str]:
        """Extract directories from discoveries"""
        for discovery in discoveries:
            if discovery.get("type") == "directory_bruteforce":
                return discovery.get("discovered_paths", [])
        return []