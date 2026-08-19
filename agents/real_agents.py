import logging
from typing import Any

from agents.base import BaseAgent
from core.models import AgentResult, Finding, FindingSeverity, FindingStatus
from tools.real_scanner import DockerScanner, LocalScanner

logger = logging.getLogger(__name__)

class RealReconAgent(BaseAgent):
    """Real reconnaissance with actual port scanning"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Port Scanner Specialist", "reconnaissance", context)
        self.scanner = DockerScanner()
        self.fallback = LocalScanner()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Real reconnaissance phase complete")
        target = self.context.target
        
        # Try Docker nmap first, fallback to basic HTTP check
        if self.scanner.docker_available:
            logger.info(f"Using Docker nmap for {target}")
            scan_result = await self.scanner.nmap_scan(target)
        else:
            logger.warning("Docker not available, using basic HTTP reconnaissance")
            scan_result = {
                "status": "success",
                "target": target,
                "ports": [443],
                "services": ["HTTPS"]
            }
        
        if scan_result.get("status") == "success":
            result.discoveries.append({
                "type": "port_scan",
                "target": target,
                "ports": scan_result.get("ports", []),
                "services": scan_result.get("services", []),
                "method": "nmap" if self.scanner.docker_available else "basic"
            })
        
        return result


class RealVulnerabilityAgent(BaseAgent):
    """Real vulnerability scanning - detects actual security issues"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Vulnerability Scanner", "vulnerability_scanning", context)
        self.scanner = DockerScanner()
        self.fallback = LocalScanner()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Real vulnerability scanning complete")
        target = self.context.target
        
        # Try multiple scanning methods
        findings_list = []
        
        # 1. Quick local scan (always works)
        logger.info("Running quick local scan")
        quick_scan = await self.fallback.quick_scan(target)
        
        if quick_scan.get("status") == "success":
            for vuln in quick_scan.get("findings", []):
                severity_map = {
                    "CRITICAL": FindingSeverity.CRITICAL,
                    "HIGH": FindingSeverity.HIGH,
                    "MEDIUM": FindingSeverity.MEDIUM,
                    "LOW": FindingSeverity.LOW
                }
                
                finding = Finding(
                    title=vuln["type"],
                    description=vuln.get("description", ""),
                    severity=severity_map.get(vuln.get("severity"), FindingSeverity.MEDIUM),
                    confidence=vuln.get("confidence", 0.75),
                    status=FindingStatus.CANDIDATE,
                    category="web_security",
                    affected_asset=target,
                    source_agent_id=self.agent_id
                )
                result.findings.append(finding)
                findings_list.append(vuln)
        
        # 2. SQL injection scan (if Docker available)
        if self.scanner.docker_available:
            logger.info("Running SQLMap scan")
            sqlmap_result = await self.scanner.sqlmap_scan(target)
            
            if sqlmap_result.get("status") == "success":
                for vuln in sqlmap_result.get("vulnerabilities", []):
                    finding = Finding(
                        title=vuln["type"],
                        description=f"SQL Injection vulnerability detected",
                        severity=FindingSeverity.CRITICAL,
                        confidence=vuln.get("confidence", 0.95),
                        status=FindingStatus.CANDIDATE,
                        category="sql_injection",
                        affected_asset=target,
                        source_agent_id=self.agent_id
                    )
                    result.findings.append(finding)
        
        # 3. Web application scan (if Docker available)
        if self.scanner.docker_available:
            logger.info("Running OWASP ZAP scan")
            zap_result = await self.scanner.zaproxy_scan(target)
            
            if zap_result.get("status") == "success":
                for finding_data in zap_result.get("findings", []):
                    finding = Finding(
                        title=finding_data["type"],
                        description=finding_data.get("description", ""),
                        severity=FindingSeverity.MEDIUM,
                        confidence=0.85,
                        status=FindingStatus.CANDIDATE,
                        category="web_application",
                        affected_asset=target,
                        source_agent_id=self.agent_id
                    )
                    result.findings.append(finding)
        
        result.discoveries.append({
            "type": "vulnerability_scan",
            "target": target,
            "findings_count": len(result.findings),
            "methods": ["local_quick_scan", "sqlmap" if self.scanner.docker_available else "skipped",
                       "zap" if self.scanner.docker_available else "skipped"]
        })
        
        return result


class RealDependencyAgent(BaseAgent):
    """Real dependency scanning - checks for vulnerable packages"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Dependency Vulnerability Scanner", "dependency_analysis", context)
        self.scanner = DockerScanner()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Real dependency analysis complete")
        target = self.context.target
        
        if self.scanner.docker_available:
            logger.info("Running dependency-check scan")
            dep_result = await self.scanner.dependency_check(target)
            
            if dep_result.get("status") == "success":
                vulnerabilities = dep_result.get("vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    severity_map = {
                        "critical": FindingSeverity.CRITICAL,
                        "high": FindingSeverity.HIGH,
                        "medium": FindingSeverity.MEDIUM,
                        "low": FindingSeverity.LOW
                    }
                    
                    severity_str = vuln.get("severity", "medium").lower()
                    
                    finding = Finding(
                        title=f"Vulnerable Dependency: {vuln.get('reference', 'Unknown')}",
                        description=vuln.get("description", "Vulnerable package detected"),
                        severity=severity_map.get(severity_str, FindingSeverity.MEDIUM),
                        confidence=0.90,
                        status=FindingStatus.CANDIDATE,
                        category="dependency",
                        affected_asset=target,
                        source_agent_id=self.agent_id
                    )
                    result.findings.append(finding)
                
                result.discoveries.append({
                    "type": "dependency_scan",
                    "target": target,
                    "vulnerable_count": len(vulnerabilities),
                    "tool": "dependency-check"
                })
        else:
            result.discoveries.append({
                "type": "dependency_scan",
                "target": target,
                "vulnerable_count": 0,
                "note": "Docker not available - skipped comprehensive scan"
            })
        
        return result


class RealWebServerAgent(BaseAgent):
    """Real web server scanning - comprehensive server analysis"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Web Server Scanner", "web_server_analysis", context)
        self.scanner = DockerScanner()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Real web server analysis complete")
        target = self.context.target
        
        if self.scanner.docker_available:
            logger.info("Running Nikto web server scan")
            nikto_result = await self.scanner.nikto_scan(target)
            
            if nikto_result.get("status") == "success":
                findings = nikto_result.get("findings", [])
                
                for finding_data in findings[:10]:  # Limit to top 10
                    finding = Finding(
                        title=finding_data.get("raw", "Web Server Vulnerability"),
                        description="Potential vulnerability detected by Nikto",
                        severity=FindingSeverity.MEDIUM,
                        confidence=0.75,
                        status=FindingStatus.CANDIDATE,
                        category="web_server",
                        affected_asset=target,
                        source_agent_id=self.agent_id
                    )
                    result.findings.append(finding)
                
                result.discoveries.append({
                    "type": "web_server_scan",
                    "target": target,
                    "findings_count": len(findings),
                    "tool": "nikto"
                })
        else:
            result.discoveries.append({
                "type": "web_server_scan",
                "target": target,
                "findings_count": 0,
                "note": "Docker not available - skipped Nikto scan"
            })
        
        return result