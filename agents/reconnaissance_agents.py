"""
Comprehensive Reconnaissance Agents
Agents for target discovery, port scanning, content discovery, tech identification
"""

import logging
from typing import Any, List
import asyncio

from agents.base import BaseAgent
from core.models import AgentResult, Finding, FindingSeverity, FindingStatus
from tools.recon_toolkit import DockerReconManager, RECON_TOOLS

logger = logging.getLogger(__name__)

class SubdomainDiscoveryAgent(BaseAgent):
    """Agent: Subdomain and target discovery"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Subdomain Discovery Specialist", "subdomain_discovery", context)
        self.manager = DockerReconManager()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Subdomain discovery complete")
        target = self.context.target
        
        # Extract domain
        domain = target.split("://")[-1].split("/")[0]
        
        # Run subdomain discovery tools
        tools = ["subfinder", "assetfinder", "dnsx", "shuffledns"]
        
        all_domains = set()
        
        for tool_name in tools:
            try:
                output = await self.manager.run_tool(tool_name, domain)
                
                if output["status"] == "success":
                    parsed = output.get("output", {})
                    domains = parsed.get("domains", [])
                    all_domains.update(domains)
                    
                    logger.info(f"{tool_name}: Found {len(domains)} domains")
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
        
        result.discoveries.append({
            "type": "subdomains",
            "target": domain,
            "discovered_domains": list(all_domains),
            "count": len(all_domains),
            "tools_used": tools
        })
        
        return result


class PortScanAgent(BaseAgent):
    """Agent: Port and service discovery"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Port Scan Specialist", "port_scanning", context)
        self.manager = DockerReconManager()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Port scanning complete")
        target = self.context.target
        
        # Extract IP/host
        host = target.split("://")[-1].split("/")[0]
        
        # Run port scanners
        tools = ["nmap", "naabu", "httpx"]
        
        all_ports = {}
        all_services = set()
        
        for tool_name in tools:
            try:
                output = await self.manager.run_tool(tool_name, host)
                
                if output["status"] == "success":
                    parsed = output.get("output", {})
                    ports = parsed.get("ports", [])
                    services = parsed.get("services", [])
                    
                    for port in ports:
                        if port not in all_ports:
                            all_ports[port] = []
                        all_ports[port].append(tool_name)
                    
                    all_services.update(services)
                    
                    logger.info(f"{tool_name}: Found {len(ports)} ports")
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
        
        result.discoveries.append({
            "type": "port_scan",
            "target": host,
            "discovered_ports": all_ports,
            "services": list(all_services),
            "total_ports": len(all_ports),
            "tools_used": tools
        })
        
        return result


class DirectoryBruteforceAgent(BaseAgent):
    """Agent: Directory and file discovery"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Directory Discovery Specialist", "directory_bruteforce", context)
        self.manager = DockerReconManager()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Directory bruteforcing complete")
        target = self.context.target
        
        # Run directory discovery tools
        tools = ["gobuster", "ffuf", "dirsearch"]
        
        all_paths = set()
        
        for tool_name in tools:
            try:
                output = await self.manager.run_tool(tool_name, target)
                
                if output["status"] == "success":
                    raw_output = output.get("raw", "")
                    
                    # Parse found paths
                    import re
                    paths = re.findall(r'(\/[\w\-\.\/]*)', raw_output)
                    all_paths.update(paths)
                    
                    logger.info(f"{tool_name}: Found {len(paths)} paths")
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
        
        result.discoveries.append({
            "type": "directory_bruteforce",
            "target": target,
            "discovered_paths": list(all_paths),
            "count": len(all_paths),
            "tools_used": tools
        })
        
        return result


class TechStackAgent(BaseAgent):
    """Agent: Technology stack and framework identification"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Tech Stack Specialist", "tech_detection", context)
        self.manager = DockerReconManager()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Technology detection complete")
        target = self.context.target
        
        # Run tech identification tools
        tools = ["wappalyzer", "whatweb", "nuclei", "tlsx"]
        
        all_technologies = set()
        vulnerabilities = []
        
        for tool_name in tools:
            try:
                output = await self.manager.run_tool(tool_name, target)
                
                if output["status"] == "success":
                    parsed = output.get("output", {})
                    techs = parsed.get("technologies", [])
                    all_technologies.update(techs)
                    
                    # Check for vulnerabilities in output
                    if "vulnerability" in output.get("raw", "").lower():
                        vulnerabilities.append({
                            "type": "Potential Vulnerability",
                            "tool": tool_name,
                            "description": "Vulnerability detected in tech stack"
                        })
                    
                    logger.info(f"{tool_name}: Found {len(techs)} technologies")
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
        
        result.discoveries.append({
            "type": "technology_stack",
            "target": target,
            "technologies": list(all_technologies),
            "tech_count": len(all_technologies),
            "potential_vulnerabilities": vulnerabilities,
            "tools_used": tools
        })
        
        # Create findings for any detected vulnerabilities
        for vuln in vulnerabilities:
            finding = Finding(
                title=vuln["type"],
                description=vuln["description"],
                severity=FindingSeverity.MEDIUM,
                confidence=0.70,
                status=FindingStatus.CANDIDATE,
                category="technology",
                affected_asset=target,
                source_agent_id=self.agent_id
            )
            result.findings.append(finding)
        
        return result


class ScreenshotAgent(BaseAgent):
    """Agent: Visual reconnaissance via screenshots"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Visual Reconnaissance Specialist", "screenshot", context)
        self.manager = DockerReconManager()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Visual reconnaissance complete")
        target = self.context.target
        
        # Run screenshot tools
        tools = ["gowitness", "eyewitness"]
        
        screenshots = []
        
        for tool_name in tools:
            try:
                output = await self.manager.run_tool(tool_name, target)
                
                if output["status"] == "success":
                    screenshots.append({
                        "tool": tool_name,
                        "target": target,
                        "status": "captured",
                        "path": f"/tmp/screenshots/{tool_name}"
                    })
                    
                    logger.info(f"{tool_name}: Screenshot captured")
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
        
        result.discoveries.append({
            "type": "visual_reconnaissance",
            "target": target,
            "screenshots": screenshots,
            "total": len(screenshots),
            "tools_used": tools
        })
        
        return result


class VulnerabilityDetectionAgent(BaseAgent):
    """Agent: Advanced vulnerability detection"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Vulnerability Detection Specialist", "vulnerability_detection", context)
        self.manager = DockerReconManager()
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Vulnerability detection complete")
        target = self.context.target
        
        # Run vulnerability scanners
        tools = ["nuclei", "nikto"]
        
        vulnerabilities = []
        
        for tool_name in tools:
            try:
                output = await self.manager.run_tool(tool_name, target)
                
                if output["status"] == "success":
                    raw = output.get("raw", "")
                    
                    # Parse vulnerabilities from output
                    import re
                    vulns = re.findall(r'(\[.*?\]|\w+:\s.*)', raw)
                    
                    for vuln_text in vulns:
                        vulnerabilities.append({
                            "tool": tool_name,
                            "description": vuln_text,
                            "severity": self._estimate_severity(vuln_text)
                        })
                    
                    logger.info(f"{tool_name}: Found {len(vulns)} vulnerabilities")
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
        
        # Create findings
        for vuln in vulnerabilities:
            finding = Finding(
                title=vuln["description"][:100],
                description=vuln["description"],
                severity=vuln["severity"],
                confidence=0.80,
                status=FindingStatus.CANDIDATE,
                category="vulnerability",
                affected_asset=target,
                source_agent_id=self.agent_id
            )
            result.findings.append(finding)
        
        result.discoveries.append({
            "type": "vulnerability_detection",
            "target": target,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "tools_used": tools
        })
        
        return result
    
    def _estimate_severity(self, text: str) -> FindingSeverity:
        """Estimate vulnerability severity from text"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ["critical", "rce", "injection", "auth bypass"]):
            return FindingSeverity.CRITICAL
        elif any(word in text_lower for word in ["high", "xss", "csrf", "sqli"]):
            return FindingSeverity.HIGH
        elif any(word in text_lower for word in ["medium", "info disclosure", "config"]):
            return FindingSeverity.MEDIUM
        else:
            return FindingSeverity.LOW


class ComprehensiveReconAgent(BaseAgent):
    """Agent: Master reconnaissance agent running all discovery tools"""
    
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Comprehensive Reconnaissance Master", "comprehensive_recon", context)
        self.manager = DockerReconManager()
        
        # Sub-agents
        self.subdomain_agent = SubdomainDiscoveryAgent(f"{agent_id}-subdomain", context)
        self.port_agent = PortScanAgent(f"{agent_id}-port", context)
        self.directory_agent = DirectoryBruteforceAgent(f"{agent_id}-directory", context)
        self.tech_agent = TechStackAgent(f"{agent_id}-tech", context)
        self.screenshot_agent = ScreenshotAgent(f"{agent_id}-screenshot", context)
        self.vuln_agent = VulnerabilityDetectionAgent(f"{agent_id}-vuln", context)
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Comprehensive reconnaissance complete")
        
        # Run all reconnaissance agents in parallel
        agents = [
            self.subdomain_agent,
            self.port_agent,
            self.directory_agent,
            self.tech_agent,
            self.screenshot_agent,
            self.vuln_agent
        ]
        
        tasks = [agent.perform_work() for agent in agents]
        results = await asyncio.gather(*tasks)
        
        # Aggregate results
        for agent_result in results:
            result.discoveries.extend(agent_result.discoveries)
            result.findings.extend(agent_result.findings)
        
        result.discoveries.append({
            "type": "reconnaissance_summary",
            "status": "complete",
            "agents_executed": len(agents),
            "total_discoveries": len(result.discoveries),
            "total_findings": len(result.findings)
        })
        
        return result