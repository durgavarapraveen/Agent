"""
Comprehensive Reconnaissance Toolkit
Dockerized security reconnaissance tools with automatic container management
Covers: Target Discovery, Port Scanning, Directory Bruteforcing, Tech Stack Detection
"""

import subprocess
import json
import logging
import re
import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

@dataclass
class ReconTool:
    """Reconnaissance tool definition"""
    name: str
    docker_image: str
    category: str  # target_discovery, port_scanning, brute_force, tech_detection, screenshot
    description: str
    command_template: str
    parse_function: callable = None
    timeout: int = 120
    risk_level: str = "passive"  # passive, active, aggressive

# Tool Registry
RECON_TOOLS = {
    # ========== TARGET DISCOVERY & SCOPE MAPPING ==========
    "amass": ReconTool(
        name="Amass",
        docker_image="caffix/amass:latest",
        category="target_discovery",
        description="Active/passive network mapping, DNS enumeration, attack surface discovery",
        command_template="amass enum -d {domain} -passive",
        timeout=300,
        risk_level="passive"
    ),
    "subfinder": ReconTool(
        name="Subfinder",
        docker_image="projectdiscovery/subfinder:latest",
        category="target_discovery",
        description="Fast passive subdomain enumeration across 100+ data sources",
        command_template="subfinder -d {domain} -json",
        timeout=120,
        risk_level="passive"
    ),
    "assetfinder": ReconTool(
        name="Assetfinder",
        docker_image="tomnomnom/assetfinder:latest",
        category="target_discovery",
        description="Lightweight subdomain discovery using web scraping",
        command_template="assetfinder --subs-only {domain}",
        timeout=60,
        risk_level="passive"
    ),
    "shodan": ReconTool(
        name="Shodan",
        docker_image="jakejarvis/shodan:latest",
        category="target_discovery",
        description="Search engine for internet-connected devices, open ports, banners",
        command_template="shodan host {ip}",
        timeout=30,
        risk_level="passive"
    ),
    
    # ========== PORT & SERVICE SCANNING ==========
    "nmap": ReconTool(
        name="Nmap",
        docker_image="nmap/nmap:latest",
        category="port_scanning",
        description="Industry-standard network scanner for ports, services, OS detection",
        command_template="nmap -sV -p 1-10000 --top-ports 100 {target}",
        timeout=180,
        risk_level="active"
    ),
    "masscan": ReconTool(
        name="Masscan",
        docker_image="shadowcoder/masscan:latest",
        category="port_scanning",
        description="Ultra-fast TCP port scanner capable of scanning internet in minutes",
        command_template="masscan {target} -p1-1000 --rate 10000",
        timeout=120,
        risk_level="aggressive"
    ),
    "naabu": ReconTool(
        name="Naabu",
        docker_image="projectdiscovery/naabu:latest",
        category="port_scanning",
        description="Fast, reliable port scanner focused on integration",
        command_template="naabu -host {target} -p - -json",
        timeout=120,
        risk_level="active"
    ),
    
    # ========== CONTENT & DIRECTORY BRUTEFORCING ==========
    "gobuster": ReconTool(
        name="Gobuster",
        docker_image="evitenews/gobuster:latest",
        category="brute_force",
        description="High-speed URI, directory, DNS subdomain bruteforcing",
        command_template="gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt",
        timeout=180,
        risk_level="active"
    ),
    "ffuf": ReconTool(
        name="FFUF",
        docker_image="projectdiscovery/ffuf:latest",
        category="brute_force",
        description="Fast web fuzzer for directories, files, parameters, virtual hosts",
        command_template="ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
        timeout=180,
        risk_level="active"
    ),
    "dirsearch": ReconTool(
        name="Dirsearch",
        docker_image="evitenews/dirsearch:latest",
        category="brute_force",
        description="Multi-threaded directory/file bruteforcing tool",
        command_template="dirsearch -u {url} -w /usr/share/wordlists/dirb/common.txt",
        timeout=180,
        risk_level="active"
    ),
    
    # ========== WEB TECH STACK & VULNERABILITY FINGERPRINTING ==========
    "wappalyzer": ReconTool(
        name="Wappalyzer",
        docker_image="projectdiscovery/nuclei:latest",
        category="tech_detection",
        description="Identifies software, frameworks, CMS, server technologies",
        command_template="nuclei -u {url} -t /root/nuclei-templates/technologies/",
        timeout=120,
        risk_level="passive"
    ),
    "whatweb": ReconTool(
        name="WhatWeb",
        docker_image="evitenews/whatweb:latest",
        category="tech_detection",
        description="Identifies web technologies, frameworks, analytics packages",
        command_template="whatweb -a 3 -v {url}",
        timeout=120,
        risk_level="passive"
    ),
    "nikto": ReconTool(
        name="Nikto",
        docker_image="evitenews/nikto:latest",
        category="tech_detection",
        description="Web server scanner for dangerous files, outdated software, misconfigs",
        command_template="nikto -h {target}",
        timeout=180,
        risk_level="active"
    ),
    "nuclei": ReconTool(
        name="Nuclei",
        docker_image="projectdiscovery/nuclei:latest",
        category="tech_detection",
        description="Template-based vulnerability scanner for CVEs, misconfigurations",
        command_template="nuclei -u {url} -severity high,critical",
        timeout=300,
        risk_level="active"
    ),
    
    # ========== VISUAL RECONNAISSANCE ==========
    "gowitness": ReconTool(
        name="Gowitness",
        docker_image="leonjza/gowitness:latest",
        category="screenshot",
        description="Web screenshot utility using headless Chrome",
        command_template="gowitness single -u {url} -d /tmp/screenshots",
        timeout=60,
        risk_level="passive"
    ),
    "eyewitness": ReconTool(
        name="EyeWitness",
        docker_image="eyewitness:latest",
        category="screenshot",
        description="Takes screenshots, headers, server info for target identification",
        command_template="python3 EyeWitness.py -u {url}",
        timeout=120,
        risk_level="passive"
    ),
    
    # ========== ADDITIONAL CRITICAL TOOLS ==========
    "httpx": ReconTool(
        name="Httpx",
        docker_image="projectdiscovery/httpx:latest",
        category="port_scanning",
        description="Fast HTTP prober with multiple protocols support",
        command_template="httpx -l {targets_file} -json",
        timeout=120,
        risk_level="passive"
    ),
    "tlsx": ReconTool(
        name="TlsX",
        docker_image="projectdiscovery/tlsx:latest",
        category="tech_detection",
        description="TLS certificate information extraction and analysis",
        command_template="tlsx -host {target} -json",
        timeout=30,
        risk_level="passive"
    ),
    "shuffledns": ReconTool(
        name="ShuffledDNS",
        docker_image="projectdiscovery/shuffledns:latest",
        category="target_discovery",
        description="DNS subdomain resolver with permutation generation",
        command_template="shuffledns -d {domain} -json",
        timeout=120,
        risk_level="passive"
    ),
    "dnsx": ReconTool(
        name="Dnsx",
        docker_image="projectdiscovery/dnsx:latest",
        category="target_discovery",
        description="DNS lookup tool with multiple record type support",
        command_template="dnsx -d {domain} -json",
        timeout=60,
        risk_level="passive"
    ),
}

# ============================================================================
# DOCKER CONTAINER MANAGER
# ============================================================================

class DockerReconManager:
    """Manages Docker containers for reconnaissance tools"""
    
    def __init__(self):
        self.docker_available = self._check_docker()
        self.pulled_images = set()
        self.running_containers = {}
    
    def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5
            )
            return True
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            return False
    
    async def ensure_image(self, image: str) -> bool:
        """Ensure Docker image is pulled"""
        if not self.docker_available:
            return False
        
        if image in self.pulled_images:
            return True
        
        try:
            logger.info(f"Pulling Docker image: {image}")
            result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.pulled_images.add(image)
                logger.info(f"Successfully pulled: {image}")
                return True
            else:
                logger.error(f"Failed to pull {image}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error pulling image {image}: {e}")
            return False
    
    async def run_tool(
        self,
        tool_name: str,
        target: str,
        tool_config: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Run reconnaissance tool in Docker container"""
        
        if tool_name not in RECON_TOOLS:
            return {"status": "error", "error": f"Unknown tool: {tool_name}"}
        
        tool = RECON_TOOLS[tool_name]
        
        # Ensure image is available
        if not await self.ensure_image(tool.docker_image):
            return {
                "status": "error",
                "error": f"Could not pull Docker image: {tool.docker_image}"
            }
        
        # Build command
        command = tool.command_template.format(
            target=target,
            domain=target.split("://")[-1].split("/")[0],
            url=target,
            ip=target,
            targets_file="/tmp/targets.txt"
        )
        
        try:
            # Run in Docker
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", "/tmp:/tmp:rw",
                tool.docker_image,
                "sh", "-c", command
            ]
            
            logger.info(f"Running {tool_name} on {target}")
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=tool.timeout
            )
            
            output = result.stdout
            
            # Parse output if function provided
            if tool.parse_function:
                parsed = tool.parse_function(output)
            else:
                parsed = {"raw": output}
            
            return {
                "status": "success",
                "tool": tool_name,
                "target": target,
                "category": tool.category,
                "output": parsed,
                "raw": output[:500]  # Limit raw output
            }
        
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "tool": tool_name,
                "target": target,
                "error": f"Tool timeout after {tool.timeout}s"
            }
        except Exception as e:
            logger.error(f"Error running {tool_name}: {e}")
            return {
                "status": "error",
                "tool": tool_name,
                "target": target,
                "error": str(e)
            }
    
    async def run_tool_suite(
        self,
        tools: List[str],
        target: str
    ) -> Dict[str, List[Dict]]:
        """Run multiple tools in parallel"""
        
        results = {
            "target_discovery": [],
            "port_scanning": [],
            "brute_force": [],
            "tech_detection": [],
            "screenshot": []
        }
        
        tasks = []
        for tool in tools:
            if tool in RECON_TOOLS:
                tasks.append(self.run_tool(tool, target))
        
        outputs = await asyncio.gather(*tasks)
        
        for output in outputs:
            if output["status"] == "success":
                category = output["category"]
                if category in results:
                    results[category].append(output)
        
        return results


# ============================================================================
# PARSING FUNCTIONS
# ============================================================================

def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse nmap output"""
    ports = []
    services = []
    
    for line in output.split('\n'):
        match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
        if match:
            ports.append(int(match.group(1)))
            services.append(match.group(2))
    
    return {
        "ports": sorted(set(ports)),
        "services": list(set(services)),
        "port_count": len(ports)
    }

def parse_subfinder_output(output: str) -> Dict[str, Any]:
    """Parse subfinder output"""
    domains = []
    
    try:
        for line in output.split('\n'):
            if line.strip():
                domains.append(line.strip())
    except:
        pass
    
    return {
        "domains": domains,
        "count": len(domains)
    }

def parse_whatweb_output(output: str) -> Dict[str, Any]:
    """Parse WhatWeb output"""
    technologies = []
    
    for line in output.split('\n'):
        if '[' in line and ']' in line:
            match = re.search(r'\[(.*?)\]', line)
            if match:
                technologies.append(match.group(1))
    
    return {
        "technologies": list(set(technologies)),
        "tech_count": len(set(technologies))
    }

# Assign parsers
RECON_TOOLS["nmap"].parse_function = parse_nmap_output
RECON_TOOLS["subfinder"].parse_function = parse_subfinder_output
RECON_TOOLS["whatweb"].parse_function = parse_whatweb_output

# ============================================================================
# SETUP SCRIPT
# ============================================================================

async def install_all_tools() -> Dict[str, bool]:
    """Pre-install all reconnaissance tool images"""
    
    logger.info("Installing all reconnaissance tools...")
    manager = DockerReconManager()
    
    if not manager.docker_available:
        logger.error("Docker is not available. Install Docker first.")
        return {"status": "error", "docker_available": False}
    
    results = {}
    
    for tool_name, tool_config in RECON_TOOLS.items():
        logger.info(f"Installing {tool_name}...")
        success = await manager.ensure_image(tool_config.docker_image)
        results[tool_name] = success
        
        if success:
            logger.info(f"✓ {tool_name} installed")
        else:
            logger.error(f"✗ {tool_name} failed to install")
    
    return results

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'DockerReconManager',
    'RECON_TOOLS',
    'install_all_tools',
    'ReconTool',
]