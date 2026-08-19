"""
Reconnaissance Toolkit for Kali Linux
Runs scanning tools already installed in your Kali Docker container
No additional Docker image pulls needed
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
# TOOL DEFINITIONS - KALI PRE-INSTALLED TOOLS
# ============================================================================

@dataclass
class KaliTool:
    """Kali tool definition"""
    name: str
    command: str  # Full command template
    category: str
    description: str
    parse_function: Optional[callable] = None
    timeout: int = 120
    risk_level: str = "passive"

# Tool Registry - All tools pre-installed in Kali
KALI_TOOLS = {
    # ========== TARGET DISCOVERY ==========
    "amass": KaliTool(
        name="Amass",
        command="amass enum -d {domain} -passive",
        category="target_discovery",
        description="Active/passive network mapping and DNS enumeration",
        timeout=300,
        risk_level="passive"
    ),
    "subfinder": KaliTool(
        name="Subfinder",
        command="subfinder -d {domain} -json",
        category="target_discovery",
        description="Fast passive subdomain enumeration",
        timeout=120,
        risk_level="passive"
    ),
    "assetfinder": KaliTool(
        name="Assetfinder",
        command="assetfinder --subs-only {domain}",
        category="target_discovery",
        description="Lightweight subdomain discovery",
        timeout=60,
        risk_level="passive"
    ),
    "whois": KaliTool(
        name="Whois",
        command="whois {domain}",
        category="target_discovery",
        description="Domain registration information",
        timeout=30,
        risk_level="passive"
    ),
    "dig": KaliTool(
        name="Dig",
        command="dig {domain} +short",
        category="target_discovery",
        description="DNS lookup tool",
        timeout=30,
        risk_level="passive"
    ),
    
    # ========== PORT SCANNING ==========
    "nmap": KaliTool(
        name="Nmap",
        command="nmap -sV -p 1-1000 {target}",
        category="port_scanning",
        description="Network port and service scanner",
        timeout=300,
        risk_level="active"
    ),
    "masscan": KaliTool(
        name="Masscan",
        command="masscan {target} -p1-1000 --rate 10000",
        category="port_scanning",
        description="Ultra-fast port scanner",
        timeout=120,
        risk_level="aggressive"
    ),
    
    # ========== DIRECTORY DISCOVERY ==========
    "gobuster": KaliTool(
        name="Gobuster",
        command="gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -q",
        category="brute_force",
        description="Directory and file enumeration",
        timeout=180,
        risk_level="active"
    ),
    "dirb": KaliTool(
        name="Dirb",
        command="dirb {url} /usr/share/wordlists/dirb/common.txt -q",
        category="brute_force",
        description="Web directory scanner",
        timeout=180,
        risk_level="active"
    ),
    "dirsearch": KaliTool(
        name="Dirsearch",
        command="dirsearch -u {url} -q",
        category="brute_force",
        description="Multi-threaded directory scanner",
        timeout=180,
        risk_level="active"
    ),
    
    # ========== WEB TECHNOLOGY DETECTION ==========
    "nikto": KaliTool(
        name="Nikto",
        command="nikto -h {target} -q",
        category="tech_detection",
        description="Web server vulnerability scanner",
        timeout=180,
        risk_level="active"
    ),
    "whatweb": KaliTool(
        name="WhatWeb",
        command="whatweb -a 3 {url}",
        category="tech_detection",
        description="Web technology fingerprinting",
        timeout=120,
        risk_level="passive"
    ),
    "curl": KaliTool(
        name="Curl",
        command="curl -I {url}",
        category="tech_detection",
        description="HTTP header analysis",
        timeout=30,
        risk_level="passive"
    ),
    
    # ========== VULNERABILITY SCANNING ==========
    "sqlmap": KaliTool(
        name="SQLMap",
        command="sqlmap -u {url} --batch --level=1 --risk=1 -q",
        category="vulnerability",
        description="SQL injection detection",
        timeout=300,
        risk_level="active"
    ),
    "xssstrike": KaliTool(
        name="XSSStrike",
        command="xssstrike -u {url} --crawl 2",
        category="vulnerability",
        description="XSS vulnerability scanner",
        timeout=180,
        risk_level="active"
    ),
    
    # ========== VISUAL RECONNAISSANCE ==========
    "screencapture": KaliTool(
        name="Screenshot",
        command="timeout 10 google-chrome --headless --disable-gpu --screenshot={output} {url}",
        category="screenshot",
        description="Website screenshot capture",
        timeout=30,
        risk_level="passive"
    ),
    
    # ========== ADDITIONAL TOOLS ==========
    "host": KaliTool(
        name="Host",
        command="host {domain}",
        category="target_discovery",
        description="DNS hostname lookup",
        timeout=30,
        risk_level="passive"
    ),
    "nslookup": KaliTool(
        name="Nslookup",
        command="nslookup {domain}",
        category="target_discovery",
        description="DNS query tool",
        timeout=30,
        risk_level="passive"
    ),
    "traceroute": KaliTool(
        name="Traceroute",
        command="traceroute -m 15 {domain}",
        category="target_discovery",
        description="Network path tracing",
        timeout=60,
        risk_level="passive"
    ),
    "ping": KaliTool(
        name="Ping",
        command="ping -c 4 {domain}",
        category="target_discovery",
        description="Host availability check",
        timeout=30,
        risk_level="passive"
    ),
}

# ============================================================================
# KALI SCANNER MANAGER
# ============================================================================

class KaliScanner:
    """Manages scanning with Kali Linux pre-installed tools"""
    
    def __init__(self):
        self.tools_available = self._check_available_tools()
        self.results_cache = {}
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which tools are available in Kali"""
        available = {}
        
        for tool_name, tool_config in KALI_TOOLS.items():
            # Extract command name (first word)
            cmd_name = tool_config.command.split()[0]
            
            try:
                result = subprocess.run(
                    [f"which {cmd_name}"],
                    shell=True,
                    capture_output=True,
                    timeout=5
                )
                available[tool_name] = result.returncode == 0
                
                if available[tool_name]:
                    logger.info(f"✓ {tool_name} available")
                else:
                    logger.warning(f"✗ {tool_name} not found")
            except Exception as e:
                logger.warning(f"Error checking {tool_name}: {e}")
                available[tool_name] = False
        
        return available
    
    async def run_tool(
        self,
        tool_name: str,
        target: str
    ) -> Dict[str, Any]:
        """Run a Kali tool"""
        
        if tool_name not in KALI_TOOLS:
            return {"status": "error", "error": f"Unknown tool: {tool_name}"}
        
        if not self.tools_available.get(tool_name, False):
            return {"status": "error", "error": f"Tool not available: {tool_name}"}
        
        tool = KALI_TOOLS[tool_name]
        
        # Prepare command
        domain = target.split("://")[-1].split("/")[0].split(":")[0]
        url = target if target.startswith("http") else f"http://{target}"
        output_file = f"/tmp/{tool_name}_output.txt"
        
        command = tool.command.format(
            target=target,
            domain=domain,
            url=url,
            output=output_file
        )
        
        try:
            logger.info(f"Running {tool_name} on {target}")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=tool.timeout
            )
            
            output = result.stdout + result.stderr
            
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
                "raw": output[:1000]  # Limit raw output
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
    
    async def run_passive_scan(self, target: str) -> Dict[str, List[Dict]]:
        """Run passive reconnaissance tools"""
        
        results = {
            "target_discovery": [],
            "tech_detection": []
        }
        
        # Extract domain
        domain = target.split("://")[-1].split("/")[0]
        
        # Passive tools
        passive_tools = [
            "subfinder", "assetfinder", "whois", "dig",
            "whatweb", "curl", "host", "nslookup", "ping"
        ]
        
        tasks = []
        for tool in passive_tools:
            if self.tools_available.get(tool, False):
                tasks.append(self.run_tool(tool, domain if tool in ["amass", "subfinder", "assetfinder", "whois", "dig", "host", "nslookup", "ping"] else target))
        
        outputs = await asyncio.gather(*tasks)
        
        for output in outputs:
            if output["status"] == "success":
                category = output["category"]
                if category in results:
                    results[category].append(output)
        
        return results
    
    async def run_active_scan(self, target: str) -> Dict[str, List[Dict]]:
        """Run active scanning tools"""
        
        results = {
            "port_scanning": [],
            "brute_force": [],
            "vulnerability": []
        }
        
        # Active tools
        active_tools = [
            "nmap", "gobuster", "dirb", "dirsearch",
            "nikto", "whatweb", "curl"
        ]
        
        tasks = []
        for tool in active_tools:
            if self.tools_available.get(tool, False):
                tasks.append(self.run_tool(tool, target))
        
        outputs = await asyncio.gather(*tasks)
        
        for output in outputs:
            if output["status"] == "success":
                category = output["category"]
                if category in results:
                    results[category].append(output)
        
        return results
    
    async def run_aggressive_scan(self, target: str) -> Dict[str, List[Dict]]:
        """Run aggressive vulnerability scanning"""
        
        results = {
            "port_scanning": [],
            "vulnerability": [],
            "screenshot": []
        }
        
        # Aggressive tools
        aggressive_tools = [
            "nmap", "masscan", "sqlmap", "xssstrike", "nikto"
        ]
        
        tasks = []
        for tool in aggressive_tools:
            if self.tools_available.get(tool, False):
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
            if line.strip() and not line.startswith('['):
                domains.append(line.strip())
    except:
        pass
    
    return {
        "domains": domains,
        "count": len(domains)
    }

def parse_dig_output(output: str) -> Dict[str, Any]:
    """Parse dig output"""
    records = []
    
    for line in output.split('\n'):
        if line.strip() and not line.startswith(';'):
            records.append(line.strip())
    
    return {
        "records": records,
        "count": len(records)
    }

def parse_nikto_output(output: str) -> Dict[str, Any]:
    """Parse nikto output"""
    findings = []
    
    for line in output.split('\n'):
        if '+' in line and '[' in line:
            findings.append(line.strip())
    
    return {
        "findings": findings,
        "count": len(findings)
    }

# Assign parsers
KALI_TOOLS["nmap"].parse_function = parse_nmap_output
KALI_TOOLS["subfinder"].parse_function = parse_subfinder_output
KALI_TOOLS["dig"].parse_function = parse_dig_output
KALI_TOOLS["nikto"].parse_function = parse_nikto_output

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'KaliScanner',
    'KALI_TOOLS',
    'KaliTool',
]