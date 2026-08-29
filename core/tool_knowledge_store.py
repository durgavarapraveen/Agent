"""
Tool Knowledge Store.
Centralized repository for dynamic tool profiles, capabilities, and execution metrics.
"""

import logging
from typing import Dict, List, Optional, Any
from core.tool_intelligence import ToolProfile

logger = logging.getLogger(__name__)


class ToolKnowledgeStore:
    """Stores and indexes dynamic tool intelligence"""

    _instance: Optional["ToolKnowledgeStore"] = None

    @classmethod
    def get_instance(cls) -> "ToolKnowledgeStore":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.profiles: Dict[str, ToolProfile] = {}
        self.capability_index: Dict[str, List[str]] = {}  # capability -> [tool_ids]
        self.execution_history: List[Dict[str, Any]] = []
        self._bootstrap_default_tools()

    def register_tool(self, profile: ToolProfile, log_profile: bool = True) -> None:
        """Register or update a tool profile in the store"""
        tool_id = profile.name.lower().strip()
        profile.id = f"tool_{tool_id}"
        self.profiles[tool_id] = profile

        for cap in profile.capabilities:
            cap_norm = cap.lower().strip()
            if cap_norm not in self.capability_index:
                self.capability_index[cap_norm] = []
            if tool_id not in self.capability_index[cap_norm]:
                self.capability_index[cap_norm].append(tool_id)

        if log_profile:
            logger.info(f"TOOL_PROFILE_CREATED: tool={profile.name} capabilities={profile.capabilities} trust={profile.trust_score}")
        else:
            logger.debug(f"TOOL_PROFILE_CREATED: tool={profile.name} capabilities={profile.capabilities} trust={profile.trust_score}")

    def get_tool(self, name: str) -> Optional[ToolProfile]:
        """Get profile by tool name"""
        return self.profiles.get(name.lower().strip())

    def get_tools_for_capability(self, capability: str) -> List[ToolProfile]:
        """Retrieve all registered tool profiles matching a capability"""
        cap_norm = capability.lower().strip()
        tool_ids = self.capability_index.get(cap_norm, [])
        return [self.profiles[tid] for tid in tool_ids if tid in self.profiles]

    def record_execution(
        self,
        tool_name: str,
        success: bool,
        duration: float,
        findings_count: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record execution outcome and update tool performance stats"""
        tool_id = tool_name.lower().strip()
        profile = self.profiles.get(tool_id)
        if profile:
            profile.update_performance(success, duration, findings_count)

        self.execution_history.append({
            "tool": tool_name,
            "success": success,
            "duration": duration,
            "findings_count": findings_count,
            "metadata": metadata or {}
        })

    def get_all_tools(self) -> List[ToolProfile]:
        """Return all registered tool profiles"""
        return list(self.profiles.values())

    def _bootstrap_default_tools(self) -> None:
        """Initialize baseline profiles for security tools"""
        defaults = [
            # DNS Enumeration
            ToolProfile(
                name="subfinder",
                description="Fast passive subdomain enumeration tool",
                capabilities=["dns_enumeration"],
                trust_score=0.96,
                performance_score=0.94,
                source="local"
            ),
            ToolProfile(
                name="amass",
                description="In-depth DNS enumeration and network mapping",
                capabilities=["dns_enumeration"],
                trust_score=0.92,
                performance_score=0.88,
                source="local"
            ),
            ToolProfile(
                name="dig",
                description="DNS query utility",
                capabilities=["dns_enumeration"],
                trust_score=0.95,
                performance_score=0.95,
                source="local"
            ),
            # Port Scanning
            ToolProfile(
                name="nmap",
                description="Network exploration tool and security / port scanner",
                capabilities=["port_scanning", "vulnerability_scanning"],
                trust_score=0.98,
                performance_score=0.90,
                source="local"
            ),
            ToolProfile(
                name="masscan",
                description="High-speed TCP port scanner",
                capabilities=["port_scanning"],
                trust_score=0.85,
                performance_score=0.98,
                source="local"
            ),
            # TLS Analysis
            ToolProfile(
                name="sslscan",
                description="Tests SSL/TLS enabled services and ciphers",
                capabilities=["tls_analysis"],
                trust_score=0.94,
                performance_score=0.92,
                source="local"
            ),
            ToolProfile(
                name="openssl",
                description="OpenSSL diagnostic tool for TLS certs and handshakes",
                capabilities=["tls_analysis"],
                trust_score=0.95,
                performance_score=0.90,
                source="local"
            ),
            # Technology Fingerprinting & HTTP Analysis
            ToolProfile(
                name="whatweb",
                description="Next generation web scanner for tech identification",
                capabilities=["technology_fingerprinting", "http_analysis"],
                trust_score=0.92,
                performance_score=0.90,
                source="local"
            ),
            ToolProfile(
                name="httpx",
                description="Fast and multi-purpose HTTP toolkit",
                capabilities=["technology_fingerprinting", "http_analysis", "endpoint_discovery"],
                trust_score=0.95,
                performance_score=0.96,
                source="local"
            ),
            # Endpoint Discovery & Crawling
            ToolProfile(
                name="katana",
                description="Next-generation crawling and spidering framework",
                capabilities=["endpoint_discovery", "web_crawling", "javascript_analysis"],
                trust_score=0.94,
                performance_score=0.92,
                source="local"
            ),
            ToolProfile(
                name="paramspider",
                description="Mining parameters and endpoints from web archives",
                capabilities=["endpoint_discovery"],
                trust_score=0.90,
                performance_score=0.89,
                source="local"
            ),
            ToolProfile(
                name="gau",
                description="GetAllUrls: Fetch known URLs from AlienVault, Wayback, Common Crawl",
                capabilities=["endpoint_discovery", "web_crawling"],
                trust_score=0.91,
                performance_score=0.93,
                source="local"
            ),
            ToolProfile(
                name="waybackurls",
                description="Fetch known URLs from the Wayback Machine",
                capabilities=["endpoint_discovery"],
                trust_score=0.88,
                performance_score=0.90,
                source="local"
            ),
            ToolProfile(
                name="gobuster",
                description="Directory/file & DNS busting tool written in Go",
                capabilities=["endpoint_discovery"],
                trust_score=0.91,
                performance_score=0.88,
                source="local"
            ),
            ToolProfile(
                name="feroxbuster",
                description="Fast, simple, recursive content discovery tool in Rust",
                capabilities=["endpoint_discovery"],
                trust_score=0.90,
                performance_score=0.89,
                source="local"
            ),
            ToolProfile(
                name="ffuf",
                description="Fast web fuzzer written in Go",
                capabilities=["endpoint_discovery"],
                trust_score=0.93,
                performance_score=0.94,
                source="local"
            ),
            # Vulnerability Scanning & WAF
            ToolProfile(
                name="wafw00f",
                description="Web Application Firewall fingerprinting toolkit",
                capabilities=["technology_fingerprinting", "vulnerability_scanning"],
                trust_score=0.93,
                performance_score=0.92,
                source="local"
            ),
            ToolProfile(
                name="nuclei",
                description="Fast and customizable vulnerability scanner based on simple YAML DSL",
                capabilities=["vulnerability_scanning"],
                trust_score=0.96,
                performance_score=0.93,
                source="local"
            ),
            ToolProfile(
                name="msfconsole",
                description="Metasploit Framework modular auxiliary scanner and exploit verification engine",
                capabilities=["vulnerability_scanning", "authentication_testing"],
                trust_score=0.97,
                performance_score=0.88,
                source="local"
            ),
            ToolProfile(
                name="sqlmap",
                description="Automatic SQL injection and database takeover tool",
                capabilities=["vulnerability_scanning", "authentication_testing"],
                trust_score=0.94,
                performance_score=0.82,
                source="local"
            ),
            ToolProfile(
                name="arjun",
                description="HTTP parameter discovery suite",
                capabilities=["endpoint_discovery"],
                trust_score=0.89,
                performance_score=0.90,
                source="local"
            ),
            ToolProfile(
                name="dalfox",
                description="Finder and utility analyzer for XSS vulnerabilities",
                capabilities=["vulnerability_scanning"],
                trust_score=0.88,
                performance_score=0.90,
                source="local"
            ),
        ]

        for p in defaults:
            self.register_tool(p, log_profile=False)

        logger.info(f"[ToolKnowledgeStore] Bootstrapped {len(defaults)} baseline tool profiles.")
