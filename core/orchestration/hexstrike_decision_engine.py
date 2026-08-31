import os
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Set

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)

class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"

    def add_step(self, step: AttackStep):
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate

    def calculate_success_probability(self):
        if not self.steps:
            self.success_probability = 0.0
            return
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability
        self.success_probability = prob

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine from HexStrike"""

    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.attack_patterns = self._initialize_attack_patterns()

    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8, "gobuster": 0.9, "nuclei": 0.95, "nikto": 0.85,
                "sqlmap": 0.9, "ffuf": 0.9, "feroxbuster": 0.85, "katana": 0.88,
                "httpx": 0.85, "wpscan": 0.95, "dirsearch": 0.87, "gau": 0.82,
                "waybackurls": 0.8, "arjun": 0.9, "paramspider": 0.85, "dalfox": 0.93
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95, "masscan": 0.92, "rustscan": 0.9, "autorecon": 0.95,
                "enum4linux": 0.8, "smbmap": 0.85, "amass": 0.7
            },
            TargetType.API_ENDPOINT.value: {
                "nuclei": 0.9, "ffuf": 0.85, "arjun": 0.95, "paramspider": 0.88,
                "httpx": 0.9, "katana": 0.85
            }
        }

    def _initialize_attack_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "web_reconnaissance": [
                {"tool": "nmap", "priority": 1, "params": {"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}},
                {"tool": "httpx", "priority": 2, "params": {"probe": True, "tech_detect": True}},
                {"tool": "katana", "priority": 3, "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "priority": 4, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 5, "params": {"get_versions": False}},
                {"tool": "nuclei", "priority": 6, "params": {"severity": "critical,high", "tags": "tech"}},
                {"tool": "dirsearch", "priority": 7, "params": {"extensions": "php,html,js,txt", "threads": 30}},
                {"tool": "gobuster", "priority": 8, "params": {"mode": "dir", "extensions": "php,html,js,txt"}}
            ],
            "api_testing": [
                {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True}},
                {"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": True}},
                {"tool": "paramspider", "priority": 4, "params": {"level": 2}},
                {"tool": "nuclei", "priority": 5, "params": {"tags": "api,graphql,jwt", "severity": "high,critical"}},
                {"tool": "ffuf", "priority": 6, "params": {"mode": "parameter", "method": "POST"}}
            ],
            "network_discovery": [
                {"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "masscan", "priority": 4, "params": {"rate": 1000, "ports": "1-65535", "banners": True}},
                {"tool": "smbmap", "priority": 7, "params": {"recursive": True}}
            ],
            "vulnerability_assessment": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high,medium", "update": True}},
                {"tool": "dalfox", "priority": 3, "params": {"mining_dom": True, "mining_dict": True}},
                {"tool": "nikto", "priority": 4, "params": {"comprehensive": True}},
                {"tool": "sqlmap", "priority": 5, "params": {"crawl": 2, "batch": True}}
            ],
            "bug_bounty_reconnaissance": [
                {"tool": "amass", "priority": 1, "params": {"mode": "enum", "passive": False}},
                {"tool": "subfinder", "priority": 2, "params": {"silent": True, "all_sources": True}},
                {"tool": "httpx", "priority": 3, "params": {"probe": True, "tech_detect": True, "status_code": True}},
                {"tool": "katana", "priority": 4, "params": {"depth": 3, "js_crawl": True, "form_extraction": True}},
                {"tool": "gau", "priority": 5, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 6, "params": {"get_versions": False}},
                {"tool": "paramspider", "priority": 7, "params": {"level": 2}},
                {"tool": "arjun", "priority": 8, "params": {"method": "GET,POST", "stable": True}}
            ]
        }

    def analyze_target(self, target: str) -> TargetProfile:
        profile = TargetProfile(target=target)
        profile.target_type = self._determine_target_type(target)
        
        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            try:
                hostname = urllib.parse.urlparse(target).hostname or target
                profile.ip_addresses = [socket.gethostbyname(hostname)]
            except Exception:
                pass

        if 'wordpress' in target.lower() or 'wp-' in target.lower():
            profile.technologies.append(TechnologyStack.WORDPRESS)
            profile.cms_type = "WordPress"
        elif any(ext in target.lower() for ext in ['.php', 'php']):
            profile.technologies.append(TechnologyStack.PHP)

        profile.attack_surface_score = 7.0 if profile.target_type == TargetType.WEB_APPLICATION else 5.0
        return profile

    def _determine_target_type(self, target: str) -> TargetType:
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return TargetType.NETWORK_HOST
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return TargetType.WEB_APPLICATION
        return TargetType.UNKNOWN

    def create_attack_chain(self, profile: TargetProfile, objective: str = "comprehensive") -> AttackChain:
        chain = AttackChain(profile)

        if profile.target_type == TargetType.WEB_APPLICATION:
            if objective == "quick":
                pattern = self.attack_patterns["vulnerability_assessment"][:2]
            else:
                pattern = self.attack_patterns["bug_bounty_reconnaissance"] + self.attack_patterns["vulnerability_assessment"]
        elif profile.target_type == TargetType.API_ENDPOINT:
            pattern = self.attack_patterns["api_testing"]
        elif profile.target_type == TargetType.NETWORK_HOST:
            pattern = self.attack_patterns["network_discovery"]
        else:
            pattern = self.attack_patterns["web_reconnaissance"]

        for step_config in pattern:
            tool = step_config["tool"]
            params = step_config.get("params", {})
            effectiveness = self.tool_effectiveness.get(profile.target_type.value, {}).get(tool, 0.5)
            
            step = AttackStep(
                tool=tool,
                parameters=params,
                expected_outcome=f"Discover vulnerabilities using {tool}",
                success_probability=effectiveness,
                execution_time_estimate=180
            )
            chain.add_step(step)

        chain.calculate_success_probability()
        return chain
