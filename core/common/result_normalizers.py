"""
Result normalizers - Convert raw tool output to structured observations.
Preserve information during normalization.
"""

import logging
import json
import re
from typing import Dict, List, Any, Optional
from core.schemas import ToolResult, Evidence, KnowledgeItem

logger = logging.getLogger(__name__)


class ResultNormalizer:
    """Base normalizer - preserve raw output as evidence"""
    
    def __init__(self, tool_result: ToolResult):
        self.result = tool_result
    
    def create_evidence(self) -> Evidence:
        """Create evidence object from raw output"""
        return Evidence(
            source=self.result.tool,
            raw_output=self.result.stdout,
            confidence=1.0 if self.result.status == "success" else 0.5,
            target=self.result.target,
            tool_version=None,
            caveat="Raw tool output" if self.result.status != "success" else None,
        )
    
    def normalize(self) -> List[KnowledgeItem]:
        """Override in subclass"""
        return []


class DNSResultNormalizer(ResultNormalizer):
    """Normalize DNS lookup results"""
    
    def normalize(self) -> List[KnowledgeItem]:
        """Extract IPs from DNS output"""
        if self.result.status != "success":
            return []
        
        items = []
        target = self.result.target or self.result.data.get("domain")
        
        # Handle structured data from python tool
        if "ips" in self.result.data:
            for ip in self.result.data["ips"]:
                items.append(KnowledgeItem(
                    entity_type="host",
                    entity_value=ip,
                    attributes={"hostname": target},
                    confidence=0.95,
                    source=self.result.tool,
                    evidence_id="",  # Set by knowledge store
                    discovered_by="",
                ))
        else:
            # Parse text output
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = set(re.findall(ip_pattern, self.result.stdout))
            for ip in ips:
                items.append(KnowledgeItem(
                    entity_type="host",
                    entity_value=ip,
                    attributes={"hostname": target},
                    confidence=0.95,
                    source=self.result.tool,
                    evidence_id="",
                    discovered_by="",
                ))
        
        logger.info(f"[DNSResultNormalizer] Found {len(items)} IPs")
        return items


class NmapResultNormalizer(ResultNormalizer):
    """Normalize nmap port scanning results"""
    
    def normalize(self) -> List[KnowledgeItem]:
        """Extract open ports and services"""
        if self.result.status != "success":
            return []
        
        items = []
        target = self.result.target
        
        # Parse nmap output for open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\w+)'
        
        for match in re.finditer(port_pattern, self.result.stdout):
            port = match.group(1)
            service = match.group(2)
            
            items.append(KnowledgeItem(
                entity_type="port",
                entity_value=f"{target}:{port}",
                attributes={
                    "host": target,
                    "port": int(port),
                    "protocol": "tcp",
                    "service": service,
                },
                confidence=0.95,
                source=self.result.tool,
                evidence_id="",
                discovered_by="",
            ))
        
        logger.info(f"[NmapResultNormalizer] Found {len(items)} open ports")
        return items


class HTTPResultNormalizer(ResultNormalizer):
    """Normalize HTTP response analysis"""
    
    def normalize(self) -> List[KnowledgeItem]:
        """Extract HTTP information"""
        if self.result.status != "success":
            return []
        
        items = []
        target = self.result.target
        
        status_code = self.result.data.get("status_code")
        headers = self.result.data.get("headers", {})
        
        # Create knowledge for HTTP endpoint
        items.append(KnowledgeItem(
            entity_type="http_endpoint",
            entity_value=target,
            attributes={
                "status_code": status_code,
                "headers": dict(headers),
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
            },
            confidence=0.95,
            source=self.result.tool,
            evidence_id="",
            discovered_by="",
        ))
        
        # Extract server technology from headers
        server_header = headers.get("server", "")
        if server_header:
            items.append(KnowledgeItem(
                entity_type="technology",
                entity_value=server_header,
                attributes={"type": "web_server", "endpoint": target},
                confidence=0.85,
                source=self.result.tool,
                evidence_id="",
                discovered_by="",
            ))
        
        return items


class TLSResultNormalizer(ResultNormalizer):
    """Normalize SSL/TLS certificate and vulnerability results"""
    
    def normalize(self) -> List[KnowledgeItem]:
        """Extract TLS information"""
        if self.result.status != "success":
            return []
        
        items = []
        target = self.result.target
        
        # Parse certificate information from output
        cert_pattern = r'Subject:.*CN=([^,\n]+)'
        version_pattern = r'TLSv([\d.]+)'
        
        cert_match = re.search(cert_pattern, self.result.stdout)
        if cert_match:
            items.append(KnowledgeItem(
                entity_type="tls_cert",
                entity_value=target,
                attributes={"cn": cert_match.group(1)},
                confidence=0.95,
                source=self.result.tool,
                evidence_id="",
                discovered_by="",
            ))
        
        # Extract TLS versions
        for version in re.findall(version_pattern, self.result.stdout):
            items.append(KnowledgeItem(
                entity_type="tls_version",
                entity_value=f"TLS {version}",
                attributes={"endpoint": target, "version": version},
                confidence=0.9,
                source=self.result.tool,
                evidence_id="",
                discovered_by="",
            ))
        
        return items


class TechnologyResultNormalizer(ResultNormalizer):
    """Normalize technology fingerprinting results (whatweb, etc)"""
    
    def normalize(self) -> List[KnowledgeItem]:
        """Extract identified technologies"""
        if self.result.status != "success":
            return []
        
        items = []
        target = self.result.target
        
        # Whatweb format: [Technology version]
        tech_pattern = r'\[([^\]]+)\]'
        
        for match in re.finditer(tech_pattern, self.result.stdout):
            tech_str = match.group(1)
            
            # Parse into name and version
            parts = tech_str.split()
            name = parts[0] if parts else tech_str
            version = " ".join(parts[1:]) if len(parts) > 1 else None
            
            items.append(KnowledgeItem(
                entity_type="technology",
                entity_value=name,
                attributes={
                    "endpoint": target,
                    "version": version,
                    "type": "web_component"
                },
                confidence=0.8,
                source=self.result.tool,
                evidence_id="",
                discovered_by="",
                version=version,
            ))
        
        return items


class NormalizerFactory:
    """Factory to select appropriate normalizer"""
    
    NORMALIZERS = {
        "dns_lookup_python": DNSResultNormalizer,
        "nslookup": DNSResultNormalizer,
        "dig": DNSResultNormalizer,
        "nmap": NmapResultNormalizer,
        "curl_python": HTTPResultNormalizer,
        "curl": HTTPResultNormalizer,
        "openssl": TLSResultNormalizer,
        "sslscan": TLSResultNormalizer,
        "whatweb": TechnologyResultNormalizer,
    }
    
    @classmethod
    def get_normalizer(cls, tool_result: ToolResult) -> ResultNormalizer:
        """Get appropriate normalizer for tool"""
        normalizer_class = cls.NORMALIZERS.get(
            tool_result.tool,
            ResultNormalizer  # Default: preserve only evidence
        )
        return normalizer_class(tool_result)
    
    @classmethod
    def normalize_result(cls, tool_result: ToolResult) -> tuple[Evidence, List[KnowledgeItem]]:
        """Normalize tool result to evidence + structured knowledge"""
        normalizer = cls.get_normalizer(tool_result)
        evidence = normalizer.create_evidence()
        knowledge = normalizer.normalize()
        return evidence, knowledge