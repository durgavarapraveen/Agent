"""
Tool definitions and capability registry.
Single source of truth for tool/capability mapping.
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from core.schemas import CapabilityType

logger = logging.getLogger(__name__)


class ToolType(str, Enum):
    KALI = "kali"
    PYTHON = "python"
    CUSTOM = "custom"


class OperationType(str, Enum):
    READ_ONLY = "READ_ONLY"
    ENVIRONMENT_MODIFICATION = "ENVIRONMENT_MODIFICATION"
    DESTRUCTIVE = "DESTRUCTIVE"


@dataclass
class ToolDefinition:
    """Complete tool specification"""
    name: str
    executable: str
    capability: CapabilityType
    tool_type: ToolType
    operation_type: OperationType = OperationType.READ_ONLY
    available: bool = True
    version: Optional[str] = None
    execution_adapter: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    timeout_default: int = 120
    description: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    
    def is_available(self) -> bool:
        """Check if tool is available for use"""
        return self.available and not self.dependencies
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "executable": self.executable,
            "capability": self.capability.value,
            "tool_type": self.tool_type.value,
            "available": self.available,
            "version": self.version,
            "dependencies": self.dependencies,
            "timeout_default": self.timeout_default,
            "operation_type": self.operation_type.value,
        }


class CapabilityRegistry:
    """Maps capabilities to available tool implementations"""
    
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self.capabilities: Dict[CapabilityType, List[str]] = {}  # capability -> [tool_names]
        self._init_default_tools()
    
    def _init_default_tools(self) -> None:
        """Initialize standard tools and capabilities"""
        
        # DNS Enumeration
        self.register_tool(ToolDefinition(
            name="dns_lookup_python",
            executable="python",
            capability=CapabilityType.DNS_ENUMERATION,
            tool_type=ToolType.PYTHON,
            operation_type=OperationType.READ_ONLY,
            description="Python socket-based DNS resolution"
        ))
        
        self.register_tool(ToolDefinition(
            name="nslookup",
            executable="nslookup",
            capability=CapabilityType.DNS_ENUMERATION,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="DNS query tool"
        ))
        
        self.register_tool(ToolDefinition(
            name="dig",
            executable="dig",
            capability=CapabilityType.DNS_ENUMERATION,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="DNS lookup utility"
        ))
        
        # Port Scanning
        self.register_tool(ToolDefinition(
            name="nmap",
            executable="nmap",
            capability=CapabilityType.PORT_SCANNING,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="Network mapper - port scanning"
        ))
        
        # TLS Analysis
        self.register_tool(ToolDefinition(
            name="openssl",
            executable="openssl",
            capability=CapabilityType.TLS_ANALYSIS,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="SSL/TLS certificate analysis"
        ))
        
        self.register_tool(ToolDefinition(
            name="sslscan",
            executable="sslscan",
            capability=CapabilityType.TLS_ANALYSIS,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="SSL/TLS vulnerability scanner"
        ))
        
        # Technology Fingerprinting
        self.register_tool(ToolDefinition(
            name="whatweb",
            executable="whatweb",
            capability=CapabilityType.TECHNOLOGY_FINGERPRINTING,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="Web technology identification"
        ))
        
        # HTTP Analysis
        self.register_tool(ToolDefinition(
            name="curl_python",
            executable="python",
            capability=CapabilityType.HTTP_ANALYSIS,
            tool_type=ToolType.PYTHON,
            operation_type=OperationType.READ_ONLY,
            description="HTTP request tool (httpx)"
        ))
        
        self.register_tool(ToolDefinition(
            name="curl",
            executable="curl",
            capability=CapabilityType.HTTP_ANALYSIS,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="Command-line HTTP client"
        ))
        
        # Vulnerability Scanning
        self.register_tool(ToolDefinition(
            name="nuclei",
            executable="nuclei",
            capability=CapabilityType.VULNERABILITY_SCANNING,
            tool_type=ToolType.KALI,
            operation_type=OperationType.READ_ONLY,
            description="Template-based vulnerability scanner"
        ))
    
    def register_tool(self, tool: ToolDefinition) -> None:
        """Register a tool"""
        self.tools[tool.name] = tool
        
        if tool.capability not in self.capabilities:
            self.capabilities[tool.capability] = []
        
        self.capabilities[tool.capability].append(tool.name)
        logger.info(f"[ToolRegistry] Registered tool: {tool.name} -> {tool.capability.value}")
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Get tool by name"""
        return self.tools.get(name)
    
    def get_tools_for_capability(self, capability: CapabilityType) -> List[ToolDefinition]:
        """Get available tools for a capability"""
        tool_names = self.capabilities.get(capability, [])
        tools = []
        for name in tool_names:
            tool = self.tools.get(name)
            if tool and tool.is_available():
                tools.append(tool)
        return tools
    
    def resolve_capability(self, capability: CapabilityType) -> Optional[ToolDefinition]:
        """
        Resolve capability to a tool.
        Returns first available tool for capability, or None.
        """
        tools = self.get_tools_for_capability(capability)
        if tools:
            return tools[0]
        
        logger.warning(f"[ToolRegistry] No available tool for capability: {capability.value}")
        return None
    
    def resolve_alternative_tool(self, tool_name: str) -> Optional[ToolDefinition]:
        """Get alternative tool for same capability"""
        tool = self.get_tool(tool_name)
        if not tool:
            return None
        
        available_for_cap = self.get_tools_for_capability(tool.capability)
        alternatives = [t for t in available_for_cap if t.name != tool_name]
        
        if alternatives:
            logger.info(f"[ToolRegistry] Alternative for {tool_name}: {alternatives[0].name}")
            return alternatives[0]
        
        return None
    
    def resolve_tool_alternative(self, tool_name: str) -> Optional[ToolDefinition]:
        """Alias for resolve_alternative_tool (for backward compatibility)"""
        return self.resolve_alternative_tool(tool_name)
    
    def mark_tool_unavailable(self, tool_name: str) -> None:
        """Mark tool as unavailable (e.g., installation failed)"""
        if tool_name in self.tools:
            self.tools[tool_name].available = False
            logger.warning(f"[ToolRegistry] Marked tool unavailable: {tool_name}")
    
    def mark_tool_available(self, tool_name: str, version: Optional[str] = None) -> None:
        """Mark tool as available"""
        if tool_name in self.tools:
            self.tools[tool_name].available = True
            if version:
                self.tools[tool_name].version = version
            logger.info(f"[ToolRegistry] Marked tool available: {tool_name}")
    
    def get_all_available_tools(self) -> List[ToolDefinition]:
        """Get all available tools"""
        return [t for t in self.tools.values() if t.is_available()]
    
    def get_all_capabilities(self) -> List[CapabilityType]:
        """Get all capabilities with available tools"""
        return [
            cap for cap, tools in self.capabilities.items()
            if any(self.tools[t].is_available() for t in tools if t in self.tools)
        ]
    
    def to_dict(self) -> Dict:
        """Serialize registry"""
        return {
            "tools": {name: tool.to_dict() for name, tool in self.tools.items()},
            "capabilities": {
                cap.value: self.capabilities[cap]
                for cap in self.capabilities
            }
        }