from typing import Dict, List, Optional, Any
from tools.base import Tool, ToolPermission
import logging

logger = logging.getLogger(__name__)

class ToolRegistry:
    """Registry of available tools."""
    
    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self.categories: Dict[str, List[str]] = {}  # category -> list of tool names
    
    def register(self, tool: Tool, category: str = "general"):
        """Register a tool."""
        self.tools[tool.name] = tool
        if category not in self.categories:
            self.categories[category] = []
        self.categories[category].append(tool.name)
        logger.debug(f"Registered tool: {tool.name} (category: {category})")
    
    def get_tool(self, tool_name: str) -> Optional[Tool]:
        """Get a tool by name."""
        return self.tools.get(tool_name)
    
    def get_tools_by_category(self, category: str) -> List[Tool]:
        """Get tools in a category."""
        if category not in self.categories:
            return []
        return [self.tools[name] for name in self.categories[category] if name in self.tools]
    
    def get_available_tools(self) -> List[str]:
        """Get all available tool names."""
        return list(self.tools.keys())
    
    def get_tools_for_permission(self, permission: ToolPermission) -> List[str]:
        """Get tools available at permission level."""
        available = []
        for tool_name, tool in self.tools.items():
            if permission in tool.permissions:
                available.append(tool_name)
        return available

class ToolManager:
    """Manages tool execution."""
    
    def __init__(self):
        self.registry = ToolRegistry()
        self.execution_history: List[Dict[str, Any]] = []
        self._load_default_tools()
    
    def _load_default_tools(self):
        """Load default tools."""
        from tools.mock import MockReconTool, MockAPIAnalysisTool, MockSourceAnalysisTool
        
        self.registry.register(MockReconTool(), "reconnaissance")
        self.registry.register(MockAPIAnalysisTool(), "api_analysis")
        self.registry.register(MockSourceAnalysisTool(), "source_analysis")
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any],
                          permission_level: ToolPermission = ToolPermission.PASSIVE,
                          agent_id: str = "") -> Dict[str, Any]:
        """Execute a tool."""
        tool = self.registry.get_tool(tool_name)
        if not tool:
            logger.error(f"Tool not found: {tool_name}")
            return {"status": "failed", "error": f"Tool not found: {tool_name}"}
        
        logger.info(f"Executing tool {tool_name} with params: {params}")
        
        result = await tool.safe_execute(params, permission_level)
        
        # Record execution
        execution_record = {
            "tool_name": tool_name,
            "agent_id": agent_id,
            "params": params,
            "result": result
        }
        self.execution_history.append(execution_record)
        
        return result
    
    def register_tool(self, tool: Tool, category: str = "general"):
        """Register a new tool."""
        self.registry.register(tool, category)
    
    def get_available_tools(self) -> List[str]:
        """Get all available tools."""
        return self.registry.get_available_tools()
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a tool."""
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return None
        
        return {
            "name": tool.name,
            "description": tool.description,
            "permissions": [p.value for p in tool.permissions],
            "input_schema": {
                "required": tool.input_schema.required_params,
                "optional": tool.input_schema.optional_params or {}
            }
        }
    
    def get_execution_history(self) -> List[Dict[str, Any]]:
        """Get tool execution history."""
        return self.execution_history
