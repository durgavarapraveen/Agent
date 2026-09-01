import logging
from typing import Dict, Any, List, Optional
from core.domain.endpoint import Endpoint
from core.fuzzing.models import ToolResult, ToolStatus
from core.fuzzing.adapters import SQLMapAdapter, NucleiAdapter, DalfoxAdapter

logger = logging.getLogger(__name__)

class FuzzerOrchestrator:
    def __init__(self, target: str):
        self.target = target
        
        # Tool registry: test_type -> list of tools in fallback priority order
        self.tool_registry = {
            "sqli": ["sqlmap", "nuclei", "dalfox"],
            "xss": ["dalfox", "nuclei"],
            "idor": ["custom", "manual"]
        }

    def _get_adapter(self, tool_name: str, endpoint: Endpoint):
        if tool_name == "sqlmap":
            return SQLMapAdapter(endpoint, self.target)
        elif tool_name == "nuclei":
            return NucleiAdapter(endpoint, self.target)
        elif tool_name == "dalfox":
            return DalfoxAdapter(endpoint, self.target)
        else:
            raise ValueError(f"Unknown tool adapter: {tool_name}")

    def get_applicable_tools(self, test_type: str) -> List[str]:
        return self.tool_registry.get(test_type, [])

    def execute_tool(self, tool_name: str, endpoint: Endpoint, params: Dict[str, Any]) -> ToolResult:
        try:
            adapter = self._get_adapter(tool_name, endpoint)
            logger.info(f"Executing {tool_name} on {endpoint.url}")
            return adapter.execute(params)
        except Exception as e:
            logger.error(f"Failed to instantiate or execute adapter {tool_name}: {e}")
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e)
            )

    def run_fuzzing(self, test_type: str, endpoint: Endpoint, params: Dict[str, Any]) -> ToolResult:
        """
        Orchestrates tool execution with automatic fallback chain logic.
        """
        tools = self.get_applicable_tools(test_type)
        if not tools:
            logger.warning(f"No tools registered for test type: {test_type}")
            return ToolResult(tool_name="none", status=ToolStatus.ERROR, evidence="No tools registered")

        for i, tool_name in enumerate(tools):
            # Known unsupported mock tools like "custom" or "manual" are treated as exhausted fallback chain
            if tool_name in ["custom", "manual"]:
                logger.warning(f"Fallback reached manual/custom phase for {test_type}")
                return ToolResult(tool_name=tool_name, status=ToolStatus.ERROR, evidence="Manual analysis required")
                
            result = self.execute_tool(tool_name, endpoint, params)
            
            if result.status == ToolStatus.SUCCESS:
                # Primary tool succeeded
                return result
            else:
                logger.warning(f"Tool {tool_name} failed with status {result.status}. Attempting fallback...")
                
        logger.error(f"All fallback tools exhausted for {test_type} on {endpoint.url}")
        return ToolResult(tool_name="exhausted", status=ToolStatus.ERROR, evidence="All tools failed")
