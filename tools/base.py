from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, List
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ToolPermission(Enum):
    PASSIVE = "passive"          # Information gathering only
    SAFE_ACTIVE = "safe_active"  # Non-destructive testing
    FULL = "full"                # Full authorization

@dataclass
class ToolInputSchema:
    """Input parameter schema."""
    required_params: Dict[str, str]  # param_name -> type
    optional_params: Dict[str, str] = None
    
    def validate(self, params: Dict[str, Any]) -> bool:
        """Validate params against schema."""
        for req_param, param_type in self.required_params.items():
            if req_param not in params:
                return False
        return True

@dataclass
class ToolOutputSchema:
    """Output format specification."""
    return_type: str
    description: str

class Tool(ABC):
    """Base class for all tools."""
    
    def __init__(self, name: str, description: str, 
                 input_schema: ToolInputSchema,
                 output_schema: ToolOutputSchema,
                 permissions: List[ToolPermission] = None):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.permissions = permissions or [ToolPermission.PASSIVE]
        self.last_result = None
        self.call_count = 0
    
    @abstractmethod
    async def execute(self, **params) -> Dict[str, Any]:
        """Execute the tool with given parameters."""
        pass
    
    async def safe_execute(self, params: Dict[str, Any], 
                          permission_level: ToolPermission) -> Dict[str, Any]:
        """Execute with permission checking."""
        # Check permissions
        if permission_level not in self.permissions:
            return {
                "status": "failed",
                "error": f"Tool {self.name} not allowed at permission level {permission_level.value}"
            }
        
        # Validate input
        if not self.input_schema.validate(params):
            return {
                "status": "failed",
                "error": f"Invalid parameters for {self.name}: {params}"
            }
        
        # Execute
        try:
            self.call_count += 1
            result = await self.execute(**params)
            self.last_result = result
            return result
        except Exception as e:
            logger.error(f"Tool {self.name} execution failed: {e}")
            return {
                "status": "failed",
                "error": str(e)
            }

class MockTool(Tool):
    """Mock tool for testing/demo."""
    
    def __init__(self, name: str, mock_result: Dict[str, Any]):
        input_schema = ToolInputSchema(required_params={}, optional_params={})
        output_schema = ToolOutputSchema(return_type="dict", description="Mock result")
        super().__init__(name, f"Mock {name}", input_schema, output_schema)
        self.mock_result = mock_result
    
    async def execute(self, **params) -> Dict[str, Any]:
        return self.mock_result

class ToolResult:
    """Represents result from tool execution."""
    
    def __init__(self, tool_name: str, success: bool, data: Dict[str, Any], 
                 error: Optional[str] = None, evidence_type: str = "tool_output"):
        self.tool_name = tool_name
        self.success = success
        self.data = data
        self.error = error
        self.evidence_type = evidence_type
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error
        }
