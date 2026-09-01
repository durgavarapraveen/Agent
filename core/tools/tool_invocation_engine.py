import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from core.common.schemas import ToolInvocation, ToolResult

logger = logging.getLogger(__name__)

class InvocationSource(Enum):
    TASK_MANAGER = "TASK_MANAGER"
    TOOL_USE = "TOOL_USE"
    MANUAL = "MANUAL"

@dataclass
class ToolInvocationContext:
    tool_id: Optional[str]
    operation: Optional[str]
    target: str
    params: Dict[str, Any]
    session_id: str
    source: InvocationSource
    auth_context: Any
    audit_context: Optional[Dict] = None

class ToolInvocationEngine:
    def __init__(self, tool_gateway):
        self.gateway = tool_gateway

    async def invoke(self, context: ToolInvocationContext) -> ToolResult:
        """
        Single entry point for tool invocations.
        Routes to ToolGateway and returns normalized ToolResult.
        """
        logger.info(f"Tool invocation started from source: {context.source.name}")
        
        # Convert engine context to gateway schema
        invocation = ToolInvocation(
            tool_id=context.tool_id or "",
            operation=context.operation or "",
            target=context.target,
            params=context.params,
            session_id=context.session_id,
            audit_context=context.audit_context
        )

        try:
            # Both paths converge here at ToolGateway for security, caching, audit trail
            result = await self.gateway.execute(invocation, context.auth_context)
            
            if not result.success:
                self._handle_tool_failure(invocation, result)
            else:
                stdout_len = len(str(result.stdout or ""))
                stderr_len = len(str(result.stderr or ""))
                logger.info(f"Tool invocation completed with success: {result.success} | stdout: {stdout_len} bytes | stderr: {stderr_len} bytes")
                
            return result
        except Exception as e:
            logger.error(f"Critical engine failure executing {invocation.tool_id}: {e}", exc_info=True)
            from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
            result = SchemaToolResult(
                tool=invocation.tool_id or invocation.operation or "unknown",
                capability=invocation.operation or "unknown",
                status=ToolExecutionStatus.FAILED,
                target=invocation.target,
                error=ErrorInfo(
                    error_type=ErrorType.EXECUTION_ERROR,
                    message=f"Critical engine failure: {str(e)}",
                    tool=invocation.tool_id
                )
            )
            self._handle_tool_failure(invocation, result)
            return result

    def _handle_tool_failure(self, invocation: ToolInvocation, result: ToolResult):
        """Diagnostic logging for failed tools, outputting stderr/stdout captures."""
        logger.warning(f"TASK_FAILED: Tool={result.tool} target={result.target} status={result.status}")
        if result.error:
            logger.warning(f"Error Type: {result.error.error_type.name} - {result.error.message}")
        if getattr(result, "stderr", None):
            logger.warning(f"Stderr capture: {str(result.stderr)[:500]}")
        if getattr(result, "stdout", None):
            logger.info(f"Stdout capture: {str(result.stdout)[:500]}")

    async def invoke_from_capability(
        self, capability: str, target: str, params: Dict[str, Any], 
        session_id: str, auth_context: Any
    ) -> ToolResult:
        """
        Approach A:
        Called by TaskManager when DeepSeek requests a capability (e.g., 'port_scan').
        The router within or alongside the gateway will select the actual tool.
        """
        context = ToolInvocationContext(
            tool_id=None,
            operation=capability,
            target=target,
            params=params,
            session_id=session_id,
            source=InvocationSource.TASK_MANAGER,
            auth_context=auth_context
        )
        return await self.invoke(context)

    async def invoke_tool_directly(
        self, tool_id: str, target: str, params: Dict[str, Any], 
        session_id: str, auth_context: Any
    ) -> ToolResult:
        """
        Approach B:
        Called by Claude when it explicitly specifies a tool (e.g., 'nmap_scan').
        Skips router capability selection and goes directly to ToolGateway.
        """
        context = ToolInvocationContext(
            tool_id=tool_id,
            operation=tool_id,  # Fallback to tool_id as operation to satisfy underlying router temporarily
            target=target,
            params=params,
            session_id=session_id,
            source=InvocationSource.TOOL_USE,
            auth_context=auth_context
        )
        return await self.invoke(context)
