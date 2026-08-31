import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ToolUseExecutor:
    """
    When Claude generates tool_use blocks, this handles them.
    Routes through same ToolInvocationEngine as DeepSeek does.
    """
    
    def __init__(self, invocation_engine):
        self.invocation_engine = invocation_engine
    
    async def execute_claude_tool_call(self, tool_name: str, tool_input: dict, 
                                      session_id: str, auth_context: Any) -> dict:
        """Claude called tool_use block → execute via invocation engine"""
        
        logger.info(f"Executing Claude tool_use for {tool_name}")
        
        # Execute through the unified engine
        result = await self.invocation_engine.invoke_tool_directly(
            tool_id=tool_name,
            target=tool_input.get("target", ""),
            params=tool_input,
            session_id=session_id,
            auth_context=auth_context
        )
        
        return {
            "success": getattr(result, "success", getattr(result, "status", "") == "SUCCESS"),
            "findings": getattr(result, "findings", getattr(result, "data", {})),
            "errors": getattr(result, "errors", [getattr(result, "error", "")] if getattr(result, "error", None) else []),
            "execution_time_sec": getattr(result, "execution_time_sec", getattr(result, "duration_seconds", 0.0))
        }
    
    async def handle_claude_response(self, response: Any, auth_context: Any, session_id: str) -> List[dict]:
        """Process Claude response, execute any tool_use blocks"""
        
        results = []
        
        for content_block in response.content:
            if getattr(content_block, "type", "") == "tool_use":
                result = await self.execute_claude_tool_call(
                    tool_name=content_block.name,
                    tool_input=content_block.input,
                    session_id=session_id,
                    auth_context=auth_context
                )
                
                results.append({
                    "tool_use_id": content_block.id,
                    "result": result
                })
        
        return results