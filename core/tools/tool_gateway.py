import asyncio
import time
import logging
from typing import Dict, Any, Optional
from core.schemas import ToolInvocation, ToolResult, ToolDefinition
from core.audit_logger import AuditLogger
from core.authorization import AuthContext
from core.resource_limiter import ResourceLimiter

logger = logging.getLogger(__name__)

class ToolGateway:
    """
    Universal tool access point (both A and B paths feed here).
    
    Responsibilities:
    1. Authorization (can user run this tool on this target?)
    2. Scope validation (is target in authorized scope?)
    3. Caching (avoid re-running identical tool calls)
    4. Audit logging (who ran what, when, result)
    5. Resource limiting (CPU, memory, network)
    6. Error recovery (call fallback tools)
    """
    
    def __init__(self, tool_registry, cache_db, audit_logger):
        self.registry = tool_registry
        self.cache = cache_db
        self.audit = audit_logger
        self.resource_limiter = ResourceLimiter()
    
    async def execute(self, invocation: ToolInvocation, 
                     auth_context: AuthContext) -> ToolResult:
        """
        Main entry point (used by both Approach A and B).
        
        Flow:
        1. Validate auth & scope
        2. Check cache
        3. Check resources
        4. Execute tool
        5. Normalize result
        6. Update cache
        7. Audit log
        8. Handle errors & fallbacks
        """
        
        # STEP 1: Authorization & Scope
        if not await self._authorize(invocation, auth_context):
            self.audit.log_denial(invocation, auth_context)
            from core.schemas import ErrorInfo, ErrorType
            return ToolResult(
                tool=invocation.tool_id or invocation.operation or "unknown",
                capability=invocation.operation or "unknown",
                status="failed",
                target=invocation.target,
                error=ErrorInfo(error_type=ErrorType.SCOPE_VIOLATION, message="Authorization denied", details={"target": invocation.target})
            )
        
        # STEP 2: Cache Lookup
        cache_key = self._make_cache_key(invocation)
        cached_result = await self.cache.get(cache_key)
        if cached_result:
            logger.info(f"Cache HIT: {invocation.tool_id}")
            self.audit.log_cache_hit(cache_key, invocation)
            return cached_result
        
        # STEP 3: Resource Check
        if not self.resource_limiter.can_allocate(invocation.tool_id):
            logger.warning(f"Resource limit: {invocation.tool_id}")
            from core.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
            return SchemaToolResult(
                tool=invocation.tool_id or invocation.operation or "unknown",
                capability=invocation.operation or "unknown",
                status=ToolExecutionStatus.FAILED,
                target=invocation.target,
                error=ErrorInfo(
                    error_type=ErrorType.EXECUTION_ERROR,
                    message="Resource limit exceeded",
                    tool=invocation.tool_id
                )
            )
        
        # STEP 4: Execute (with timeout)
        try:
            logger.info(f"Executing: operation={invocation.operation} tool_id={invocation.tool_id} target={invocation.target}")
            result = await asyncio.wait_for(
                self._execute_tool(invocation, auth_context),
                timeout=300  # 5 min timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Timeout: {invocation.tool_id}")
            result = await self._handle_timeout(invocation, auth_context)
        except Exception as e:
            logger.error(f"Error: {invocation.tool_id}: {e}")
            result = await self._handle_error(invocation, auth_context, e)
        
        # STEP 5: Normalize Result
        result = await self._normalize_result(result, invocation)
        
        # STEP 6: Cache It (only cache successes — failed results should not poison future calls)
        if result.success:
            await self.cache.set(cache_key, result)
        else:
            logger.info(f"Skipping cache for failed result: operation={invocation.operation} tool={invocation.tool_id}")
        
        # STEP 7: Audit
        self.audit.log_tool_execution(invocation, result, auth_context)
        
        return result
    
    async def _authorize(self, invocation: ToolInvocation, 
                        auth_context: Optional[AuthContext]) -> bool:
        """Check: user can run this tool on this target"""
        if auth_context is None:
            from core.authorization import AuthContext
            allowed_tools = list(self.registry.tools.keys()) if hasattr(self.registry, 'tools') else []
            auth_context = AuthContext(allowed_tools=allowed_tools, has_elevated_privilege=True)
        
        # Check tool in scope
        if invocation.tool_id and auth_context.allowed_tools and invocation.tool_id not in auth_context.allowed_tools:
            return False
        
        # Check target in scope
        if not auth_context.can_scan_target(invocation.target):
            return False
        
        # Check specific tool restrictions
        tool_def = self.registry.get(invocation.tool_id) if invocation.tool_id else None
        if tool_def and tool_def.restricted and not auth_context.has_elevated_privilege:
            return False
        
        return True
    
    async def _execute_tool(self, invocation: ToolInvocation, 
                           auth_context: AuthContext) -> ToolResult:
        """Route to ToolRouter (next layer)"""
        from core.tool_router import ToolRouter
        
        router = ToolRouter(self.registry)
        return await router.route_and_execute(invocation, auth_context)
    
    async def _handle_timeout(self, invocation: ToolInvocation,
                             auth_context: AuthContext) -> ToolResult:
        """Handle tool execution timeout"""
        from core.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
        return SchemaToolResult(
            tool=invocation.tool_id or invocation.operation or "unknown",
            capability=invocation.operation or "unknown",
            status=ToolExecutionStatus.TIMEOUT,
            target=invocation.target,
            error=ErrorInfo(
                error_type=ErrorType.TIMEOUT,
                message=f"Tool {invocation.tool_id or invocation.operation} timed out after 300s",
                retryable=True,
                tool=invocation.tool_id
            )
        )
    
    async def _handle_error(self, invocation: ToolInvocation, 
                           auth_context: AuthContext, error: Exception) -> ToolResult:
        """Try fallback tool"""
        tool_def = self.registry.get(invocation.tool_id)
        
        if tool_def and tool_def.fallback_tools:
            logger.info(f"Trying fallback for {invocation.tool_id}")
            
            for fallback_id in tool_def.fallback_tools:
                try:
                    fallback_invocation = ToolInvocation(
                        tool_id=fallback_id,
                        operation=invocation.operation,
                        target=invocation.target,
                        params=invocation.params,
                        session_id=invocation.session_id,
                        audit_context=invocation.audit_context
                    )
                    
                    result = await self._execute_tool(fallback_invocation, auth_context)
                    result.fallback_used = invocation.tool_id
                    return result
                except Exception as e:
                    logger.warning(f"Fallback {fallback_id} also failed: {e}")
                    continue
        
        # No fallback worked
        from core.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
        return SchemaToolResult(
            tool=invocation.tool_id or invocation.operation or "unknown",
            capability=invocation.operation or "unknown",
            status=ToolExecutionStatus.FAILED,
            target=invocation.target,
            error=ErrorInfo(
                error_type=ErrorType.EXECUTION_ERROR,
                message=str(error),
                tool=invocation.tool_id
            )
        )
    
    async def _normalize_result(self, result: ToolResult, 
                               invocation: ToolInvocation) -> ToolResult:
        """Parse raw tool output into canonical findings"""
        # We skip normalization here because ToolGateway doesn't have a KnowledgeStore.
        # The central brain handles evidence and knowledge parsing at a higher level.
        return result
    
    def _make_cache_key(self, invocation: ToolInvocation) -> str:
        """Hash: operation + tool_id + target + params = cache key"""
        import hashlib
        import json
        
        key = f"{invocation.operation}:{invocation.tool_id}:{invocation.target}:{json.dumps(invocation.params, sort_keys=True)}"
        return hashlib.md5(key.encode()).hexdigest()