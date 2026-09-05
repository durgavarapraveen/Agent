import asyncio
import logging
from typing import Optional
from core.common.schemas import ToolInvocation, ToolResult
from core.security.authorization import AuthContext
from core.security.resource_limiter import ResourceLimiter

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
        from aiolimiter import AsyncLimiter
        self.rate_limiter = AsyncLimiter(max_rate=3, time_period=60)
        self._last_target_hit: dict = {}  # target -> timestamp for per-target throttling
        from core.tools.tool_router import ToolRouter
        self.router = ToolRouter(self.registry)
        from core.tools.rate_limiter import get_rate_limiter
        self.adaptive_limiter = get_rate_limiter()
    
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
            from core.common.schemas import ErrorInfo, ErrorType
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
            from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
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
            if invocation.tool_id and not self._is_tool_available(invocation.tool_id):
                raise FileNotFoundError(f"Tool binary for {invocation.tool_id} is not installed or available.")

            # Adaptive per-target throttling (WAF/rate-limit aware)
            target_key = invocation.target or ""
            if target_key:
                await self.adaptive_limiter.wait_if_needed(target_key)

            logger.info(f"Executing: operation={invocation.operation} tool_id={invocation.tool_id} target={invocation.target}")
            
            timeout_val = invocation.params.get("timeout", 900)
            
            async with self.rate_limiter:
                result = await asyncio.wait_for(
                    self._execute_tool(invocation, auth_context),
                    timeout=timeout_val
                )
            
            # Record result for adaptive rate limiting
            if target_key:
                _rc = getattr(result, 'returncode', 0) or 0
                _stdout = str(getattr(result, 'stdout', '') or '')[:1000]
                _stderr = str(getattr(result, 'stderr', '') or '')[:1000]
                await self.adaptive_limiter.record_result(
                    target_key, result.success, status_code=_rc,
                    stdout=_stdout, stderr=_stderr,
                )

            if not result.success:
                err_detail = result.error.message if result.error else ""
                stderr_detail = getattr(result, "stderr", "") or ""
                msg = f"{err_detail} | stderr={stderr_detail[:500]}" if stderr_detail else (err_detail or "Tool execution failed")
                raise RuntimeError(msg)
                
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
            from core.security.authorization import AuthContext
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
        is_restricted = getattr(tool_def, 'restricted', False) if tool_def else False
        if is_restricted and not auth_context.has_elevated_privilege:
            return False
        
        return True
    
    async def _execute_tool(self, invocation: ToolInvocation,
                           auth_context: AuthContext) -> ToolResult:
        """Route to ToolRouter (next layer)"""
        return await self.router.route_and_execute(invocation, auth_context)
    
    async def _handle_timeout(self, invocation: ToolInvocation,
                             auth_context: AuthContext) -> ToolResult:
        """Handle tool execution timeout"""
        from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
        from core.common.error_translator import ErrorTranslator
        
        tool_id = invocation.tool_id or invocation.operation or "unknown"
        translation = ErrorTranslator.translate(tool_id, "timeout", exit_code=1, target=invocation.target)
        
        return SchemaToolResult(
            tool=tool_id,
            capability=invocation.operation or "unknown",
            status=ToolExecutionStatus.TIMEOUT,
            target=invocation.target,
            data={"error_human": translation.get("formatted_report")},
            error=ErrorInfo(
                error_type=ErrorType.TIMEOUT,
                message=f"Tool {tool_id} timed out after 300s",
                retryable=True,
                tool=tool_id
            )
        )
    
    async def _handle_error(self, invocation: ToolInvocation, 
                           auth_context: AuthContext, error: Exception) -> ToolResult:
        """Try fallback tool"""
        tool_id = invocation.tool_id or invocation.operation or "unknown"
        error_msg = str(error)
        
        from core.common.error_translator import ErrorTranslator
        translation = ErrorTranslator.translate(tool_id, error_msg, exit_code=1, target=invocation.target)
        logger.error(f"Translated Error: {translation['formatted_report']}")
        
        tool_def = self.registry.get(tool_id)
        fallback_tools = list(getattr(tool_def, "fallback_tools", [])) if tool_def else []
        
        alt_tool = translation.get("alternative_tool")
        if alt_tool and alt_tool not in fallback_tools and alt_tool != tool_id:
            fallback_tools.insert(0, alt_tool)
            
        if fallback_tools:
            logger.info(f"Trying fallbacks for {tool_id}: {fallback_tools}")
            
            for fallback_id in fallback_tools:
                if not self._is_tool_available(fallback_id):
                    continue
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
                    if result.success:
                        result.fallback_used = fallback_id
                        return result
                    else:
                        logger.warning(f"Fallback {fallback_id} returned failure: {result.error.message if result.error else 'Unknown'}")
                except Exception as e:
                    logger.warning(f"Fallback {fallback_id} also failed: {e}")
                    continue
        
        # No fallback worked
        from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
        return SchemaToolResult(
            tool=tool_id,
            capability=invocation.operation or "unknown",
            status=ToolExecutionStatus.FAILED,
            target=invocation.target,
            data={"error_human": translation.get("formatted_report")},
            error=ErrorInfo(
                error_type=ErrorType.EXECUTION_ERROR,
                message=translation.get("formatted_report", error_msg),
                retryable=translation.get("should_retry", False),
                tool=tool_id
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

    def _is_tool_available(self, tool_id: str) -> bool:
        """Pre-flight check to verify tool is available."""
        if not tool_id:
            return True
        tool_def = self.registry.get(tool_id)
        if tool_def and tool_def.__class__.__name__ == "KaliTool":
            from agents.kali_executor import KaliDockerExecutor
            if KaliDockerExecutor.get_container(auto_create=False):
                return True
            import shutil
            if not shutil.which(tool_id) and not shutil.which(tool_id.lower()):
                logger.warning(f"Pre-flight check failed: {tool_id} binary not found in PATH and no Kali container")
                return False
        return True
