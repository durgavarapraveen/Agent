import asyncio
import logging
from typing import Dict, Any, Optional, List
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
    _TOOL_TO_OP = {
        "nmap": "port_scanning", "masscan": "port_scanning",
        "subfinder": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration", "dnsenum": "dns_enumeration",
        "fierce": "dns_enumeration", "dig": "dns_intelligence", "whois": "dns_intelligence",
        "httpx": "technology_fingerprinting", "whatweb": "technology_fingerprinting",
        "wafw00f": "waf_detection",
        "nuclei": "vulnerability_scanning", "nikto": "vulnerability_scanning",
        "sqlmap": "sql_injection", "wpscan": "vulnerability_scanning",
        "ffuf": "endpoint_discovery", "gobuster": "endpoint_discovery",
        "feroxbuster": "endpoint_discovery", "dirb": "endpoint_discovery",
        "dirsearch": "endpoint_discovery", "katana": "web_crawling",
        "sslscan": "tls_analysis", "sslyze": "tls_analysis",
        "hydra": "authentication_testing", "arjun": "parameter_discovery",
        "dalfox": "xss_scanning", "theharvester": "employee_enumeration",
        "curl": "http_analysis",
    }

    def __init__(self, tool_gateway):
        self.gateway = tool_gateway

    async def invoke(self, context: ToolInvocationContext) -> ToolResult:
        """
        Single entry point for tool invocations.
        Routes to ToolGateway and returns normalized ToolResult.
        """
        logger.info(f"Tool invocation started from source: {context.source.name}")
        
        # Convert engine context to gateway schema
        resolved_operation = context.operation or ""
        resolved_tool_id = context.tool_id or ""
        # If operation equals tool_id (no capability mapping was applied upstream),
        # resolve it so the router's op_map can find the right tool set.
        if resolved_operation and resolved_operation == resolved_tool_id:
            mapped = self._TOOL_TO_OP.get(resolved_operation)
            if mapped:
                resolved_operation = mapped
        invocation = ToolInvocation(
            tool_id=resolved_tool_id,
            operation=resolved_operation,
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
                _tool = getattr(invocation, "tool_id", None) or getattr(invocation, "tool", "?")
                _tgt = getattr(invocation, "target", "") or ""
                logger.info(
                    f"TOOL_OK tool={_tool} target={_tgt} | stdout: {stdout_len} bytes | "
                    f"stderr: {stderr_len} bytes"
                )
                
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

    # Capabilities where running ALL tools and merging results is better than picking one
    MULTI_TOOL_CAPABILITIES = {
        "dns_enumeration", "subdomain_enumeration", "port_discovery",
        "port_scanning", "endpoint_discovery", "technology_fingerprinting",
    }

    async def invoke_all_for_capability(
        self, capability: str, target: str, params: Dict[str, Any],
        session_id: str, auth_context: Any,
        tool_ids: List[str] = None,
    ) -> ToolResult:
        """
        Run multiple tools for a discovery capability concurrently and merge
        their results. Returns a single merged ToolResult. Tools that fail
        are logged but don't block the aggregate.
        """
        if not tool_ids:
            if hasattr(self.gateway, 'router') and hasattr(self.gateway.router, '_get_tools_for_operation'):
                tool_objs = self.gateway.router._get_tools_for_operation(capability)
                tool_ids = [t.name for t in tool_objs]
            if not tool_ids:
                return await self.invoke_from_capability(capability, target, params, session_id, auth_context)

        logger.info(f"MULTI_TOOL_SWEEP: capability={capability} tools={tool_ids}")

        async def _run_one(tool_id: str) -> Optional[ToolResult]:
            try:
                ctx = ToolInvocationContext(
                    tool_id=tool_id, operation=capability,
                    target=target, params=dict(params),
                    session_id=session_id, source=InvocationSource.TASK_MANAGER,
                    auth_context=auth_context,
                )
                r = await self.invoke(ctx)
                if r.success:
                    logger.info(f"MULTI_TOOL_OK: {tool_id} stdout={len(str(r.stdout or ''))}b")
                else:
                    logger.warning(f"MULTI_TOOL_FAIL: {tool_id} — {getattr(r.error, 'message', '') if r.error else 'unknown'}")
                return r
            except Exception as e:
                logger.warning(f"MULTI_TOOL_ERROR: {tool_id} — {e}")
                return None

        results = await asyncio.gather(*[_run_one(tid) for tid in tool_ids], return_exceptions=False)
        good = [r for r in results if r and r.success]

        if not good:
            # Fall back to best single-tool result or first failure
            any_result = next((r for r in results if r), None)
            if any_result:
                return any_result
            return await self.invoke_from_capability(capability, target, params, session_id, auth_context)

        # Merge: combine stdout and data dicts
        merged_stdout_parts = []
        merged_data: Dict[str, Any] = {}
        tools_used = []

        for r in good:
            tools_used.append(getattr(r, 'tool', '?'))
            if r.stdout:
                merged_stdout_parts.append(f"--- [{getattr(r, 'tool', '?')}] ---\n{r.stdout}")
            rdata = getattr(r, 'data', None) or {}
            if isinstance(rdata, dict):
                for k, v in rdata.items():
                    if isinstance(v, list):
                        existing = merged_data.get(k, [])
                        if isinstance(existing, list):
                            seen = set(str(x) for x in existing)
                            for item in v:
                                if str(item) not in seen:
                                    existing.append(item)
                                    seen.add(str(item))
                            merged_data[k] = existing
                        else:
                            merged_data[k] = v
                    elif k not in merged_data:
                        merged_data[k] = v

        best = good[0]
        best.stdout = "\n".join(merged_stdout_parts)
        best.data = merged_data
        best.tool = "+".join(tools_used)
        logger.info(f"MULTI_TOOL_MERGED: {len(good)}/{len(tool_ids)} tools succeeded, "
                     f"merged data keys={list(merged_data.keys())}")
        return best

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
