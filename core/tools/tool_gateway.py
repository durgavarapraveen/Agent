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
        
        # STEP 0 (P0-9): Unified deterministic action gate — schema -> scope ->
        # precondition -> duplicate -> risk. Rejects malformed / out-of-scope LLM
        # plans before anything else runs; surfaces duplicate/risk flags.
        try:
            from core.security.action_gate import ActionGate
            _ctx = getattr(self, "ctx", None) or getattr(auth_context, "ctx", None)
            _tier = getattr(auth_context, "tier", None) or "POC"
            _decision = ActionGate.evaluate(invocation, _ctx, _tier)
            if _decision.flags:
                logger.info(f"ACTION_GATE: allow={_decision.allowed} "
                            f"op={invocation.operation} flags={_decision.flags}")
            if not _decision.allowed:
                logger.warning(f"ACTION_GATE_DENIED: stage={_decision.stage} "
                               f"reason={_decision.reason} op={invocation.operation} "
                               f"target={invocation.target}")
                from core.common.schemas import ErrorInfo, ErrorType
                return ToolResult(
                    tool=invocation.tool_id or invocation.operation or "unknown",
                    capability=invocation.operation or "unknown",
                    status="failed",
                    target=invocation.target,
                    error=ErrorInfo(
                        error_type=ErrorType.SCOPE_VIOLATION,
                        message=f"Action gate denied at {_decision.stage}: {_decision.reason}",
                        details={"stage": _decision.stage}),
                )
        except ImportError:
            pass
        except Exception as _ge:
            logger.debug(f"[ActionGate] evaluation skipped: {_ge}")

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
        
        # STEP 2: Cache Lookup (legacy per-tool cache)
        cache_key = self._make_cache_key(invocation)
        cached_result = await self.cache.get(cache_key)
        if cached_result:
            logger.info(f"Cache HIT: {invocation.tool_id}")
            self.audit.log_cache_hit(cache_key, invocation)
            return self._stamp_cached(cached_result)

        # STEP 2a (P2-4): capability-level result cache. Same target +
        # operation + normalized args returns the cached payload without
        # touching the tool, even across different tool_ids.
        try:
            from core.tools.result_cache import get_result_cache
            rc = get_result_cache()
            hit = rc.get(invocation.target or "", invocation.operation or "",
                         invocation.params)
            if hit is not None:
                logger.info(f"RESULT_CACHE_HIT: op={invocation.operation} target={invocation.target}")
                return self._stamp_cached(hit)
        except Exception as _e:
            logger.debug(f"result cache lookup skipped: {_e}")
        
        # STEP 2b (P1-2): Freshness gate — skip repeated recon that is
        # still fresh in the knowledge store.
        try:
            from core.knowledge.freshness import get_freshness
            fresh = get_freshness()
            _op = invocation.operation or ""
            _tgt = invocation.target or ""
            if _op and _tgt and fresh.has_fresh_result(_tgt, _op):
                from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus
                logger.info(f"FRESHNESS_SKIP: operation={_op} target={_tgt}")
                try:
                    from core.observability.scan_metrics import get_metrics
                    get_metrics().inc("duplicate_tool_calls")
                except Exception:
                    pass
                return SchemaToolResult(
                    tool=invocation.tool_id or _op or "unknown",
                    capability=_op or "unknown",
                    # P0.4: the truth lives in the STATUS field, not just metadata.
                    # SKIPPED_FRESH is a non-failing no-op (see ToolResult.success)
                    # so it neither triggers a retry nor is recorded as SUCCESS.
                    status=ToolExecutionStatus.SKIPPED_FRESH,
                    exit_code=0,
                    target=_tgt,
                    stdout=f"[SKIPPED_FRESH] {_op} on {_tgt} not re-executed — a "
                           "fresh prior result is already in the knowledge store.",
                    data={"freshness_skip": True},
                    metadata={"reason": "fresh knowledge already recorded",
                              "execution_state": "SKIPPED_FRESH"},
                )
        except Exception as _e:
            logger.debug(f"freshness gate skipped: {_e}")

        # STEP 2c (P1-7): Tool health gate — refuse invocation of a tool
        # already in COOLDOWN or UNAVAILABLE state; pick a replacement
        # instead of wasting an LLM round on a known-broken binary.
        try:
            from core.tools.tool_health import get_health_manager
            hm = get_health_manager()
            if invocation.tool_id:
                h = hm.status_of(invocation.tool_id)
                if h and not h.is_available():
                    alt = hm.pick_replacement(invocation.tool_id)
                    if alt:
                        logger.info(f"HEALTH_SWAP: {invocation.tool_id} -> {alt} "
                                    f"({h.last_failure})")
                        invocation.tool_id = alt
        except Exception as _e:
            logger.debug(f"health gate skipped: {_e}")

        # STEP 2d (P1-1): WAF-mode gate — passive-only mode blocks active
        # tools entirely; cautious mode blocks brute-force.
        try:
            from core.adaptation.waf_state import get_waf_state
            waf = get_waf_state()
            _tgt = invocation.target or ""
            _cap = (invocation.operation or "").lower()
            # Coarse category mapping — mirrors DEFAULT_CLASS keys.
            _brute = _cap in ("directory_bruteforce", "endpoint_discovery",
                              "parameter_discovery")
            _active = _cap in ("vulnerability_scanning", "sql_injection",
                               "xss_scanning", "web_crawling")
            _passive = _cap in ("technology_fingerprinting", "waf_detection",
                                "tls_analysis", "http_analysis",
                                "subdomain_enumeration", "dns_enumeration")
            cat = "brute" if _brute else ("active" if _active else ("passive" if _passive else "recon"))
            if _tgt and not waf.is_tool_allowed(_tgt, cat):
                from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
                logger.warning(f"WAF_BLOCKED: operation={_cap} category={cat} "
                               f"mode={waf.mode_for(_tgt).value} target={_tgt}")
                try:
                    from core.observability.scan_metrics import get_metrics
                    get_metrics().inc("waf_blocks")
                except Exception:
                    pass
                return SchemaToolResult(
                    tool=invocation.tool_id or _cap or "unknown",
                    capability=_cap or "unknown",
                    status=ToolExecutionStatus.BLOCKED,
                    target=_tgt,
                    error=ErrorInfo(
                        error_type=ErrorType.EXECUTION_ERROR,
                        message=f"blocked by WAF policy in mode {waf.mode_for(_tgt).value}",
                    ),
                )
        except Exception as _e:
            logger.debug(f"waf gate skipped: {_e}")

        # STEP 2e (P1-8): Clamp timeout to the class ceiling for this capability.
        try:
            from core.tools.timeout_classes import default_seconds_for
            _cap = invocation.operation or ""
            if _cap and "timeout" not in (invocation.params or {}):
                invocation.params = dict(invocation.params or {})
                invocation.params["timeout"] = default_seconds_for(_cap)
        except Exception:
            pass

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
            logger.error(f"Timeout: {invocation.tool_id} after {timeout_val}s")
            result = await self._handle_timeout(invocation, auth_context, timeout_seconds=timeout_val)
        except Exception as e:
            logger.error(f"Error: {invocation.tool_id}: {e}")
            result = await self._handle_error(invocation, auth_context, e)
        
        # STEP 5: Normalize Result
        result = await self._normalize_result(result, invocation)

        # STEP 5b: Record success/failure into WAF state, freshness, metrics.
        try:
            from core.adaptation.waf_state import get_waf_state
            from core.knowledge.freshness import get_freshness
            from core.observability.scan_metrics import get_metrics
            waf = get_waf_state()
            metrics = get_metrics()
            metrics.inc("tool_calls")
            _tgt = invocation.target or ""
            _status = getattr(result.status, "value", str(result.status)).upper()
            if _status == "BLOCKED":
                if _tgt:
                    waf.record_block(_tgt)
                metrics.inc("waf_blocks")
            elif _status == "TIMEOUT":
                metrics.inc("failed_tools")
            elif _status in ("FAILED",):
                metrics.inc("failed_tools")
            elif _status in ("PARTIAL", "PARTIAL_SUCCESS"):
                metrics.inc("partial_tools")
                if _tgt:
                    waf.record_success(_tgt)
            elif _status == "SUCCESS":
                if _tgt:
                    waf.record_success(_tgt)
            # Freshness: only cache SUCCESS results.
            if _status == "SUCCESS" and _tgt and invocation.operation:
                get_freshness().record(_tgt, invocation.operation)
        except Exception as _e:
            logger.debug(f"post-exec accounting skipped: {_e}")
        
        # STEP 6: Cache It (only cache successes — failed results should not poison future calls)
        if result.success:
            await self.cache.set(cache_key, result)
            # P2-4: also populate the capability-level cache so tool_id
            # substitution (health swap, WAF category downgrade) still
            # hits fresh results.
            try:
                from core.tools.result_cache import get_result_cache
                get_result_cache().set(
                    invocation.target or "", invocation.operation or "",
                    result, invocation.params,
                )
            except Exception:
                pass
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
                             auth_context: AuthContext,
                             timeout_seconds: int = 0) -> ToolResult:
        """Handle tool execution timeout. Prefers the actual configured
        timeout in the error message — previously this hardcoded "300s"
        regardless of the real cap."""
        from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
        from core.common.error_translator import ErrorTranslator

        tool_id = invocation.tool_id or invocation.operation or "unknown"
        translation = ErrorTranslator.translate(tool_id, "timeout", exit_code=1, target=invocation.target)

        actual_timeout = timeout_seconds or int((invocation.params or {}).get("timeout", 900))
        return SchemaToolResult(
            tool=tool_id,
            capability=invocation.operation or "unknown",
            status=ToolExecutionStatus.TIMEOUT,
            target=invocation.target,
            data={"error_human": translation.get("formatted_report")},
            error=ErrorInfo(
                error_type=ErrorType.TIMEOUT,
                message=f"Tool {tool_id} timed out after {actual_timeout}s",
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
        """Reconcile status vs exit_code (P0-1) then hand off untouched.

        Root fix for the `rc=2 ... TOOL_OK` incident: even if the executor
        reports SUCCESS, a non-zero exit code must downgrade the status
        to PARTIAL (useful output) or FAILED (no trustworthy output).
        Timeout/blocked flags always win.
        """
        try:
            from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus
            ec = getattr(result, "exit_code", None)
            if ec is None:
                ec = getattr(result, "returncode", None)
            timed_out = str(getattr(result, "status", "")).upper().endswith("TIMEOUT")
            blocked = str(getattr(result, "status", "")).upper() in ("BLOCKED", "SCOPE_DENIED")
            derived = SchemaToolResult.derive_status(
                exit_code=ec,
                stdout=str(getattr(result, "stdout", "") or ""),
                stderr=str(getattr(result, "stderr", "") or ""),
                timed_out=timed_out,
                blocked=blocked,
            )
            # Only overwrite when derivation disagrees (avoids clobbering
            # richer statuses like EMPTY_RESULT set by upstream parsers).
            cur = str(getattr(result, "status", "")).upper()
            if cur in ("SUCCESS", "COMPLETED") and derived != ToolExecutionStatus.SUCCESS:
                logger.warning(
                    "STATUS_DOWNGRADE: tool=%s reported %s but exit_code=%s -> %s",
                    getattr(result, "tool", "?"), cur, ec, derived.value,
                )
                result.status = derived
        except Exception as _e:
            logger.debug(f"status reconciliation skipped: {_e}")
        return result
    
    def _stamp_cached(self, result):
        """P0.4: mark a returned cache hit as CACHED so it is not recorded as a
        fresh SUCCESS. A cached success becomes CACHED (still non-failing); a
        cached non-success keeps its status and only gains a cache_hit flag.
        The original status is preserved in metadata for audit.
        """
        try:
            from core.common.schemas import ToolExecutionStatus
            _st = getattr(result, "status", "")
            orig = str(_st.value if hasattr(_st, "value") else _st).upper()
            md = dict(getattr(result, "metadata", {}) or {})
            md["cache_hit"] = True
            md.setdefault("original_status", orig)
            update = {"metadata": md}
            if orig in ("SUCCESS", "PARTIAL_SUCCESS", "PARTIAL", "COMPLETED"):
                update["status"] = ToolExecutionStatus.CACHED
            if hasattr(result, "copy"):
                return result.copy(update=update)
            if hasattr(result, "model_copy"):
                return result.model_copy(update=update)
        except Exception as _e:
            logger.debug(f"cache stamp skipped: {_e}")
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
