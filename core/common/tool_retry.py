"""Expert-mode tool invocation wrapper: retry-on-timeout with longer budget,
then fall back to an alternate tool for the same capability.

Applied to every ToolGateway.execute call so a Kali tool timeout no longer
declares the whole finding lost — we escalate the timeout, then walk the
portfolio's fallback chain (e.g. sqlmap → nuclei → custom_mutator).
"""
from __future__ import annotations
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


TIMEOUT_ESCALATION = [1.0, 2.5, 4.0]   # multipliers of the original timeout


def _is_timeout_result(result: Any) -> bool:
    if result is None:
        return True
    err = getattr(result, "error", None)
    if err is None and isinstance(result, dict):
        err = result.get("error")
    if err is not None:
        et = getattr(err, "error_type", None) or (err.get("error_type") if isinstance(err, dict) else None)
        et_name = getattr(et, "name", None) or (str(et) if et else "")
        if "TIMEOUT" in (et_name or "").upper():
            return True
    status = getattr(result, "status", None) or (result.get("status") if isinstance(result, dict) else None)
    return bool(status and "timeout" in str(status).lower())


async def execute_with_expert_retry(gateway, invocation, auth_context,
                                     base_timeout: int = 60,
                                     fallback_tool_ids: Optional[list] = None) -> Any:
    """Execute a tool invocation, escalating the timeout on failure, then
    walking the portfolio's fallback chain for the same capability.

    `fallback_tool_ids`: alternate tool_ids ordered by preference (e.g. after
    sqlmap timeouts, try ["nuclei", "custom_mutator"]). Pulled from the
    tool_portfolio when not supplied.
    """
    original_timeout = getattr(invocation, "timeout_seconds", None) or base_timeout
    original_tool = getattr(invocation, "tool_id", "")

    # Attempt 1: original settings
    result = await gateway.execute(invocation, auth_context)
    if not _is_timeout_result(result):
        return result

    # Attempts 2-4: escalate timeout
    for mult in TIMEOUT_ESCALATION:
        new_timeout = int(original_timeout * mult)
        try:
            invocation.timeout_seconds = new_timeout
        except Exception:
            pass
        logger.info(f"[ToolRetry] {original_tool} timed out — retrying with timeout={new_timeout}s")
        result = await gateway.execute(invocation, auth_context)
        if not _is_timeout_result(result):
            return result

    # Attempts 5+: portfolio fallback chain
    if not fallback_tool_ids:
        try:
            from core.tools.tool_portfolio import get_fallback_chain
            cap = getattr(invocation, "operation", "") or ""
            fallback_tool_ids = [t for t in (get_fallback_chain(cap) or []) if t != original_tool]
        except Exception:
            fallback_tool_ids = []
    for alt in (fallback_tool_ids or [])[:3]:
        try:
            invocation.tool_id = alt
            invocation.timeout_seconds = int(original_timeout * 3)
        except Exception:
            continue
        logger.info(f"[ToolRetry] Falling back {original_tool} -> {alt}")
        result = await gateway.execute(invocation, auth_context)
        if not _is_timeout_result(result):
            return result
    # Restore invocation identity for downstream logging
    try:
        invocation.tool_id = original_tool
        invocation.timeout_seconds = original_timeout
    except Exception:
        pass
    return result
