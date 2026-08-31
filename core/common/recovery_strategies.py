"""
Fallback & Recovery Strategies Module (Phase 3 Module 3.3).
Implements Error-to-Action mapping, exponential backoff retries, tool fallback chains,
and automatic HTTPS -> HTTP protocol downgrades.
"""

import functools
import logging
import re
import time
from typing import Callable, Dict, List, Optional, Tuple, Any

from core.authorization import TargetScopeValidator
from core.exceptions import ScopeViolationException

logger = logging.getLogger(__name__)

ERROR_MAPPING = {
    "Timeout": {"action": "increase_timeout", "params": {"timeout": 120}},
    "Authentication failed": {"action": "try_credential_spray", "params": {"userlist": "default_users.txt"}},
    "WAF": {"action": "activate_bypass_mode", "params": {"delay": 2, "user_agent_rotation": True}},
    "Host unreachable": {"action": "fallback_tool", "params": {"tool": "masscan"}}
}

TOOL_CHAINS = {
    "port_scan": ["nmap", "masscan"],
    "directory_bruteforce": ["gobuster", "ffuf", "dirb"],
    "sqli_test": ["sqlmap", "bbqsql"]
}


def retry_with_backoff(max_attempts: int = 3, base_delay: float = 2.0):
    """
    Decorator for retrying transient failures (timeouts, 502s, network errors)
    with exponential backoff delays (2s, 4s, 8s).
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"[RetryBackoff] Max attempts ({max_attempts}) reached for {func.__name__}. Error: {e}")
                        raise e
                    delay = base_delay * (2 ** (attempts - 1))
                    logger.warning(f"[RetryBackoff] Attempt {attempts}/{max_attempts} failed for {func.__name__}: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
        return wrapper
    return decorator


class FallbackRecoveryManager:
    """Manages error mapping, tool chain fallbacks, and protocol downgrades."""

    def __init__(self, scope_validator: Optional[TargetScopeValidator] = None):
        self.scope_validator = scope_validator or TargetScopeValidator.get()

    def handle_error_action(self, error_message: str) -> Dict[str, Any]:
        """Look up error message via regex patterns and return mapped fallback action."""
        err_clean = str(error_message)
        for pattern, action_spec in ERROR_MAPPING.items():
            if re.search(pattern, err_clean, re.IGNORECASE):
                logger.info(f"[ErrorRecovery] Matched pattern '{pattern}' -> Action: {action_spec['action']}")
                return action_spec

        return {"action": "default_retry", "params": {}}

    def execute_tool_fallback_chain(self, task_type: str, primary_runner: Callable[[str], bool]) -> Dict[str, Any]:
        """
        Execute tool fallback chain if primary tool fails (exit code != 0 or zero findings).
        Automatically invokes the next tool in the chain.
        """
        tools = TOOL_CHAINS.get(task_type, ["nmap"])
        logger.info(f"[ToolChain] Executing tool chain for '{task_type}': {tools}")

        for idx, tool in enumerate(tools):
            try:
                success = primary_runner(tool)
                if success:
                    logger.info(f"[ToolChain] Tool '{tool}' succeeded.")
                    return {"task_type": task_type, "successful_tool": tool, "attempts": idx + 1}
                else:
                    logger.warning(f"[ToolChain] Tool '{tool}' failed or yielded zero findings. Switching to next tool in chain...")
            except Exception as e:
                logger.warning(f"[ToolChain] Tool '{tool}' raised exception: {e}. Switching to next tool...")

        return {"task_type": task_type, "successful_tool": None, "attempts": len(tools)}

    def perform_protocol_downgrade_request(self, target_url: str, request_func: Callable[[str], str]) -> Tuple[str, List[Dict[str, str]]]:
        """
        If HTTPS request fails with SSL errors (e.g., SSLCertVerificationError),
        automatically retry using HTTP. Log downgrade and flag as 'Potential insecure service'.
        """
        self.scope_validator.validate(target_url)
        findings = []

        try:
            res = request_func(target_url)
            return res, findings
        except Exception as e:
            err_msg = str(e)
            if "ssl" in err_msg.lower() or "cert" in err_msg.lower() or "sslcertverificationerror" in err_msg.lower():
                logger.warning(f"[ProtocolDowngrade] SSL error on {target_url}: {e}. Retrying over HTTP...")
                http_url = target_url.replace("https://", "http://")
                self.scope_validator.validate(http_url)

                try:
                    res = request_func(http_url)
                    findings.append({
                        "vulnerability": "Potential insecure service (SSL Error - HTTP Downgrade Succeeded)",
                        "url": http_url,
                        "detail": f"Service failed SSL verification on HTTPS but accepted unencrypted HTTP connection ({target_url} -> {http_url}).",
                        "severity": "MEDIUM"
                    })
                    return res, findings
                except Exception as http_err:
                    logger.error(f"[ProtocolDowngrade] HTTP fallback also failed: {http_err}")
                    raise http_err
            else:
                raise e
