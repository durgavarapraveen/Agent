
import logging
from typing import Optional, Dict, Any, Union
from core.common.schemas import ToolResult, ToolExecutionStatus, RetryDecisionType

logger = logging.getLogger(__name__)


class RetryDecision:
    def __init__(
        self,
        decision: RetryDecisionType,
        reason: str,
        alternative_tool: Optional[str] = None
    ):
        self.decision = decision
        self.reason = reason
        self.alternative_tool = alternative_tool

    def should_retry(self) -> bool:
        return self.decision == RetryDecisionType.RETRY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "alternative_tool": self.alternative_tool
        }


class RetryPolicy:

    ALTERNATIVE_TOOLS: Dict[str, list[str]] = {
        "subfinder": ["amass", "dig", "dns_lookup_python"],
        "amass": ["subfinder", "dig"],
        "nmap": ["masscan", "port_check"],
        "sslscan": ["openssl", "ssl_inspect"],
        "openssl": ["sslscan"],
        "whatweb": ["httpx"],
        "httpx": ["whatweb"],
        "katana": ["paramspider", "gobuster", "feroxbuster"],
        "paramspider": ["katana", "gobuster"],
        "gobuster": ["feroxbuster", "katana"],
        "feroxbuster": ["gobuster", "katana"],
    }

    @classmethod
    def evaluate(
        cls,
        tool_name: str,
        result: Union[ToolResult, Dict[str, Any]],
        attempt: int = 1,
        max_retries: int = 3
    ) -> RetryDecision:
        # Normalize result inputs
        if isinstance(result, dict):
            status = result.get("status", "failed")
            error_msg = str(result.get("error") or "")
            stdout = str(result.get("output") or result.get("stdout") or "")
            stderr = str(result.get("stderr") or "")
            exit_code = result.get("returncode", result.get("exit_code"))
            data = result.get("data", {})
        else:
            status = result.status
            error_msg = result.error.message if result.error else ""
            stdout = result.stdout
            stderr = result.stderr
            exit_code = result.exit_code
            data = result.data

        # 1. If tool was successful or had partial success with data -> NO_RETRY
        if status in (ToolExecutionStatus.SUCCESS, ToolExecutionStatus.PARTIAL_SUCCESS, "success", "partial_success", "SUCCESS", "PARTIAL_SUCCESS"):
            dec = RetryDecision(
                decision=RetryDecisionType.NO_RETRY,
                reason="Tool succeeded or achieved partial success"
            )
            logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
            return dec

        # 2. Check if there's partial data extracted despite an error -> NO_RETRY
        if data and any(bool(v) for v in data.values() if isinstance(v, (list, dict, set))):
            dec = RetryDecision(
                decision=RetryDecisionType.NO_RETRY,
                reason="Useful intelligence recovered from output"
            )
            logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
            return dec

        combined_error = (error_msg + " " + stderr + " " + stdout).lower()

        # 3. Scope violation / Authorization failure -> NO_RETRY (Security guardrail)
        if any(w in combined_error for w in ["scope", "unauthorized", "authorization", "forbidden", "permission denied", "access denied"]):
            dec = RetryDecision(
                decision=RetryDecisionType.NO_RETRY,
                reason="Authorization or security policy violation cannot be retried"
            )
            logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
            return dec

        # 4. Invalid argument / Command syntax error -> NO_RETRY (Deterministic syntax will not change on repeat)
        if any(w in combined_error for w in ["invalid argument", "unknown option", "syntax error", "illegal option", "invalid option", "tool_invalid_argument"]):
            dec = RetryDecision(
                decision=RetryDecisionType.NO_RETRY,
                reason="Invalid command arguments will not succeed on retry"
            )
            logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
            return dec

        # 5. Tool not found / missing dependency -> ALTERNATIVE_STRATEGY
        if any(w in combined_error for w in ["not found", "command not found", "no such file", "not installed", "tool_unavailable"]):
            alts = cls.ALTERNATIVE_TOOLS.get(tool_name.lower(), [])
            alt_tool = alts[0] if alts else None
            dec = RetryDecision(
                decision=RetryDecisionType.ALTERNATIVE_STRATEGY,
                reason=f"Tool '{tool_name}' unavailable. Using alternative fallback strategy.",
                alternative_tool=alt_tool
            )
            logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}' alt_tool={alt_tool}")
            return dec

        # 6. Timeout / Network error -> RETRY if attempt < max_retries
        if attempt < max_retries:
            if any(w in combined_error for w in ["timeout", "timed out", "connection reset", "network", "econnreset", "socket"]):
                dec = RetryDecision(
                    decision=RetryDecisionType.RETRY,
                    reason=f"Transient timeout or network glitch (attempt {attempt}/{max_retries})"
                )
                logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
                return dec
            
            # Generic execution failure with retries remaining
            dec = RetryDecision(
                decision=RetryDecisionType.RETRY,
                reason=f"Transient execution error (attempt {attempt}/{max_retries})"
            )
            logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
            return dec

        # 7. Max retries exceeded -> NO_RETRY
        dec = RetryDecision(
            decision=RetryDecisionType.NO_RETRY,
            reason=f"Max retries ({max_retries}) exhausted"
        )
        logger.info(f"RETRY_POLICY_DECISION: tool={tool_name} decision={dec.decision.value} reason='{dec.reason}'")
        return dec
