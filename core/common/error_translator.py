"""
Error Context Translator with Actionable Recommendations.
Transforms raw tool stderr/exceptions into concise, classified error prompts with actionable next-step suggestions.
"""

import logging
import re
from enum import Enum
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ErrorCategory(str, Enum):
    TRANSIENT = "TRANSIENT"
    PERMANENT = "PERMANENT"
    CONFIGURATION = "CONFIGURATION"
    ENVIRONMENT = "ENVIRONMENT"
    TIMEOUT = "TIMEOUT"


class ErrorTranslator:
    """Translates raw tool errors into classified error reports with actionable recommendations."""

    # 20+ Tool-specific and general error mappings
    ERROR_MAPPINGS = [
        # Network & Connection errors
        (r"econnrefused|connection refused|failed to connect", ErrorCategory.PERMANENT, "Port not responding / Service offline", "Target port may be closed or HTTP-only. Try port 80/443 or check if target service is active.", "curl", False),
        (r"timeout|timed out|execution timed out", ErrorCategory.TIMEOUT, "Server slow or firewall blocking responses", "Increase timeout or skip deep scan for this tool and continue with HTTP analysis.", "httpx", True),
        (r"econnreset|connection reset by peer", ErrorCategory.TRANSIENT, "Network connection reset", "Network glitch or WAF connection drop. Retry once with lower rate limit.", None, True),
        (r"could not resolve host|name or service not known", ErrorCategory.ENVIRONMENT, "DNS resolution failure", "Verify domain name spelling or DNS server availability. Skip DNS-dependent tools.", "dns_lookup", False),
        
        # Permissions & Environment errors
        (r"sudo: command not found|permission denied|operation not permitted", ErrorCategory.PERMANENT, "Insufficient privileges", "Run with unprivileged flags (e.g. nmap -sT TCP connect scan instead of -sS SYN scan).", "nmap", False),
        (r"command not found|executable file not found|not installed", ErrorCategory.ENVIRONMENT, "Missing tool binary", "Tool binary missing in environment. Skip tool and use Python-native fallback.", "python", False),

        # SSL / TLS errors
        (r"ssl_error_connect_failure|handshake failure|tls_error", ErrorCategory.PERMANENT, "TLS handshake failed", "Certificate validation failed or legacy protocol unsupported. Skip TLS analysis and inspect HTTP.", "curl", False),
        (r"certificate has expired|self signed certificate", ErrorCategory.CONFIGURATION, "SSL certificate warning", "Add insecure flag (--insecure or -k) to bypass certificate verification.", "curl", True),

        # HTTP & Scanner specific errors
        (r"403 forbidden|waf|blocked|firewall", ErrorCategory.PERMANENT, "Request blocked by WAF or firewall", "WAF detected. Lower request rate, rotate User-Agent header, or switch to passive recon.", "whatweb", False),
        (r"401 unauthorized|auth failed", ErrorCategory.CONFIGURATION, "Authentication required", "Target endpoint requires valid API key or session token. Extract auth credentials first.", "auth_bypass", False),
        (r"404 not found", ErrorCategory.CONFIGURATION, "Resource endpoint not found", "Endpoint does not exist on target host. Verify URL path or try directory brute-forcing.", "gobuster", False),
        (r"500 internal server error|502 bad gateway|503 service unavailable", ErrorCategory.TRANSIENT, "Server-side error", "Target server encountered internal exception or crash. Test for SQLi/injection or retry after delay.", "sqlmap", True),

        # Subfinder & Recon specific
        (r"no subdomains found|no results|zero target", ErrorCategory.CONFIGURATION, "No target data returned", "Target has no exposed subdomains or passive APIs exhausted. Try direct brute-forcing.", "gobuster", False),
        (r"api key missing|rate limit exceeded", ErrorCategory.CONFIGURATION, "API rate limit or auth missing", "Passive API rate limit hit. Switch to local wordlist brute-forcing or DNS brute-forcing.", "amass", False),

        # Nmap & Port scanning specific
        (r"no targets specified|invalid target", ErrorCategory.CONFIGURATION, "Target format invalid", "Check target formatting (remove protocols or trailing slashes for IP/hostname).", None, False),
        (r"host seems down|0 hosts up", ErrorCategory.ENVIRONMENT, "Host unreachable or ICMP blocked", "Host blocking ping/ICMP. Pass -Pn flag to nmap to skip host discovery.", "nmap", True),

        # SQLmap & Exploit specific
        (r"all tested parameters appear to be not injectable", ErrorCategory.PERMANENT, "Parameters non-injectable", "Target parameter is not vulnerable to tested SQLi vectors. Switch to XSS/IDOR analysis.", "dalfox", False),
        (r"unable to connect to the target url", ErrorCategory.TRANSIENT, "Target URL inaccessible", "Target unreachable during exploit attempt. Check network connectivity or URL path.", "curl", True),
    ]

    @classmethod
    def translate(
        cls,
        tool_name: str,
        stderr: str,
        exit_code: int = 1,
        target: str = ""
    ) -> Dict[str, Any]:
        """Classify tool error and return structured error response with actionable recommendation."""
        tool_clean = (tool_name or "").lower().strip()
        stderr_clean = (stderr or "").strip()
        raw_text = stderr_clean.lower()

        matched_category = ErrorCategory.PERMANENT
        matched_cause = "Tool execution failure"
        matched_rec = "Skip tool execution and proceed to alternative analysis."
        alternative_tool = None
        should_retry = False

        for pattern, category, cause, rec, alt, retry in cls.ERROR_MAPPINGS:
            if re.search(pattern, raw_text, re.IGNORECASE):
                matched_category = category
                matched_cause = cause
                matched_rec = rec
                alternative_tool = alt
                should_retry = retry
                break

        retry_str = f"yes ({matched_category.value})" if should_retry else "no (permanent or environment issue)"
        alt_str = alternative_tool if alternative_tool else "none required"
        proceed_str = "retry command" if should_retry else "skip tool and proceed"

        formatted_report = (
            f"[WARN] TOOL_FAILED: {tool_clean}\n"
            f"Error: {matched_category.value} - {matched_cause}\n"
            f"Cause: {stderr_clean[:150] if stderr_clean else 'Non-zero exit code returned'}\n"
            f"Retry: {retry_str}\n"
            f"Alternative: {alt_str}\n"
            f"Next action: {proceed_str}\n"
            f"Recommendation: {matched_rec}"
        )

        return {
            "tool": tool_clean,
            "category": matched_category.value,
            "cause": matched_cause,
            "stderr": stderr_clean,
            "should_retry": should_retry,
            "alternative_tool": alternative_tool,
            "recommendation": matched_rec,
            "formatted_report": formatted_report
        }
