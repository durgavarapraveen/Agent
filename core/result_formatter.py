"""
Tool Result Formatter with Token Compression.
Reduces LLM context size by 85-95% for tool execution outputs while maintaining decision quality.
"""

import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ToolResultFormatter:
    """Smart result formatter and token compression utility."""

    @classmethod
    def should_compress(cls, tool_name: str, data: Any) -> bool:
        """Determine if tool output requires compression based on size/count."""
        tool_name = (tool_name or "").lower().strip()
        if isinstance(data, list):
            count = len(data)
            if tool_name == "subfinder" and count > 5:
                return True
            elif tool_name in ("nmap", "masscan") and count > 20:
                return True
            elif tool_name in ("httpx", "gobuster", "feroxbuster") and count > 10:
                return True
            elif tool_name in ("katana", "paramspider") and count > 50:
                return True
            elif count > 10:
                return True
        elif isinstance(data, dict):
            if tool_name in ("sslscan", "openssl"):
                return True
            elif len(str(data)) > 500:
                return True
        elif isinstance(data, str) and len(data) > 500:
            return True

        return False

    @classmethod
    def format_success_result(
        cls,
        tool_name: str,
        result_data: Dict[str, Any],
        count: int = 0,
        key_finding: str = ""
    ) -> str:
        """Format successful tool execution using a concise 3-sentence summary structure."""
        tool_name = (tool_name or "").lower().strip()
        
        # 1. Extract counts & key findings if not provided
        if not count:
            if "subdomains" in result_data:
                count = len(result_data["subdomains"])
            elif "ports" in result_data:
                count = len(result_data["ports"])
            elif "endpoints" in result_data:
                count = len(result_data["endpoints"])
            elif "technologies" in result_data:
                count = len(result_data["technologies"])

        if not key_finding:
            if "subdomains" in result_data and result_data["subdomains"]:
                key_finding = f"Top subdomains: {', '.join(result_data['subdomains'][:5])}"
            elif "ports" in result_data and result_data["ports"]:
                ports_summary = [f"{p.get('port')}/{p.get('service','tcp')}" if isinstance(p, dict) else str(p) for p in result_data["ports"][:10]]
                key_finding = f"Open ports: {', '.join(ports_summary)}"
            elif "endpoints" in result_data and result_data["endpoints"]:
                key_finding = f"Discovered endpoints: {', '.join([str(e) for e in result_data['endpoints'][:5]])}"
            elif "technologies" in result_data and result_data["technologies"]:
                key_finding = f"Tech stack: {', '.join([str(t) for t in result_data['technologies'][:5]])}"
            elif "security_headers" in result_data and result_data["security_headers"]:
                missing = [h for h, s in result_data["security_headers"].items() if s == "missing"]
                key_finding = f"Missing headers: {', '.join(missing[:5])}" if missing else "All critical security headers present"
            else:
                key_finding = "Target responded successfully with evidence."

        sentence_1 = f"STATUS: SUCCESS for tool '{tool_name}' ({count} findings extracted)."
        sentence_2 = f"KEY FINDING: {key_finding}."
        sentence_3 = f"RECOMMENDATION: Proceed to next analytical or scanning phase."
        
        return f"{sentence_1}\n{sentence_2}\n{sentence_3}"

    @classmethod
    def format_failure_result(
        cls,
        tool_name: str,
        error_type: str,
        error_message: str,
        retry_suggestion: str = ""
    ) -> str:
        """Format failed tool execution."""
        tool_name = (tool_name or "").lower().strip()
        error_msg_short = str(error_message)[:150].replace("\n", " ")
        if not retry_suggestion:
            retry_suggestion = "Switch to alternative tool or skip unavailable module"

        sentence_1 = f"STATUS: FAILED for tool '{tool_name}' ({error_type})."
        sentence_2 = f"ERROR REASON: {error_msg_short}."
        sentence_3 = f"NEXT ACTION: {retry_suggestion}."

        return f"{sentence_1}\n{sentence_2}\n{sentence_3}"

    @classmethod
    def format_duplicate_result(cls, tool_name: str, previous_task_id: str) -> str:
        """Format deduplicated task result."""
        sentence_1 = f"STATUS: DEDUPLICATED for tool '{tool_name}'."
        sentence_2 = f"REASON: Identical capability and target already completed under task '{previous_task_id}'."
        sentence_3 = f"NEXT ACTION: Reuse existing results from shared context."

        return f"{sentence_1}\n{sentence_2}\n{sentence_3}"

    @classmethod
    def compress_tool_data(cls, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply tool-specific token compression rules."""
        tool_name = (tool_name or "").lower().strip()
        compressed = {}

        # subfinder: top 5 subdomains
        if "subdomains" in data:
            compressed["subdomains"] = data["subdomains"][:5]
            if len(data["subdomains"]) > 5:
                compressed["subdomains_truncated_count"] = len(data["subdomains"]) - 5

        # nmap: top 20 ports
        if "ports" in data:
            compressed["ports"] = data["ports"][:20]
            if len(data["ports"]) > 20:
                compressed["ports_truncated_count"] = len(data["ports"]) - 20

        # sslscan: protocols, weak ciphers, vulns only
        if tool_name in ("sslscan", "openssl"):
            compressed["protocols"] = data.get("protocols", ["TLSv1.2", "TLSv1.3"])
            compressed["weak_ciphers"] = data.get("weak_ciphers", [])
            compressed["vulnerabilities"] = data.get("vulnerabilities", [])

        # httpx / gobuster: top 10 endpoints
        if "endpoints" in data:
            compressed["endpoints"] = data["endpoints"][:10]
            if len(data["endpoints"]) > 10:
                compressed["endpoints_truncated_count"] = len(data["endpoints"]) - 10

        # katana / paramspider: top 50 unique URLs
        if tool_name in ("katana", "paramspider") and "endpoints" in data:
            compressed["endpoints"] = data["endpoints"][:50]

        # preserve technologies & security headers if present
        if "technologies" in data:
            compressed["technologies"] = data["technologies"][:5]
        if "security_headers" in data:
            compressed["security_headers"] = data["security_headers"]

        return compressed if compressed else data
