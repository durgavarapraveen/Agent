"""
False Positive Filtering Module.
Validates candidate findings against HTTP response status codes, baseline differentials,
tracer string presence, and Content-Type rendering rules.
"""

import logging
import re
from typing import Dict, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Content-Types that do not render HTML scripts or input reflection contexts
NON_HTML_CONTENT_TYPES = [
    "application/json",
    "application/javascript",
    "application/pdf",
    "application/xml",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/svg+xml",
    "audio/",
    "video/",
    "application/octet-stream"
]


class FalsePositiveFilter:
    """Evaluates candidate findings against baseline rules to prevent false positive reporting."""

    def check_status_code(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Client-side reflection findings require 2xx HTTP status codes.
        Reject 404 Not Found, 403 Forbidden, 500 Server Error for reflection.
        """
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        title = str(finding.get("title") or "").lower()
        proof = str(finding.get("proof") or "").lower()

        is_reflection = "reflection" in vuln_type or "xss" in vuln_type or "unencoded" in title

        if is_reflection:
            status_match = re.search(r"status\s*(\d{3})", proof)
            if status_match:
                status_code = int(status_match.group(1))
                if status_code >= 400:
                    return False, f"Reflection finding rejected due to non-2xx status code: {status_code}"

        return True, "Status code valid"

    def check_baseline_differential(self, finding: Dict[str, Any], baseline_body: str = "") -> Tuple[bool, str]:
        """
        Database error findings require explicit DB error signatures to appear in probe responses
        while being absent from benign baseline responses.
        """
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        if "sql" in vuln_type or "verbose_error" in vuln_type:
            matched_error = finding.get("matched_error") or ""
            if matched_error and baseline_body:
                if matched_error.lower() in baseline_body.lower():
                    return False, f"Database error '{matched_error}' was already present in baseline response"

        return True, "Baseline differential valid"

    def check_tracer_reflection(self, finding: Dict[str, Any], response_body: str = "") -> Tuple[bool, str]:
        """
        Input reflection findings require the raw probe tracer string to literally appear in response body.
        """
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        tracer_used = finding.get("tracer_used")

        if ("reflection" in vuln_type or "xss" in vuln_type) and tracer_used:
            if response_body and tracer_used not in response_body:
                return False, f"Tracer string '{tracer_used}' was not found in response body"

        return True, "Tracer reflection valid"

    def check_content_type(self, finding: Dict[str, Any], content_type: str = "") -> Tuple[bool, str]:
        """
        Reject input reflection findings occurring in non-HTML response Content-Types
        (e.g., application/json, image/png).
        """
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        ct_clean = (content_type or finding.get("content_type") or "").lower().strip()

        if "reflection" in vuln_type or "xss" in vuln_type:
            if ct_clean:
                for non_html in NON_HTML_CONTENT_TYPES:
                    if non_html in ct_clean:
                        return False, f"Reflection finding rejected for non-HTML Content-Type: '{ct_clean}'"

        return True, "Content-Type valid"

    def should_report_finding(
        self,
        finding: Dict[str, Any],
        response_meta: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Run all false positive verification rules against a candidate finding.
        Returns (should_report: bool, reason: str).
        """
        response_meta = response_meta or {}
        baseline_body = response_meta.get("baseline_body", "")
        response_body = response_meta.get("response_body", "")
        content_type = response_meta.get("content_type", "")

        # 1. Status Code Check
        valid, reason = self.check_status_code(finding)
        if not valid:
            return False, reason

        # 2. Baseline Differential Check
        valid, reason = self.check_baseline_differential(finding, baseline_body)
        if not valid:
            return False, reason

        # 3. Tracer Reflection Check
        valid, reason = self.check_tracer_reflection(finding, response_body)
        if not valid:
            return False, reason

        # 4. Content-Type Check
        valid, reason = self.check_content_type(finding, content_type)
        if not valid:
            return False, reason

        return True, "Finding passed all false positive verification rules"
