"""
Compliance framework definitions (structured data, not hardcoded strings).

Each framework is a dict of:
    control_id -> {title, description, applicable_finding_categories: [...]}

Findings are mapped by a normalized *category* (e.g. "injection", "xss",
"vulnerable_component"). A CWE->category table lets findings that carry only a
CWE be mapped too.

Frameworks shipped: PCI-DSS 4.0, SOC 2 (TSC), HIPAA Security Rule, CIS Controls
v8, NIST SP 800-53. The category lists cover the required controls at minimum;
extend the data structures to broaden coverage.
"""

from __future__ import annotations

from typing import Dict, List

# ── normalized finding categories ──
CATEGORIES = {
    "injection", "sqli", "xss", "vulnerable_component", "outdated_component",
    "crypto_weakness", "access_control", "auth", "misconfiguration",
    "sensitive_data_exposure", "ssrf", "path_traversal", "insecure_design",
    "logging_monitoring", "code_quality",
}

# CWE -> normalized category (extend as needed).
CWE_CATEGORY = {
    "CWE-89": "sqli", "CWE-79": "xss", "CWE-77": "injection",
    "CWE-78": "injection", "CWE-94": "injection",
    "CWE-1104": "vulnerable_component", "CWE-1035": "vulnerable_component",
    "CWE-937": "vulnerable_component", "CWE-1026": "vulnerable_component",
    "CWE-327": "crypto_weakness", "CWE-326": "crypto_weakness",
    "CWE-311": "sensitive_data_exposure", "CWE-200": "sensitive_data_exposure",
    "CWE-284": "access_control", "CWE-285": "access_control",
    "CWE-287": "auth", "CWE-306": "auth", "CWE-798": "auth",
    "CWE-16": "misconfiguration", "CWE-933": "misconfiguration",
    "CWE-918": "ssrf", "CWE-22": "path_traversal",
    "CWE-778": "logging_monitoring",
}


FRAMEWORKS: Dict[str, Dict[str, Dict]] = {
    # ── PCI-DSS 4.0 ──
    "pci": {
        "6.2": {
            "title": "Bespoke and custom software developed securely",
            "description": "Software is developed securely, addressing common "
                           "coding vulnerabilities (injection, XSS, etc.).",
            "applicable_finding_categories": [
                "injection", "sqli", "xss", "insecure_design", "code_quality"],
        },
        "6.3": {
            "title": "Security vulnerabilities identified and addressed",
            "description": "Vulnerabilities are identified via reputable sources "
                           "and patched; vulnerable components remediated.",
            "applicable_finding_categories": [
                "vulnerable_component", "outdated_component", "crypto_weakness"],
        },
        "11.3": {
            "title": "External and internal vulnerabilities regularly identified",
            "description": "Vulnerability scans and penetration tests are run and "
                           "findings remediated.",
            "applicable_finding_categories": [
                "vulnerable_component", "misconfiguration", "access_control",
                "ssrf", "path_traversal"],
        },
    },
    # ── SOC 2 Trust Services Criteria ──
    "soc2": {
        "CC6.1": {
            "title": "Logical access security controls",
            "description": "Access is restricted to protect information assets.",
            "applicable_finding_categories": [
                "access_control", "auth", "sensitive_data_exposure"],
        },
        "CC7.1": {
            "title": "Detection of vulnerabilities",
            "description": "Processes detect and monitor for new vulnerabilities.",
            "applicable_finding_categories": [
                "vulnerable_component", "outdated_component", "misconfiguration"],
        },
        "CC7.2": {
            "title": "Monitoring of anomalies",
            "description": "Security events are monitored, analyzed, and responded to.",
            "applicable_finding_categories": [
                "logging_monitoring", "injection", "ssrf"],
        },
        "CC8.1": {
            "title": "Change management",
            "description": "Changes are authorized, designed, and tested securely.",
            "applicable_finding_categories": [
                "insecure_design", "code_quality", "crypto_weakness"],
        },
    },
    # ── HIPAA Security Rule ──
    "hipaa": {
        "164.312(a)(1)": {
            "title": "Access Control",
            "description": "Technical policies limiting ePHI access to authorized users.",
            "applicable_finding_categories": [
                "access_control", "auth", "path_traversal"],
        },
        "164.312(e)(1)": {
            "title": "Transmission Security",
            "description": "Guard against unauthorized access to ePHI in transit.",
            "applicable_finding_categories": [
                "crypto_weakness", "sensitive_data_exposure", "misconfiguration"],
        },
    },
    # ── CIS Controls v8 ──
    "cis": {
        "7": {
            "title": "Continuous Vulnerability Management",
            "description": "Continuously assess and track vulnerabilities; remediate.",
            "applicable_finding_categories": [
                "vulnerable_component", "outdated_component", "misconfiguration"],
        },
        "16": {
            "title": "Application Software Security",
            "description": "Manage the security lifecycle of in-house and acquired software.",
            "applicable_finding_categories": [
                "injection", "sqli", "xss", "insecure_design", "ssrf",
                "path_traversal", "code_quality"],
        },
    },
    # ── NIST SP 800-53 ──
    "nist": {
        "SI-2": {
            "title": "Flaw Remediation",
            "description": "Identify, report, and correct system flaws.",
            "applicable_finding_categories": [
                "vulnerable_component", "outdated_component", "code_quality"],
        },
        "SI-5": {
            "title": "Security Alerts, Advisories, and Directives",
            "description": "Receive and act on security advisories (e.g. CVE/KEV).",
            "applicable_finding_categories": [
                "vulnerable_component", "outdated_component"],
        },
        "RA-5": {
            "title": "Vulnerability Monitoring and Scanning",
            "description": "Scan for vulnerabilities and remediate legitimate findings.",
            "applicable_finding_categories": [
                "vulnerable_component", "misconfiguration", "injection",
                "xss", "sqli", "ssrf", "access_control"],
        },
        "SA-11": {
            "title": "Developer Testing and Evaluation",
            "description": "Developers perform security testing of the application.",
            "applicable_finding_categories": [
                "insecure_design", "code_quality", "injection", "crypto_weakness"],
        },
    },
}

FRAMEWORK_NAMES = {
    "pci": "PCI-DSS 4.0", "soc2": "SOC 2 (TSC)", "hipaa": "HIPAA Security Rule",
    "cis": "CIS Controls v8", "nist": "NIST SP 800-53",
}


# Vulnerability 'type' (as produced by the scanner's agents) -> category.
TYPE_CATEGORY = {
    "sqli": "sqli", "xss": "xss", "lfi": "path_traversal",
    "rce": "injection", "command_injection": "injection", "ssti": "injection",
    "idor": "access_control", "auth_bypass": "auth", "broken_auth": "auth",
    "ssrf": "ssrf", "path_traversal": "path_traversal",
    "file_upload": "vulnerable_component", "cors_misconfig": "misconfiguration",
    "weak_config": "misconfiguration", "misconfiguration": "misconfiguration",
    "sensitive_data_exposure": "sensitive_data_exposure",
    "crypto": "crypto_weakness", "crypto_weakness": "crypto_weakness",
    "csrf": "access_control", "outdated_component": "outdated_component",
    "vulnerable_component": "vulnerable_component",
}


def category_for_type(vuln_type: str) -> str:
    """Map a scanner vulnerability 'type' (e.g. 'sqli') to a normalized category."""
    if not vuln_type:
        return ""
    key = str(vuln_type).lower().strip()
    if key in CATEGORIES:
        return key
    return TYPE_CATEGORY.get(key, "")


def category_for_cwe(cwe: str) -> str:
    """Map a CWE id (e.g. 'CWE-89') to a normalized category, or '' if unknown."""
    if not cwe:
        return ""
    key = cwe.upper().strip()
    if not key.startswith("CWE-"):
        key = f"CWE-{key}"
    return CWE_CATEGORY.get(key, "")


def available_frameworks() -> List[str]:
    return list(FRAMEWORKS.keys())
