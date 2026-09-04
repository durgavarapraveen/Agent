"""
Feedback Loop Engine (Phase 11).

Implements closed-loop adaptive testing:
1. Classify response
2. Update hypothesis confidence
3. Choose next payload/strategy
4. Adapt to WAF/blocking patterns
5. Mine errors for intelligence
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ResponseSignature:
    status_code: int = 0
    content_length: int = 0
    body_hash: str = ""
    reflected_inputs: List[str] = field(default_factory=list)
    error_patterns: List[str] = field(default_factory=list)
    timing_ms: float = 0.0
    headers_of_interest: Dict[str, str] = field(default_factory=dict)
    redirect_url: str = ""
    technologies_detected: List[str] = field(default_factory=list)


class ResponseClassifier:

    ERROR_PATTERNS = {
        "sql_error": [
            r"SQL syntax", r"mysql_fetch", r"pg_query", r"ORA-\d+",
            r"sqlite3\.OperationalError", r"Microsoft SQL Native Client",
            r"SQLSTATE\[", r"syntax error at or near",
        ],
        "path_disclosure": [
            r"/var/www/", r"/home/\w+/", r"C:\\\\inetpub",
            r"/usr/local/", r"DocumentRoot",
        ],
        "stack_trace": [
            r"Traceback \(most recent", r"at \w+\.java:\d+",
            r"TypeError:", r"ReferenceError:", r"NullPointerException",
            r"at Object\.<anonymous>",
        ],
        "template_error": [
            r"TemplateSyntaxError", r"Jinja2", r"freemarker",
            r"Twig_Error", r"smarty",
        ],
        "debug_info": [
            r"DEBUG\s*=\s*True", r"DJANGO_SETTINGS", r"phpinfo\(\)",
            r"X-Debug-", r"SERVER_SOFTWARE",
        ],
        "waf_block": [
            r"403 Forbidden", r"Access Denied", r"Request Blocked",
            r"ModSecurity", r"Web Application Firewall",
            r"Cloudflare", r"AWS WAF",
        ],
    }

    TECH_SIGNATURES = {
        "php": [r"X-Powered-By:\s*PHP", r"\.php", r"PHPSESSID"],
        "asp.net": [r"X-Powered-By:\s*ASP\.NET", r"\.aspx", r"__VIEWSTATE"],
        "java": [r"X-Powered-By:\s*Servlet", r"JSESSIONID", r"\.jsp"],
        "python": [r"X-Powered-By:\s*Python", r"csrfmiddlewaretoken"],
        "node": [r"X-Powered-By:\s*Express", r"connect\.sid"],
        "nginx": [r"Server:\s*nginx"],
        "apache": [r"Server:\s*Apache"],
    }

    def classify(self, status_code: int, headers: Dict[str, str],
                 body: str, timing_ms: float,
                 injected_input: str = "") -> ResponseSignature:
        sig = ResponseSignature(
            status_code=status_code,
            content_length=len(body),
            body_hash=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16],
            timing_ms=timing_ms,
        )

        if injected_input and injected_input in body:
            sig.reflected_inputs.append(injected_input)

        for category, patterns in self.ERROR_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    sig.error_patterns.append(category)
                    break

        for header_name in ("server", "x-powered-by", "set-cookie",
                            "content-security-policy", "x-frame-options",
                            "access-control-allow-origin"):
            val = headers.get(header_name, "")
            if val:
                sig.headers_of_interest[header_name] = val

        location = headers.get("location", "")
        if location:
            sig.redirect_url = location

        all_text = body + " ".join(f"{k}: {v}" for k, v in headers.items())
        for tech, patterns in self.TECH_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, all_text, re.IGNORECASE):
                    sig.technologies_detected.append(tech)
                    break

        return sig


class ErrorMiner:

    def mine(self, body: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        intel: Dict[str, Any] = {
            "file_paths": [],
            "technologies": [],
            "db_type": "",
            "framework": "",
            "error_messages": [],
        }

        path_patterns = [
            r"(/(?:var|home|usr|opt|etc|srv)/[\w/._-]+)",
            r"([A-Z]:\\\\[\w\\\\._-]+)",
        ]
        for pat in path_patterns:
            intel["file_paths"].extend(re.findall(pat, body))

        db_hints = {
            "mysql": r"mysql|MariaDB",
            "postgres": r"postgres|pg_",
            "mssql": r"Microsoft SQL|MSSQL|sqlsrv",
            "oracle": r"ORA-\d+|Oracle",
            "sqlite": r"sqlite",
            "mongodb": r"MongoError|mongo",
        }
        for db, pat in db_hints.items():
            if re.search(pat, body, re.IGNORECASE):
                intel["db_type"] = db
                break

        framework_hints = {
            "django": r"django|csrfmiddlewaretoken",
            "flask": r"Werkzeug|flask",
            "spring": r"org\.springframework|Whitelabel Error",
            "express": r"Cannot (GET|POST|PUT)|Express",
            "rails": r"ActionController|ActiveRecord",
            "laravel": r"Laravel|Illuminate\\\\",
            "aspnet": r"ASP\.NET|__VIEWSTATE",
        }
        for fw, pat in framework_hints.items():
            if re.search(pat, body, re.IGNORECASE):
                intel["framework"] = fw
                break

        error_lines = re.findall(r"(?:Error|Exception|Warning|Fatal)[\s:]+(.{10,120})", body)
        intel["error_messages"] = error_lines[:10]

        return intel


class PayloadAdapter:

    def __init__(self) -> None:
        self._blocked_patterns: Dict[str, List[str]] = {}
        self._effective_patterns: Dict[str, List[str]] = {}

    def record_blocked(self, target: str, payload: str) -> None:
        self._blocked_patterns.setdefault(target, []).append(payload)

    def record_effective(self, target: str, payload: str) -> None:
        self._effective_patterns.setdefault(target, []).append(payload)

    def is_likely_blocked(self, target: str, payload: str) -> bool:
        blocked = self._blocked_patterns.get(target, [])
        for b in blocked:
            if b in payload or payload in b:
                return True
        return False

    def suggest_alternative(self, target: str, blocked_payload: str,
                            alternatives: List[str]) -> Optional[str]:
        for alt in alternatives:
            if not self.is_likely_blocked(target, alt):
                return alt
        return None

    def get_evasion_level(self, target: str) -> int:
        blocked = self._blocked_patterns.get(target, [])
        if len(blocked) > 10:
            return 2
        elif len(blocked) > 3:
            return 1
        return 0


class FeedbackLoopEngine:

    def __init__(self) -> None:
        self.classifier = ResponseClassifier()
        self.error_miner = ErrorMiner()
        self.payload_adapter = PayloadAdapter()
        self._baseline_signatures: Dict[str, ResponseSignature] = {}
        self._observations: List[Dict[str, Any]] = []

    def record_baseline(self, endpoint_key: str, status_code: int,
                        headers: Dict[str, str], body: str,
                        timing_ms: float) -> ResponseSignature:
        sig = self.classifier.classify(status_code, headers, body, timing_ms)
        self._baseline_signatures[endpoint_key] = sig
        return sig

    def analyze_response(self, endpoint_key: str, status_code: int,
                         headers: Dict[str, str], body: str,
                         timing_ms: float, payload: str = "",
                         target: str = "") -> Dict[str, Any]:
        sig = self.classifier.classify(status_code, headers, body,
                                       timing_ms, payload)
        baseline = self._baseline_signatures.get(endpoint_key)
        analysis: Dict[str, Any] = {
            "signature": sig,
            "is_different": False,
            "differences": [],
            "intelligence": {},
            "waf_detected": False,
            "recommendation": "continue",
        }

        if baseline:
            if sig.status_code != baseline.status_code:
                analysis["differences"].append(
                    f"status: {baseline.status_code} → {sig.status_code}")
                analysis["is_different"] = True
            length_delta = abs(sig.content_length - baseline.content_length)
            if length_delta > 100:
                analysis["differences"].append(
                    f"length: {baseline.content_length} → {sig.content_length}")
                analysis["is_different"] = True
            if sig.body_hash != baseline.body_hash:
                analysis["differences"].append("body_hash_changed")
                analysis["is_different"] = True
            if sig.timing_ms > baseline.timing_ms * 3 and sig.timing_ms > 2000:
                analysis["differences"].append(
                    f"timing: {baseline.timing_ms:.0f} → {sig.timing_ms:.0f}ms")
                analysis["is_different"] = True

        if sig.reflected_inputs:
            analysis["is_different"] = True
            analysis["differences"].append(f"input_reflected: {sig.reflected_inputs}")

        if sig.error_patterns:
            analysis["intelligence"] = self.error_miner.mine(body, headers)
            analysis["is_different"] = True

        if "waf_block" in sig.error_patterns:
            analysis["waf_detected"] = True
            if target:
                self.payload_adapter.record_blocked(target, payload)
            analysis["recommendation"] = "increase_evasion"
        elif not analysis["is_different"]:
            analysis["recommendation"] = "try_next_payload"

        self._observations.append({
            "endpoint": endpoint_key,
            "payload": payload[:500],
            "is_different": analysis["is_different"],
            "waf": analysis["waf_detected"],
        })

        return analysis

    def get_recommended_evasion_level(self, target: str) -> int:
        return self.payload_adapter.get_evasion_level(target)

    def observation_count(self) -> int:
        return len(self._observations)
