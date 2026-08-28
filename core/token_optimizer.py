"""
Context Compression & Token Optimization Module (Phase 3 Module 3.4).
Provides endpoint filtering, tech stack compression, quick vuln pattern detection,
exact token estimation via tiktoken (with fallback), deduplication, tool output trimming,
finding rank prioritization, dynamic threshold compression (70%),
and emergency 90% warning degradation logging.
"""

import json
import logging
import os
import re
from typing import Dict, List, Optional, Set, Tuple, Any

logger = logging.getLogger(__name__)

# Attempt tiktoken import with graceful word-estimation fallback
try:
    import tiktoken
    HAS_TIKTOKEN = True
except ImportError:
    HAS_TIKTOKEN = False

STRIPPED_FINDINGS_LOG = "stripped_findings_audit.log"


class TokenOptimizer:
    """Optimize data sent to LLM to reduce token usage and manage token budgeting."""

    # Safe patterns to filter out (no vulns here)
    SAFE_PATTERNS = {
        r'^/static/',
        r'^/assets/',
        r'^/public/',
        r'^/images?/',
        r'^/img/',
        r'^/css/',
        r'^/js/',
        r'^/fonts/',
        r'\.(js|css|jpg|jpeg|png|gif|svg|woff|woff2|ttf|eot)$',
        r'^/health$',
        r'^/ping$',
        r'^/status$',
        r'^/metrics$',
        r'^/api/docs',
        r'^/swagger',
        r'^/openapi',
    }

    # Suspicious patterns worth investigating
    SUSPICIOUS_PATTERNS = {
        r'/api/': 'API endpoint',
        r'/admin': 'Admin panel',
        r'/login': 'Authentication',
        r'/auth': 'Authentication',
        r'/register': 'User registration',
        r'/profile': 'User profile',
        r'/upload': 'File upload',
        r'/file': 'File handling',
        r'/download': 'File download',
        r'/search': 'Search functionality',
        r'/filter': 'Data filtering',
        r'/query': 'Query endpoint',
        r'/\{id\}': 'ID parameter',
        r'\?': 'Query parameters',
    }

    def __init__(self, model_name: str = "gpt-4", token_limit: int = 8000):
        self.model_name = model_name
        self.token_limit = token_limit
        if HAS_TIKTOKEN:
            try:
                self.encoding = tiktoken.encoding_for_model(model_name)
            except Exception:
                self.encoding = tiktoken.get_encoding("cl100k_base")
        else:
            self.encoding = None

    def count_tokens(self, text: str) -> int:
        """Count tokens using tiktoken if available, else approximate 1 token = ~4 chars."""
        if not text:
            return 0
        if self.encoding:
            return len(self.encoding.encode(text))
        return max(1, len(text) // 4)

    def trim_tool_output(self, output: str, max_lines: int = 10) -> str:
        """Trim tool execution output to the last N lines where errors/summaries are printed."""
        if not output:
            return ""
        lines = output.strip().splitlines()
        if len(lines) <= max_lines:
            return output
        return f"[... truncated {len(lines) - max_lines} lines ...]\n" + "\n".join(lines[-max_lines:])

    def rank_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Rank findings by:
          1. Severity (Critical > High > Medium > Low)
          2. Exploitability (Public exploit > PoC > Theoretical)
        """
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        exploit_map = {"PUBLIC EXPLOIT": 3, "POC": 2, "THEORETICAL": 1}

        def _key(f: Dict[str, Any]):
            s_val = sev_map.get(str(f.get("severity", "LOW")).upper(), 1)
            e_str = str(f.get("exploitability", f.get("exploit_type", "THEORETICAL"))).upper()
            e_val = 1
            for k, v in exploit_map.items():
                if k in e_str:
                    e_val = v
                    break
            return (s_val, e_val, float(f.get("confidence_score", f.get("confidence", 0.5))))

        return sorted(findings, key=_key, reverse=True)

    def deduplicate_and_filter_findings(self, findings: List[Dict[str, Any]], min_confidence: float = 0.30) -> List[Dict[str, Any]]:
        """
        Deduplicate identical findings and filter out findings with confidence < min_confidence (30%).
        """
        seen_keys = set()
        deduped = []

        for f in findings:
            conf = float(f.get("confidence_score", f.get("confidence", 1.0)))
            if conf < min_confidence:
                logger.debug(f"[TokenOptimizer] Filtering low-confidence finding ({conf} < {min_confidence}): {f.get('title') or f.get('cve_id')}")
                continue

            dedup_key = (
                str(f.get("cve_id") or f.get("title") or f.get("type", "")).strip().upper(),
                str(f.get("target") or f.get("url") or f.get("location", "")).strip().lower()
            )
            if dedup_key in seen_keys:
                continue

            seen_keys.add(dedup_key)
            deduped.append(f)

        return deduped

    def compress_prompt_context(self, prompt: str, findings: List[Dict[str, Any]], tool_outputs: Dict[str, str]) -> Dict[str, Any]:
        """
        Calculates token budget. If tokens > 70%, triggers compression.
        If tokens > 90%, raises TokenLimitWarning, strips all but top 5 findings, and logs stripped findings.
        """
        # Trim tool outputs first
        trimmed_tool_outputs = {k: self.trim_tool_output(v, 10) for k, v in tool_outputs.items()}

        # Filter and rank findings
        filtered_findings = self.deduplicate_and_filter_findings(findings, min_confidence=0.30)
        ranked_findings = self.rank_findings(filtered_findings)

        context_payload = {
            "prompt": prompt,
            "findings": ranked_findings,
            "tool_outputs": trimmed_tool_outputs
        }
        raw_text = json.dumps(context_payload)
        token_count = self.count_tokens(raw_text)
        token_ratio = token_count / float(self.token_limit)

        status_flag = "NORMAL"
        compressed_findings = list(ranked_findings)

        if token_ratio > 0.90:
            status_flag = "TOKEN_LIMIT_WARNING_90"
            logger.warning(f"[TokenOptimizer] EMERGENCY TOKEN WARNING: Token count ({token_count}) exceeds 90% limit! Stripping to top 5 critical findings.")

            keep_count = 5
            compressed_findings = ranked_findings[:keep_count]
            stripped_findings = ranked_findings[keep_count:]

            # Log stripped findings to file
            if stripped_findings:
                try:
                    with open(STRIPPED_FINDINGS_LOG, "a", encoding="utf-8") as f:
                        f.write(f"=== STRIPPED FINDINGS AT 90% TOKEN WARNING (Count: {len(stripped_findings)}) ===\n")
                        f.write(json.dumps(stripped_findings, indent=2) + "\n")
                except Exception as e:
                    logger.error(f"[TokenOptimizer] Failed writing stripped findings log: {e}")

        elif token_ratio > 0.70:
            status_flag = "COMPRESSION_TRIGGERED_70"
            logger.info(f"[TokenOptimizer] Token ratio ({round(token_ratio * 100, 1)}%) exceeds 70%. Triggering smart compression.")

            # Calculate dynamic N based on 60% token limit allocation
            budget_tokens = int(self.token_limit * 0.60)
            avg_tokens_per_finding = max(50, self.count_tokens(json.dumps(ranked_findings[0])) if ranked_findings else 100)
            keep_n = max(1, budget_tokens // avg_tokens_per_finding)
            compressed_findings = ranked_findings[:keep_n]

        final_payload = {
            "prompt": prompt,
            "findings": compressed_findings,
            "tool_outputs": trimmed_tool_outputs
        }
        final_text = json.dumps(final_payload)
        final_token_count = self.count_tokens(final_text)

        reduction_percent = round(((token_count - final_token_count) / float(token_count)) * 100.0, 1) if token_count > 0 else 0.0

        return {
            "status": status_flag,
            "original_token_count": token_count,
            "final_token_count": final_token_count,
            "reduction_percent": reduction_percent,
            "compressed_payload": final_payload
        }

    # Static utility methods preserved for backward compatibility
    @staticmethod
    def filter_endpoints(endpoints: List[Dict]) -> List[Dict]:
        """
        SAFE endpoint filtering (60-70% reduction, 0% analysis loss)
        - ALWAYS KEEP: /api/*, endpoints with parameters, /admin, /auth, /upload
        - SAFE TO FILTER: static files (.js, .css, .jpg), /health, /ping, /docs
        """
        filtered = []
        DANGEROUS_PATHS = {
            '/api/', '/admin/', '/upload', '/file', '/download',
            '/user', '/profile', '/account', '/auth', '/login', '/register'
        }
        STATIC_EXTENSIONS = {
            '.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg',
            '.woff', '.woff2', '.ttf', '.eot', '.ico', '.webp',
            '.mp4', '.mp3', '.pdf'
        }
        SAFE_PATHS_TO_REMOVE = {
            '/health', '/ping', '/status', '/metrics',
            '/docs', '/swagger', '/openapi', '/.well-known'
        }

        for endpoint in endpoints:
            url = endpoint.get('url', '').lower()
            if any(path in url for path in DANGEROUS_PATHS):
                filtered.append(endpoint)
                continue
            if '?' in url or '{' in url or '[' in url:
                filtered.append(endpoint)
                continue
            if any(url.endswith(ext) for ext in STATIC_EXTENSIONS):
                continue
            if any(path in url for path in SAFE_PATHS_TO_REMOVE):
                continue
            filtered.append(endpoint)

        return filtered

    @staticmethod
    def compress_tech_stack(technologies: Dict[str, List[str]]) -> str:
        """Compress technology stack to key frameworks only."""
        tech_list = []
        for tech_list_per_domain in technologies.values():
            for tech in tech_list_per_domain:
                tech_clean = tech.split('/')[0].strip()
                if tech_clean not in tech_list:
                    tech_list.append(tech_clean)

        important_frameworks = {
            'Node.js', 'Express', 'Django', 'Flask', 'Rails', 'Laravel',
            'Java', 'Spring', 'ASP.NET', 'Go', 'Rust',
            'Angular', 'React', 'Vue', 'Next',
            'MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'SQLite',
            'Apache', 'Nginx', 'IIS',
            'PHP', 'Python', 'JavaScript', 'C#',
            'JWT', 'OAuth', 'CORS', 'REST', 'GraphQL',
        }
        filtered = [t for t in tech_list if any(fw in t for fw in important_frameworks)]
        return ', '.join(filtered[:15])

    @staticmethod
    def detect_quick_vulns(endpoints: List[Dict]) -> List[Dict]:
        """Detect obvious vulnerability patterns without LLM calls."""
        vulns = []
        seen_types = set()

        for endpoint in endpoints:
            url = endpoint.get('url', '').lower()
            if any(x in url for x in ['?id=', '?user=', '?search=', '?query=']):
                if 'sqli' not in seen_types:
                    vulns.append({'type': 'sqli', 'title': 'Potential SQL Injection', 'severity': 'HIGH', 'location': url, 'reason': 'Endpoint with ID/search parameter'})
                    seen_types.add('sqli')
            if '/api/user' in url or '/profile/' in url or '/account/' in url:
                if 'idor' not in seen_types:
                    vulns.append({'type': 'idor', 'title': 'Potential IDOR', 'severity': 'MEDIUM', 'location': url, 'reason': 'User resource endpoint with ID parameter'})
                    seen_types.add('idor')
            if '/upload' in url or '/file' in url:
                if 'upload' not in seen_types:
                    vulns.append({'type': 'upload', 'title': 'File Upload Endpoint', 'severity': 'MEDIUM', 'location': url, 'reason': 'File upload functionality detected'})
                    seen_types.add('upload')
            if '/login' in url or '/auth' in url:
                if 'auth_bypass' not in seen_types:
                    vulns.append({'type': 'auth_bypass', 'title': 'Authentication Endpoint', 'severity': 'HIGH', 'location': url, 'reason': 'Potential auth bypass or brute force'})
                    seen_types.add('auth_bypass')
            if '/admin' in url or '/dashboard' in url:
                if 'admin_access' not in seen_types:
                    vulns.append({'type': 'admin_access', 'title': 'Admin Panel Found', 'severity': 'MEDIUM', 'location': url, 'reason': 'Admin functionality may be accessible'})
                    seen_types.add('admin_access')

        return vulns

    @staticmethod
    def build_optimized_analysis_prompt(endpoints: List[Dict], technologies: str, quick_vulns: List[Dict]) -> str:
        """Build concise prompt for LLM analysis."""
        prompt = f"Analyze for HIGH severity vulnerabilities only.\n\nTECH STACK: {technologies}\n\nENDPOINTS:\n"
        for ep in endpoints[:20]:
            prompt += f"  - {ep.get('url', '')}\n"
        if quick_vulns:
            prompt += f"\nALREADY DETECTED ({len(quick_vulns)} found):\n"
            for v in quick_vulns:
                prompt += f"  - {v['type']}: {v['title']}\n"
            prompt += "\nFind ADDITIONAL vulnerabilities not listed above.\n"
        prompt += """\nReturn JSON ONLY:\n{\n  "vulnerabilities": [\n    {"title": "...", "type": "...", "severity": "HIGH|MEDIUM", "location": "...", "reason": "..."}\n  ],\n  "chains": [\n    {"chain": ["vuln1", "vuln2"], "impact": "..."}\n  ]\n}"""
        return prompt