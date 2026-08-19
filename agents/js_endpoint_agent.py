"""
JavaScript Endpoint Extraction Agent
- Downloads all JS files from target
- Regex extraction of API endpoints, URLs, secrets
- LLM (small model) to identify additional endpoints from complex code
- Actively probes discovered endpoints
"""

import asyncio
import logging
import re
from typing import Any, List, Set, Dict
from urllib.parse import urlparse, urljoin

import httpx

from agents.base import BaseAgent
from core.models import AgentResult, Finding, FindingSeverity, FindingStatus
from agents.llm_client import LLMClient, TaskTier, llm_extract

logger = logging.getLogger(__name__)


# Regex patterns for endpoint/secret discovery
ENDPOINT_PATTERNS = [
    # Common API path patterns
    r'["\'`]/(api|rest|v\d+|graphql|admin|auth|user|users|login|logout|register|account|profile|dashboard|search|upload|download|file|files|data|export|import|config|settings)[/\w\-{}:.]*["\'`]',
    # fetch()/axios/request calls
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax)|XMLHttpRequest.*?open)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
    # URL constants
    r'(?:url|URL|endpoint|ENDPOINT|api|API|route|ROUTE)\s*[:=]\s*["\'`]([^"\'`]+)["\'`]',
    # Full URLs
    r'https?://[a-zA-Z0-9.\-]+/[a-zA-Z0-9/_\-.?=&{}]+',
]

SECRET_PATTERNS = {
    "AWS Access Key":       r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":       r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key["\'\s:=]+["\']([A-Za-z0-9/+=]{40})["\']',
    "Google API Key":       r'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token":          r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
    "GitHub Token":         r'gh[pousr]_[A-Za-z0-9]{36,255}',
    "Stripe Secret":        r'sk_(live|test)_[0-9a-zA-Z]{24,99}',
    "JWT Token":            r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*',
    "Private Key":          r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "Generic API Key":      r'(?i)(?:api[_\-]?key|apikey|api_secret|secret[_\-]?key)["\'\s:=]+["\']([A-Za-z0-9]{20,})["\']',
    "Bearer Token":         r'(?i)bearer\s+[A-Za-z0-9\-_=]{20,}',
    "Basic Auth in URL":    r'https?://[^:]+:[^@]+@[^\s]+',
}


class JSEndpointAgent(BaseAgent):
    """Extracts API endpoints and secrets from JavaScript files"""

    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "JavaScript Endpoint Analyst",
                          "js_endpoint_extraction", context)

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="JS endpoint extraction complete")
        target = self.context.target
        parsed = urlparse(target if "://" in target else f"https://{target}")
        base_url = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base_url += f":{parsed.port}"

        logger.info(f"JSEndpointAgent: Scanning {base_url}")

        # 1. Fetch main page and find JS files
        js_files = await self._discover_js_files(base_url)
        logger.info(f"  Found {len(js_files)} JS files")

        # 2. Download and analyze each JS file
        all_endpoints: Set[str] = set()
        all_secrets: List[Dict] = []
        analyzed_files = []

        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
            for js_url in list(js_files)[:15]:  # Cap at 15 files
                try:
                    r = await client.get(js_url)
                    if r.status_code == 200 and r.content:
                        content = r.text
                        endpoints = self._extract_endpoints(content, base_url)
                        secrets = self._extract_secrets(content, js_url)

                        all_endpoints.update(endpoints)
                        all_secrets.extend(secrets)
                        analyzed_files.append({
                            "url": js_url,
                            "size": len(content),
                            "endpoints_found": len(endpoints),
                            "secrets_found": len(secrets),
                        })
                        logger.info(f"    {js_url[:60]}...: {len(endpoints)} endpoints, {len(secrets)} secrets")
                except Exception as e:
                    logger.debug(f"  Failed to fetch {js_url}: {e}")

        # 3. Use LLM to find endpoints in obfuscated/complex code (SMALL model)
        llm_endpoints = await self._llm_extract_endpoints(analyzed_files, base_url)
        all_endpoints.update(llm_endpoints)

        # 4. Probe discovered endpoints to check accessibility
        logger.info(f"  Probing {len(all_endpoints)} discovered endpoints...")
        probe_results = await self._probe_endpoints(all_endpoints, base_url)

        # 5. Create findings for exposed secrets
        for secret in all_secrets:
            sev = FindingSeverity.CRITICAL if secret["type"] in [
                "AWS Access Key", "AWS Secret Key", "Private Key",
                "Stripe Secret", "GitHub Token"
            ] else FindingSeverity.HIGH
            result.findings.append(Finding(
                title=f"Secret Exposed in JS: {secret['type']}",
                description=f"Found {secret['type']} in {secret['source']}. Rotate immediately.",
                severity=sev, confidence=0.90,
                status=FindingStatus.CANDIDATE, category="credential_exposure",
                affected_asset=secret["source"], source_agent_id=self.agent_id
            ))

        # 6. Create findings for accessible sensitive endpoints
        for endpoint, probe in probe_results.items():
            if probe.get("accessible") and probe.get("sensitive"):
                result.findings.append(Finding(
                    title=f"Sensitive Endpoint Accessible: {endpoint}",
                    description=f"{endpoint} returned {probe['status']} - review access controls",
                    severity=FindingSeverity.MEDIUM, confidence=0.75,
                    status=FindingStatus.CANDIDATE, category="access_control",
                    affected_asset=f"{base_url}{endpoint}", source_agent_id=self.agent_id
                ))

        result.discoveries.append({
            "type": "js_endpoint_analysis",
            "target": base_url,
            "js_files_analyzed": analyzed_files,
            "js_file_count": len(analyzed_files),
            "endpoints_discovered": sorted(all_endpoints),
            "endpoint_count": len(all_endpoints),
            "endpoints_probed": probe_results,
            "secrets_found": all_secrets,
            "secret_count": len(all_secrets),
            "llm_assisted": len(llm_endpoints) > 0,
            "tools": ["httpx", "regex", "ollama_llm"]
        })

        logger.info(f"JSEndpointAgent: {len(all_endpoints)} endpoints, "
                    f"{len(all_secrets)} secrets, {len(result.findings)} findings")
        return result

    async def _discover_js_files(self, base_url: str) -> Set[str]:
        """Extract JS file URLs from main page HTML"""
        js_files: Set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                r = await client.get(base_url)
                if r.status_code == 200:
                    html = r.text

                    # <script src="...">
                    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
                        src = m.group(1)
                        if src.startswith("http"):
                            js_files.add(src)
                        elif src.startswith("//"):
                            js_files.add(f"{urlparse(base_url).scheme}:{src}")
                        else:
                            js_files.add(urljoin(base_url + "/", src))

                    # bundled JS references (main.*.js, runtime.*.js, etc)
                    for m in re.finditer(r'["\']([^"\']*(?:main|runtime|polyfills|vendor|app|bundle|chunk)[^"\']*\.js)["\']', html):
                        src = m.group(1)
                        if src.startswith("http"):
                            js_files.add(src)
                        else:
                            js_files.add(urljoin(base_url + "/", src))

        except Exception as e:
            logger.warning(f"Failed to discover JS files: {e}")

        return js_files

    def _extract_endpoints(self, js_content: str, base_url: str) -> Set[str]:
        """Regex-based endpoint extraction"""
        endpoints: Set[str] = set()
        base_host = urlparse(base_url).hostname

        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_content):
                candidate = match.group(1) if match.groups() else match.group(0)
                candidate = candidate.strip('"\'`')

                # Only keep same-origin or relative
                if candidate.startswith("http"):
                    if base_host and base_host in candidate:
                        endpoints.add(urlparse(candidate).path)
                elif candidate.startswith("/"):
                    # Skip common false positives
                    if not any(candidate.endswith(ext) for ext in
                                [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                                 ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map"]):
                        # Clean it up
                        clean = candidate.split("?")[0].split("#")[0]
                        if 3 < len(clean) < 200:
                            endpoints.add(clean)

        return endpoints

    def _extract_secrets(self, js_content: str, source: str) -> List[Dict]:
        """Find hardcoded secrets"""
        secrets = []
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, js_content):
                value = match.group(0)
                # Redact for safety in report
                redacted = value[:8] + "..." + value[-4:] if len(value) > 16 else "***"
                secrets.append({
                    "type": secret_type,
                    "source": source,
                    "redacted_value": redacted,
                })
        return secrets

    async def _llm_extract_endpoints(self, analyzed_files: List[Dict], base_url: str) -> Set[str]:
        """Use small LLM to find endpoints in complex/obfuscated JS"""
        client = LLMClient.get()
        if not await client.is_available():
            logger.info("  LLM unavailable, skipping AI-assisted extraction")
            return set()

        # Only process a few files with LLM to save time
        endpoints: Set[str] = set()
        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as http:
            for file_info in analyzed_files[:3]:  # Only top 3 files
                try:
                    r = await http.get(file_info["url"])
                    if r.status_code != 200:
                        continue

                    content = r.text[:8000]  # First 8KB only

                    result = await llm_extract(
                        content,
                        "Extract all API endpoint paths from this JavaScript code. "
                        "Look for URLs starting with /api/, /rest/, /v1/, /v2/, or paths passed to fetch/axios/ajax calls. "
                        "Only return real endpoint paths that this code calls. "
                        "Ignore image/font/css paths. "
                        'Format: {"endpoints": ["/api/users", "/api/products", ...]}',
                        tier=TaskTier.SMALL
                    )

                    for ep in result.get("endpoints", []):
                        if isinstance(ep, str) and ep.startswith("/") and len(ep) < 200:
                            endpoints.add(ep)

                except Exception as e:
                    logger.debug(f"  LLM extraction failed for {file_info['url']}: {e}")

        if endpoints:
            logger.info(f"  LLM found {len(endpoints)} additional endpoints")
        return endpoints

    async def _probe_endpoints(self, endpoints: Set[str], base_url: str) -> Dict[str, Dict]:
        """Probe endpoints to check status and sensitivity"""
        results = {}
        sensitive_keywords = ["admin", "config", "debug", "secret", "internal",
                                "backup", "test", "dev", ".env", "private"]

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
            tasks = []
            endpoint_list = list(endpoints)[:50]  # Cap probes

            for ep in endpoint_list:
                if not ep.startswith("/"):
                    ep = "/" + ep
                tasks.append(self._probe_single(client, base_url, ep))

            probe_data = await asyncio.gather(*tasks, return_exceptions=True)

            for ep, data in zip(endpoint_list, probe_data):
                if isinstance(data, Exception):
                    continue
                if data:
                    ep_lower = ep.lower()
                    data["sensitive"] = any(kw in ep_lower for kw in sensitive_keywords)
                    results[ep] = data

        return results

    async def _probe_single(self, client, base_url: str, endpoint: str) -> Dict:
        try:
            r = await client.get(f"{base_url}{endpoint}")
            return {
                "status": r.status_code,
                "accessible": r.status_code in [200, 201, 301, 302, 401, 403],
                "size": len(r.content),
                "content_type": r.headers.get("content-type", "")[:100],
            }
        except:
            return {}