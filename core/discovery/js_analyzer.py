"""
JavaScript Analysis Pipeline — deep extraction of endpoints, API keys,
secrets, and sensitive data from JS bundles, source maps, and webpack chunks.
"""

import json
import logging
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class JSFinding:
    category: str  # "endpoint", "secret", "api_key", "token", "config"
    value: str
    source_url: str
    context: str = ""  # surrounding code
    confidence: float = 0.5


# Regex patterns for secret detection (beyond what APIReconstructor has)
SECRET_PATTERNS = [
    # Cloud provider keys
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "api_key", 0.95),
    (r'(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key", "secret", 0.95),
    (r'(?:GOOG|AIza)[A-Za-z0-9_\\-]{35}', "Google API Key", "api_key", 0.9),
    (r'ya29\.[0-9A-Za-z_-]+', "Google OAuth Token", "token", 0.85),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}', "GitHub Token", "token", 0.95),
    (r'glpat-[A-Za-z0-9_\-]{20,}', "GitLab PAT", "token", 0.95),
    (r'sk-[A-Za-z0-9]{48,}', "OpenAI API Key", "api_key", 0.95),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe Live Key", "api_key", 0.95),
    (r'sk_test_[A-Za-z0-9]{24,}', "Stripe Test Key", "api_key", 0.8),
    (r'pk_live_[A-Za-z0-9]{24,}', "Stripe Publishable Key", "api_key", 0.7),
    (r'sq0csp-[A-Za-z0-9_-]{43}', "Square OAuth Secret", "secret", 0.9),
    (r'xox[baprs]-[A-Za-z0-9-]{10,}', "Slack Token", "token", 0.9),
    (r'https://hooks\.slack\.com/services/T[A-Za-z0-9]{8}/B[A-Za-z0-9]{8}/[A-Za-z0-9]{24}', "Slack Webhook", "secret", 0.95),
    (r'(?:twilio|TWILIO).*(?:AC|SK)[a-f0-9]{32}', "Twilio Key", "api_key", 0.85),
    (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', "SendGrid Key", "api_key", 0.95),
    (r'key-[A-Za-z0-9]{32}', "Mailgun Key", "api_key", 0.8),
    (r'(?:AZURE|azure)[_\s]*(?:KEY|key|secret)[_\s]*[=:]\s*["\']([A-Za-z0-9+/=]{40,})["\']', "Azure Key", "secret", 0.85),

    # JWT and session tokens
    (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT Token", "token", 0.9),
    (r'(?:session|token|auth|bearer|api_key|apikey|api-key|access_token|secret_key|private_key)\s*[=:]\s*["\']([A-Za-z0-9_\-/.+]{16,})["\']', "Hardcoded Credential", "secret", 0.7),

    # Database connection strings
    (r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\'<>]{10,}', "Database Connection String", "secret", 0.9),
    (r'(?:jdbc|odbc):[^\s"\'<>]{10,}', "JDBC/ODBC Connection String", "secret", 0.85),

    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key", "secret", 0.95),
    (r'-----BEGIN CERTIFICATE-----', "Certificate", "config", 0.6),

    # Internal URLs and IPs
    (r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[:/][^\s"\'<>]*', "Internal URL", "config", 0.8),
    (r'https?://localhost[:/][^\s"\'<>]*', "Localhost URL", "config", 0.6),
]

# Endpoint patterns
ENDPOINT_PATTERNS = [
    r'["\'](/api/v?\d*/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/rest/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/graphql[a-zA-Z0-9_/\-]*)["\']',
    r'["\'](/v[1-9]/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/auth/[a-zA-Z0-9_/\-]+)["\']',
    r'["\'](/admin/[a-zA-Z0-9_/\-]+)["\']',
    r'["\'](/internal/[a-zA-Z0-9_/\-]+)["\']',
    r'["\'](/webhook[s]?/[a-zA-Z0-9_/\-]+)["\']',
    r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']\s*\)',
    r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']\s*\)',
    r'\.(?:get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']\s*\)',
    r'(?:baseURL|baseUrl|apiUrl|API_URL|API_BASE|API_HOST)\s*[=:]\s*[`"\']([^`"\']+)[`"\']',
    r'(?:endpoint|ENDPOINT|apiEndpoint)\s*[=:]\s*[`"\']([^`"\']+)[`"\']',
]

# Source map detection
SOURCE_MAP_PATTERNS = [
    r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
    r'/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/',
]


# P2-2: content-addressed bundle cache. A bundle version (by content hash) is
# analyzed once per process; identical re-fetches (main.js/vendor.js re-crawled
# across phases) skip the expensive regex/tool/source-map passes.
_ANALYZED_BUNDLE_HASHES: Set[str] = set()


class JSAnalyzer:
    """Deep JavaScript analysis for endpoint and secret extraction."""

    def __init__(self, target: str, timeout: int = 30, asset_registry=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.asset_registry = asset_registry
        self.findings: List[JSFinding] = []
        self._seen_values: Set[str] = set()
        self.js_urls: List[str] = []
        self.source_map_urls: List[str] = []

    def _origin(self) -> str:
        """P1.2: resolve against the origin assets were actually served from
        (learned via the AssetRegistry) rather than a possibly-unreachable
        global target — the cause of the container curl rc=7 drop."""
        reg = getattr(self, "asset_registry", None)
        if reg is not None:
            try:
                po = reg.primary_origin()
                if po:
                    return po
            except Exception:
                pass
        return self.target

    def _resolve(self, ref: str) -> str:
        """Resolve a root-relative asset ref against the canonical origin."""
        reg = getattr(self, "asset_registry", None)
        if reg is not None:
            try:
                return reg.resolve(ref, self._origin())
            except Exception:
                pass
        from urllib.parse import urljoin as _uj
        return _uj(self._origin().rstrip("/") + "/", ref.lstrip("/"))

    def _fetch(self, url: str) -> str:
        """Fetch URL content via curl. URL is shlex-quoted to prevent shell
        injection through user-controlled URLs (was `"{url}"` interpolation)."""
        import shlex
        from agents.kali_executor import KaliDockerExecutor
        cmd = f'curl -s -L -k --max-time {int(self.timeout)} {shlex.quote(url)}'
        result = KaliDockerExecutor.run(cmd, timeout=self.timeout + 10)
        if result.get("status") == "success":
            return result.get("stdout", "")
        return ""

    def discover_js_files(self, html: str = None, endpoints: List = None) -> List[str]:
        """Find all JavaScript file URLs from HTML and known endpoints."""
        urls = set()

        # P1.2: seed from canonical registered assets (real origin URLs).
        reg = getattr(self, "asset_registry", None)
        if reg is not None:
            try:
                urls.update(reg.js_urls())
            except Exception:
                pass

        # Fetch main page if no HTML provided (against the canonical origin).
        if not html:
            html = self._fetch(self._origin())

        if html:
            # Find script src attributes
            for match in re.finditer(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = match.group(1)
                if src.endswith(".js") or ".js?" in src or "/js/" in src:
                    if src.startswith("http"):
                        urls.add(src)
                    elif src.startswith("//"):
                        urls.add(f"https:{src}")
                    elif src.startswith("/"):
                        urls.add(self._resolve(src))

            # Find webpack chunk references
            for match in re.finditer(r'["\']([^"\']*(?:chunk|bundle|vendor|app|main)[^"\']*\.js)["\']', html):
                path = match.group(1)
                if path.startswith("http"):
                    urls.add(path)
                elif path.startswith("/"):
                    urls.add(self._resolve(path))

        # Check common JS paths
        common_js_paths = [
            "/static/js/main.js", "/static/js/app.js",
            "/assets/js/app.js", "/js/app.js",
            "/bundle.js", "/app.js", "/main.js",
            "/_next/static/chunks/main.js",
            "/static/js/bundle.js",
        ]
        for path in common_js_paths:
            urls.add(self._resolve(path))

        # From known endpoints that look like JS files
        for ep in (endpoints or []):
            url = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else "")
            if url and (".js" in url or "/js/" in url):
                urls.add(url)

        self.js_urls = list(urls)
        logger.info(f"[JSAnalyzer] Discovered {len(self.js_urls)} potential JS files")
        return self.js_urls

    def _run_linkfinder(self, js_url: str) -> List[str]:
        """Run LinkFinder tool to extract endpoints from a JS file."""
        from agents.kali_executor import KaliDockerExecutor

        # Check if linkfinder is available
        check = KaliDockerExecutor.run("which linkfinder 2>/dev/null || which python3 -c 'import linkfinder' 2>/dev/null", timeout=5)
        if check.get("status") != "success" or not check.get("stdout", "").strip():
            return []

        import shlex
        cmd = f'linkfinder -i {shlex.quote(js_url)} -o cli 2>/dev/null'
        result = KaliDockerExecutor.run(cmd, timeout=self.timeout)
        if result.get("status") != "success":
            return []

        endpoints = []
        for line in result.get("stdout", "").strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("[") and len(line) > 1:
                endpoints.append(line)
        return endpoints

    def _run_secretfinder(self, js_url: str) -> List[Tuple[str, str]]:
        """Run SecretFinder tool to extract secrets from a JS file."""
        from agents.kali_executor import KaliDockerExecutor

        check = KaliDockerExecutor.run("which secretfinder 2>/dev/null", timeout=5)
        if check.get("status") != "success" or not check.get("stdout", "").strip():
            return []

        import shlex
        cmd = f'secretfinder -i {shlex.quote(js_url)} -o cli 2>/dev/null'
        result = KaliDockerExecutor.run(cmd, timeout=self.timeout)
        if result.get("status") != "success":
            return []

        # SecretFinder output shape (as of upstream v1.1.2):
        #   [+] Reason: <label>
        #   [+] Match: <value>
        # Some builds also emit `<label> : <value>` on a single line. We
        # accept the multi-line block first (correct + machine-readable),
        # then fall back to the loose single-line split — but only when the
        # colon appears AFTER a plausible label. The previous naive
        # `":" in line` matched URLs and timestamps too, filling the secrets
        # list with junk.
        secrets = []
        raw = result.get("stdout", "") or ""
        lines = raw.strip().split("\n")

        current_reason = None
        for line in lines:
            line = line.strip()
            if not line:
                current_reason = None
                continue
            low = line.lower()
            if low.startswith("[+] reason"):
                current_reason = line.split(":", 1)[1].strip() if ":" in line else None
                continue
            if low.startswith("[+] match") and current_reason:
                val = line.split(":", 1)[1].strip() if ":" in line else ""
                if val:
                    secrets.append((current_reason, val))
                current_reason = None
                continue

            # Fallback: `Label : value` on one line — require the label to
            # be short and word-like so URLs / stack traces don't match.
            import re as _re_sf
            m = _re_sf.match(r"^([A-Za-z][\w .()/-]{2,40}?)\s*:\s*(\S.*)$", line)
            if m:
                label, value = m.group(1).strip(), m.group(2).strip()
                # Skip when the "value" is itself a URL suffix like `//example.com`.
                if value and not value.startswith(("//", "/")):
                    secrets.append((label, value))

        return secrets

    def _extract_source_maps(self, js_content: str, js_url: str) -> List[str]:
        """Find and download source maps referenced in JS files."""
        maps = []
        for pattern in SOURCE_MAP_PATTERNS:
            for match in re.finditer(pattern, js_content):
                map_ref = match.group(1).strip()
                if map_ref.startswith("data:"):
                    continue
                if map_ref.startswith("http"):
                    map_url = map_ref
                elif map_ref.startswith("/"):
                    map_url = self._resolve(map_ref)
                else:
                    base = js_url.rsplit("/", 1)[0]
                    map_url = f"{base}/{map_ref}"
                maps.append(map_url)
                self.source_map_urls.append(map_url)
        return maps

    def _analyze_source_map(self, map_url: str) -> str:
        """Download and extract source code from a source map."""
        content = self._fetch(map_url)
        if not content:
            return ""

        try:
            smap = json.loads(content)
            sources_content = smap.get("sourcesContent", [])
            if sources_content:
                combined = "\n".join(s for s in sources_content if isinstance(s, str))
                logger.info(f"[JSAnalyzer] Source map {map_url}: {len(sources_content)} source files extracted")
                return combined
        except json.JSONDecodeError:
            pass
        return ""

    # Values that a broad regex will match but that are ALMOST NEVER real
    # secrets — dev placeholders, obvious test values, and public constants.
    # Filtered before recording a finding to cut down false positives from
    # `SECRET_PATTERNS`.
    _SECRET_PLACEHOLDERS = frozenset({
        "test", "testing", "example", "changeme", "changethis", "password",
        "yourpassword", "yourkey", "yourtoken", "yoursecret", "placeholder",
        "xxxxxxxx", "0000000000", "1234567890", "abcdefghij",
        "your-api-key", "your-secret-key", "your-access-token", "insertkey",
        "null", "undefined", "nan", "none",
    })

    @staticmethod
    def _looks_placeholder(value: str) -> bool:
        low = value.lower().strip()
        if low in JSAnalyzer._SECRET_PLACEHOLDERS:
            return True
        # Consecutive repeats like `AAAAAAAAA` or `xxxxxx`.
        if len(low) >= 8 and len(set(low)) <= 2:
            return True
        # `sk-` / `key-` followed by only zeros or asterisks.
        if any(low.endswith(s) for s in ("****", "0000", "____", "----")):
            return True
        return False

    def _regex_extract(self, content: str, source_url: str):
        """Run regex-based extraction for secrets and endpoints."""
        # Extract secrets
        for pattern, description, category, confidence in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in self._seen_values:
                    continue
                if len(value) < 8 or len(value) > 500:
                    continue
                if self._looks_placeholder(value):
                    continue
                self._seen_values.add(value)

                # Get context (surrounding chars)
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                context = content[start:end].replace("\n", " ").strip()

                self.findings.append(JSFinding(
                    category=category,
                    value=f"{description}: {value[:100]}",
                    source_url=source_url,
                    context=context[:200],
                    confidence=confidence,
                ))

        # Extract endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in self._seen_values:
                    continue
                if len(value) < 3 or len(value) > 300:
                    continue
                # Filter out common false positives
                if any(fp in value.lower() for fp in [".png", ".jpg", ".gif", ".svg", ".css", ".ico", "node_modules"]):
                    continue
                self._seen_values.add(value)
                self.findings.append(JSFinding(
                    category="endpoint",
                    value=value,
                    source_url=source_url,
                    confidence=0.7,
                ))

    def _extract_webpack_chunks(self, content: str) -> List[str]:
        """Find webpack chunk URLs from JS content."""
        chunks = []
        # webpackJsonp patterns
        for match in re.finditer(r'["\']([^"\']*(?:chunk|static/js)[^"\']*\.js)["\']', content):
            chunk_path = match.group(1)
            if chunk_path.startswith("http"):
                chunks.append(chunk_path)
            elif chunk_path.startswith("/"):
                chunks.append(self._resolve(chunk_path))
        # __webpack_require__ and dynamic import patterns
        for match in re.finditer(r'(?:__webpack_require__|import)\s*\(\s*["\']([^"\']+)["\']', content):
            path = match.group(1)
            if path.endswith(".js"):
                if path.startswith("/"):
                    chunks.append(self._resolve(path))
        return chunks

    def analyze(self, html: str = None, endpoints: List = None, max_files: int = 20) -> List[JSFinding]:
        """Run the full JS analysis pipeline."""
        js_urls = self.discover_js_files(html, endpoints)

        analyzed = 0
        all_chunk_urls: Set[str] = set()

        for js_url in js_urls[:max_files]:
            content = self._fetch(js_url)
            if not content or len(content) < 50:
                continue
            if "<html" in content[:200].lower():
                continue  # Skip HTML pages returned for 404s

            # P2-2: skip a bundle version already analyzed this process (same
            # content hash), regardless of URL — avoids re-parsing identical
            # main.js/vendor.js re-discovered on later crawls.
            import hashlib as _hl
            _bhash = _hl.sha256(content.encode("utf-8", "ignore")).hexdigest()
            if _bhash in _ANALYZED_BUNDLE_HASHES:
                logger.debug(f"[JSAnalyzer] bundle cache hit — skipping {js_url}")
                continue
            _ANALYZED_BUNDLE_HASHES.add(_bhash)

            analyzed += 1
            logger.info(f"[JSAnalyzer] Analyzing {js_url} ({len(content)} bytes)")

            # Run Kali tools if available
            tool_endpoints = self._run_linkfinder(js_url)
            for ep in tool_endpoints:
                if ep not in self._seen_values:
                    self._seen_values.add(ep)
                    self.findings.append(JSFinding(
                        category="endpoint", value=ep,
                        source_url=js_url, confidence=0.8,
                    ))

            tool_secrets = self._run_secretfinder(js_url)
            for desc, val in tool_secrets:
                if val not in self._seen_values:
                    self._seen_values.add(val)
                    self.findings.append(JSFinding(
                        category="secret", value=f"{desc}: {val[:100]}",
                        source_url=js_url, confidence=0.85,
                    ))

            # Regex extraction
            self._regex_extract(content, js_url)

            # Source map analysis
            source_maps = self._extract_source_maps(content, js_url)
            for map_url in source_maps[:3]:
                source_code = self._analyze_source_map(map_url)
                if source_code:
                    self._regex_extract(source_code, f"{map_url} (source)")

            # Discover webpack chunks
            chunks = self._extract_webpack_chunks(content)
            all_chunk_urls.update(chunks)

        # Analyze discovered chunks (second pass)
        remaining_budget = max_files - analyzed
        for chunk_url in list(all_chunk_urls)[:remaining_budget]:
            if chunk_url in [u for u in js_urls]:
                continue
            content = self._fetch(chunk_url)
            if not content or len(content) < 50 or "<html" in content[:200].lower():
                continue
            analyzed += 1
            self._regex_extract(content, chunk_url)

        logger.info(f"[JSAnalyzer] Analysis complete: {analyzed} files analyzed, "
                    f"{len(self.findings)} findings "
                    f"({len([f for f in self.findings if f.category == 'endpoint'])} endpoints, "
                    f"{len([f for f in self.findings if f.category in ('secret', 'api_key', 'token')])} secrets)")

        return self.findings

    def get_endpoints(self) -> List[str]:
        """Get discovered API endpoints."""
        return [f.value for f in self.findings if f.category == "endpoint"]

    def get_secrets(self) -> List[Dict]:
        """Get discovered secrets as vulnerability findings."""
        findings = []
        for f in self.findings:
            if f.category not in ("secret", "api_key", "token"):
                continue
            findings.append({
                "title": f"Exposed {f.category.replace('_', ' ').title()} in JavaScript: {f.value[:60]}",
                "type": "INFORMATION_DISCLOSURE",
                "severity": "HIGH" if f.confidence >= 0.85 else "MEDIUM",
                "confidence_score": f.confidence,
                "target": f.source_url,
                "location": f.source_url,
                "details": f"Found in JS bundle: {f.value}\nContext: {f.context}",
                "proof": f.context if f.context else f.value,
                "remediation": (
                    "Remove hardcoded secrets from client-side JavaScript. "
                    "Use environment variables and server-side configuration. "
                    "Rotate any exposed credentials immediately."
                ),
                "tool": "js_analyzer",
                "status": "CONFIRMED" if f.confidence >= 0.9 else "UNCONFIRMED",
                "cwe_id": "CWE-798" if f.category == "api_key" else "CWE-200",
            })
        return findings

    def get_source_map_findings(self) -> List[Dict]:
        """Report exposed source maps as findings."""
        findings = []
        for map_url in self.source_map_urls:
            findings.append({
                "title": f"Exposed Source Map: {map_url}",
                "type": "INFORMATION_DISCLOSURE",
                "severity": "MEDIUM",
                "confidence_score": 0.9,
                "target": map_url,
                "location": map_url,
                "details": (
                    "JavaScript source map is publicly accessible, exposing original source code, "
                    "file structure, variable names, and potentially sensitive logic."
                ),
                "remediation": "Remove source maps from production deployments or restrict access via server configuration.",
                "tool": "js_analyzer",
                "status": "CONFIRMED",
                "cwe_id": "CWE-540",
            })
        return findings
