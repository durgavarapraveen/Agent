"""
Target Profiler — HexStrike-Style Intelligent Target Analysis.

Fingerprints target type, technology stack, CMS, and attack surface
before any tools run. Feeds structured intelligence into the LLM Brain
prompt so it makes smarter tool and parameter decisions.

Inspired by HexStrike AI's IntelligentDecisionEngine + TargetProfile.
"""

import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════

class TargetType(str, Enum):
    """Classification of target for intelligent tool selection."""
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    NETWORK_HOST = "network_host"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"


class TechnologyStack(str, Enum):
    """Detected technology stack for parameter optimization."""
    # Web servers
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    # Languages / runtimes
    NODEJS = "nodejs"
    EXPRESS = "express"
    PHP = "php"
    PYTHON = "python"
    DJANGO = "django"
    FLASK = "flask"
    JAVA = "java"
    DOTNET = "dotnet"
    RUBY = "ruby"
    GO = "go"
    # CMS
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    # Frontend frameworks
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    JQUERY = "jquery"
    # Other
    GRAPHQL = "graphql"
    UNKNOWN = "unknown"


# ═══════════════════════════════════════════════
# TARGET PROFILE
# ═══════════════════════════════════════════════

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making."""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0
    waf_detected: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [t.value for t in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints[:20],
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score,
            "waf_detected": self.waf_detected,
        }

    def to_brain_context(self) -> str:
        """Format profile as a compact text block for the LLM Brain prompt."""
        tech_str = ", ".join(t.value for t in self.technologies if t != TechnologyStack.UNKNOWN) or "unknown"
        ports_str = ", ".join(str(p) for p in self.open_ports[:10]) or "not yet scanned"
        subs_str = ", ".join(self.subdomains[:5]) or "none discovered"
        endpoints_str = str(len(self.endpoints)) if self.endpoints else "0"
        headers_list = []
        for h in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
                   "X-Content-Type-Options", "X-XSS-Protection"):
            if h.lower() in {k.lower() for k in self.security_headers}:
                headers_list.append(f"[PRESENT] {h}")
            else:
                headers_list.append(f"[MISSING] {h}")
        headers_str = "; ".join(headers_list) if headers_list else "unknown"
        waf_str = self.waf_detected or "none detected"
        cms_str = self.cms_type or "none"

        # Build file extension recommendation
        ext_recommendation = _recommend_extensions(self.technologies)

        return (
            f"TARGET INTELLIGENCE (auto-profiled):\n"
            f"  Type: {self.target_type.value}\n"
            f"  Technologies: [{tech_str}]\n"
            f"  CMS: {cms_str}\n"
            f"  WAF: {waf_str}\n"
            f"  Open Ports: [{ports_str}]\n"
            f"  Subdomains: [{subs_str}] ({len(self.subdomains)} total)\n"
            f"  Endpoints discovered: {endpoints_str}\n"
            f"  Security Headers: {headers_str}\n"
            f"  Attack Surface Score: {self.attack_surface_score:.1f}/10\n"
            f"  Risk Level: {self.risk_level}\n"
            f"  Recommended file extensions for dir-bruteforce: {ext_recommendation}\n"
        )

    @property
    def has_php(self) -> bool:
        return TechnologyStack.PHP in self.technologies

    @property
    def has_dotnet(self) -> bool:
        return TechnologyStack.DOTNET in self.technologies

    @property
    def has_java(self) -> bool:
        return TechnologyStack.JAVA in self.technologies

    @property
    def has_nodejs(self) -> bool:
        return any(t in self.technologies for t in (
            TechnologyStack.NODEJS, TechnologyStack.EXPRESS))

    @property
    def has_python_web(self) -> bool:
        return any(t in self.technologies for t in (
            TechnologyStack.PYTHON, TechnologyStack.DJANGO, TechnologyStack.FLASK))

    @property
    def has_wordpress(self) -> bool:
        return TechnologyStack.WORDPRESS in self.technologies or self.cms_type == "WordPress"

    @property
    def has_spa(self) -> bool:
        return any(t in self.technologies for t in (
            TechnologyStack.REACT, TechnologyStack.ANGULAR, TechnologyStack.VUE))

    @property
    def is_api(self) -> bool:
        return self.target_type == TargetType.API_ENDPOINT


# ═══════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════

def _recommend_extensions(technologies: List[TechnologyStack]) -> str:
    """Return recommended file extensions for directory bruteforcing."""
    exts = {"html", "txt"}
    for tech in technologies:
        if tech in (TechnologyStack.PHP, TechnologyStack.WORDPRESS,
                    TechnologyStack.DRUPAL, TechnologyStack.JOOMLA):
            exts.update({"php", "php5", "phtml", "inc"})
        elif tech in (TechnologyStack.DOTNET, TechnologyStack.IIS):
            exts.update({"asp", "aspx", "ashx", "asmx", "config"})
        elif tech == TechnologyStack.JAVA:
            exts.update({"jsp", "jspa", "do", "action", "xml"})
        elif tech in (TechnologyStack.NODEJS, TechnologyStack.EXPRESS):
            exts.update({"js", "json", "map"})
        elif tech in (TechnologyStack.PYTHON, TechnologyStack.DJANGO, TechnologyStack.FLASK):
            exts.update({"py", "json", "yaml", "yml"})
        elif tech == TechnologyStack.RUBY:
            exts.update({"rb", "erb", "json", "yml"})
        elif tech in (TechnologyStack.REACT, TechnologyStack.ANGULAR, TechnologyStack.VUE):
            exts.update({"js", "json", "map", "jsx", "ts"})
    if not exts - {"html", "txt"}:
        exts.update({"php", "js", "json"})
    return ",".join(sorted(exts))


# ═══════════════════════════════════════════════
# TECHNOLOGY DETECTION SIGNATURES
# ═══════════════════════════════════════════════

HEADER_SIGNATURES: Dict[str, List[str]] = {
    TechnologyStack.APACHE.value: ["Apache", "apache"],
    TechnologyStack.NGINX.value: ["nginx", "Nginx"],
    TechnologyStack.IIS.value: ["Microsoft-IIS", "IIS"],
    TechnologyStack.PHP.value: ["PHP", "X-Powered-By: PHP"],
    TechnologyStack.EXPRESS.value: ["Express", "X-Powered-By: Express"],
    TechnologyStack.DJANGO.value: ["Django", "csrftoken"],
    TechnologyStack.FLASK.value: ["Flask", "Werkzeug"],
    TechnologyStack.JAVA.value: ["Tomcat", "JBoss", "WebLogic", "Jetty", "GlassFish"],
    TechnologyStack.DOTNET.value: ["ASP.NET", "X-AspNet-Version", "X-Powered-By: ASP.NET"],
    TechnologyStack.RUBY.value: ["Phusion Passenger", "X-Powered-By: Phusion"],
    TechnologyStack.GO.value: ["Go", "fasthttp"],
}

CONTENT_SIGNATURES: Dict[str, List[str]] = {
    TechnologyStack.WORDPRESS.value: ["wp-content", "wp-includes", "wp-json", "/wp-admin"],
    TechnologyStack.DRUPAL.value: ["Drupal", "drupal", "/sites/default", "Drupal.settings"],
    TechnologyStack.JOOMLA.value: ["Joomla", "joomla", "/administrator", "/components/com_"],
    TechnologyStack.REACT.value: ["React", "react", "__REACT_DEVTOOLS", "react-dom", "_reactRootContainer"],
    TechnologyStack.ANGULAR.value: ["Angular", "angular", "ng-version", "ng-app", "ng-controller"],
    TechnologyStack.VUE.value: ["Vue", "vue", "__VUE__", "vue-router", "v-app"],
    TechnologyStack.JQUERY.value: ["jQuery", "jquery"],
    TechnologyStack.GRAPHQL.value: ["graphql", "GraphQL", "__schema", "graphiql"],
}


# ═══════════════════════════════════════════════
# PROFILER
# ═══════════════════════════════════════════════

class TargetProfiler:
    """Build a TargetProfile from the target URL and shared context."""

    @classmethod
    def profile_target(cls, target: str, shared_context) -> TargetProfile:
        """Analyze target and create comprehensive profile.

        Uses data already in shared_context when available (tech fingerprinting,
        port scans, HTTP headers) so we avoid redundant network calls.
        Falls back to lightweight heuristics for anything missing.
        """
        profile = TargetProfile(target=target)

        # 1. Determine target type
        profile.target_type = cls._determine_target_type(target)

        # 2. Resolve IP
        profile.ip_addresses = cls._resolve_domain(target)

        # 3. Pull data from shared_context
        ctx = shared_context
        if hasattr(ctx, "get"):
            # Ports
            raw_ports = ctx.get("ports", []) or ctx.get("open_ports", []) or getattr(ctx, "ports", [])
            if raw_ports:
                profile.open_ports = [int(p) for p in raw_ports if str(p).isdigit()]

            # Subdomains
            raw_subs = ctx.get("subdomains", []) or ctx.get("discovered_subdomains", []) or getattr(ctx, "subdomains", [])
            if raw_subs:
                profile.subdomains = [
                    (s.name if hasattr(s, "name") else str(s)) for s in raw_subs
                ]

            # Endpoints
            raw_eps = ctx.get("endpoints", []) or getattr(ctx, "endpoints", [])
            if raw_eps:
                profile.endpoints = [
                    (e if isinstance(e, str) else e.get("url", str(e))) for e in raw_eps
                ]

            # Security headers from HTTP responses
            raw_headers = ctx.get("security_headers", {}) or ctx.get("response_headers", {})
            if raw_headers:
                profile.security_headers = dict(raw_headers)

            # WAF
            waf = ctx.get("waf_detected", None) or ctx.get("waf", None)
            if waf:
                profile.waf_detected = str(waf)

        # 4. Detect technologies from context + target patterns
        profile.technologies = cls._detect_technologies(target, ctx)

        # 5. Detect CMS
        profile.cms_type = cls._detect_cms(target, ctx, profile.technologies)

        # 6. Detect cloud provider
        profile.cloud_provider = cls._detect_cloud_provider(target)

        # 7. Calculate attack surface
        profile.attack_surface_score = cls._calculate_attack_surface(profile)
        profile.risk_level = cls._determine_risk_level(profile.attack_surface_score)
        profile.confidence_score = cls._calculate_confidence(profile)

        logger.info(
            f"TARGET_INTELLIGENCE: type={profile.target_type.value} "
            f"tech=[{','.join(t.value for t in profile.technologies)}] "
            f"cms={profile.cms_type} waf={profile.waf_detected} "
            f"risk={profile.risk_level} score={profile.attack_surface_score:.1f} "
            f"ports={len(profile.open_ports)} subs={len(profile.subdomains)} "
            f"endpoints={len(profile.endpoints)}"
        )

        return profile

    # ── Target Type Detection ──

    @staticmethod
    def _determine_target_type(target: str) -> TargetType:
        if not target:
            return TargetType.UNKNOWN

        # URL patterns
        if target.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(target)
            path = parsed.path.lower()
            if "/api/" in path or path.endswith("/api") or "/graphql" in path or "/v1/" in path or "/v2/" in path:
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        # IP address
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return TargetType.NETWORK_HOST

        # CIDR
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", target):
            return TargetType.NETWORK_HOST

        # Domain name
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            return TargetType.WEB_APPLICATION

        # Binary file
        if target.endswith((".exe", ".bin", ".elf", ".so", ".dll")):
            return TargetType.BINARY_FILE

        # Cloud
        cloud_patterns = ["amazonaws.com", "azure", "googleapis.com", "cloudfront.net"]
        if any(cp in target.lower() for cp in cloud_patterns):
            return TargetType.CLOUD_SERVICE

        return TargetType.UNKNOWN

    # ── IP Resolution ──

    @staticmethod
    def _resolve_domain(target: str) -> List[str]:
        try:
            hostname = target
            if target.startswith(("http://", "https://")):
                hostname = urllib.parse.urlparse(target).hostname
            if hostname:
                ip = socket.gethostbyname(hostname)
                return [ip]
        except Exception:
            pass
        return []

    # ── Technology Detection ──

    @classmethod
    def _detect_technologies(cls, target: str, ctx) -> List[TechnologyStack]:
        detected: List[TechnologyStack] = []

        # A. From shared_context stored technologies
        if hasattr(ctx, "get"):
            raw_tech = ctx.get("technologies", []) or ctx.get("detected_technologies", []) or getattr(ctx, "technologies", [])
            if raw_tech:
                for t in raw_tech:
                    t_str = str(t).lower().strip()
                    for stack in TechnologyStack:
                        if stack.value in t_str or t_str in stack.value:
                            if stack not in detected:
                                detected.append(stack)

        # B. From HTTP response headers in context
        if hasattr(ctx, "get"):
            headers = ctx.get("response_headers", {}) or ctx.get("security_headers", {})
            if isinstance(headers, dict):
                header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
                for tech_key, signatures in HEADER_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in header_text.lower():
                            stack = TechnologyStack(tech_key)
                            if stack not in detected:
                                detected.append(stack)

        # C. From HTML body content in context
        if hasattr(ctx, "get"):
            body_text = ctx.get("page_content", "") or ctx.get("html_content", "") or ""
            if body_text:
                for tech_key, signatures in CONTENT_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in body_text.lower():
                            stack = TechnologyStack(tech_key)
                            if stack not in detected:
                                detected.append(stack)

        # D. From target URL patterns
        target_lower = target.lower()
        url_hints = {
            TechnologyStack.WORDPRESS: ["wordpress", "wp-", "/wp-"],
            TechnologyStack.PHP: [".php"],
            TechnologyStack.DOTNET: [".asp", ".aspx"],
            TechnologyStack.JAVA: [".jsp", ".do", ".action"],
            TechnologyStack.NODEJS: [":3000", ":8000", ":9000"],
            TechnologyStack.GRAPHQL: ["/graphql", "/graphiql"],
        }
        for stack, patterns in url_hints.items():
            for p in patterns:
                if p in target_lower and stack not in detected:
                    detected.append(stack)

        if not detected:
            detected.append(TechnologyStack.UNKNOWN)

        return detected

    # ── CMS Detection ──

    @staticmethod
    def _detect_cms(target: str, ctx, technologies: List[TechnologyStack]) -> Optional[str]:
        if TechnologyStack.WORDPRESS in technologies:
            return "WordPress"
        if TechnologyStack.DRUPAL in technologies:
            return "Drupal"
        if TechnologyStack.JOOMLA in technologies:
            return "Joomla"

        # Check context
        if hasattr(ctx, "get"):
            cms = ctx.get("cms_type", None) or ctx.get("cms", None)
            if cms:
                return str(cms)

        return None

    # ── Cloud Provider Detection ──

    @staticmethod
    def _detect_cloud_provider(target: str) -> Optional[str]:
        t = target.lower()
        if "amazonaws.com" in t or "s3." in t:
            return "AWS"
        if "azure" in t or "blob.core.windows.net" in t:
            return "Azure"
        if "googleapis.com" in t or "appspot.com" in t:
            return "GCP"
        if "cloudfront.net" in t:
            return "AWS CloudFront"
        if "herokuapp.com" in t:
            return "Heroku"
        if "vercel.app" in t:
            return "Vercel"
        return None

    # ── Attack Surface Scoring ──

    @staticmethod
    def _calculate_attack_surface(profile: TargetProfile) -> float:
        score = 0.0

        type_scores = {
            TargetType.WEB_APPLICATION: 7.0,
            TargetType.API_ENDPOINT: 6.5,
            TargetType.NETWORK_HOST: 8.0,
            TargetType.CLOUD_SERVICE: 5.0,
            TargetType.BINARY_FILE: 4.0,
        }
        score += type_scores.get(profile.target_type, 3.0)

        # Technologies increase attack surface
        real_tech = [t for t in profile.technologies if t != TechnologyStack.UNKNOWN]
        score += min(len(real_tech) * 0.3, 1.5)

        # Open ports
        score += min(len(profile.open_ports) * 0.2, 1.0)

        # Subdomains
        score += min(len(profile.subdomains) * 0.1, 1.0)

        # Endpoints
        score += min(len(profile.endpoints) * 0.05, 0.5)

        # CMS adds attack surface
        if profile.cms_type:
            score += 1.0

        # Missing security headers increase risk
        important_headers = {"x-frame-options", "content-security-policy",
                             "strict-transport-security", "x-content-type-options"}
        present = {k.lower() for k in profile.security_headers}
        missing = important_headers - present
        score += min(len(missing) * 0.2, 0.8)

        return min(score, 10.0)

    @staticmethod
    def _determine_risk_level(score: float) -> str:
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        return "minimal"

    @staticmethod
    def _calculate_confidence(profile: TargetProfile) -> float:
        confidence = 0.4
        if profile.ip_addresses:
            confidence += 0.1
        real_tech = [t for t in profile.technologies if t != TechnologyStack.UNKNOWN]
        if real_tech:
            confidence += 0.2
        if profile.cms_type:
            confidence += 0.1
        if profile.target_type != TargetType.UNKNOWN:
            confidence += 0.1
        if profile.open_ports:
            confidence += 0.05
        if profile.security_headers:
            confidence += 0.05
        return min(confidence, 1.0)
