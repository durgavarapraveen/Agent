"""
Tool Effectiveness Engine — HexStrike-Style Intelligence Layer.

Provides tool effectiveness scoring, curated attack patterns, and
Brain-prompt recommendations. The LLM Brain sees these as advisory
intelligence — it can follow, adapt, or override them.

Inspired by HexStrike AI's IntelligentDecisionEngine + AttackChain.
"""

import logging
from typing import Any, Dict, List, Optional

from core.intelligence.target_profiler import TargetProfile, TargetType, TechnologyStack

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════
# TOOL EFFECTIVENESS MATRIX
# ═══════════════════════════════════════════════
# Scores 0.0–1.0 representing how effective a tool is for a given target type.

EFFECTIVENESS_MATRIX: Dict[str, Dict[str, float]] = {
    TargetType.WEB_APPLICATION.value: {
        "nmap": 0.80,
        "httpx": 0.85,
        "whatweb": 0.82,
        "gobuster": 0.90,
        "feroxbuster": 0.85,
        "ffuf": 0.90,
        "dirsearch": 0.87,
        "dirb": 0.75,
        "nikto": 0.85,
        "nuclei": 0.95,
        "sqlmap": 0.90,
        "dalfox": 0.93,
        "katana": 0.88,
        "gau": 0.82,
        "waybackurls": 0.80,
        "arjun": 0.90,
        "paramspider": 0.85,
        "wpscan": 0.95,
        "wafw00f": 0.78,
        "sslscan": 0.70,
        "sslyze": 0.70,
        "openssl": 0.65,
        "curl": 0.60,
        "subfinder": 0.75,
        "amass": 0.70,
        "theharvester": 0.72,
    },
    TargetType.API_ENDPOINT.value: {
        "httpx": 0.90,
        "nuclei": 0.90,
        "arjun": 0.95,
        "paramspider": 0.88,
        "ffuf": 0.85,
        "katana": 0.85,
        "curl": 0.80,
        "sqlmap": 0.85,
        "dalfox": 0.80,
        "nmap": 0.65,
        "nikto": 0.70,
        "gobuster": 0.75,
        "wafw00f": 0.72,
    },
    TargetType.NETWORK_HOST.value: {
        "nmap": 0.95,
        "masscan": 0.92,
        "subfinder": 0.60,
        "amass": 0.70,
        "dig": 0.75,
        "whois": 0.65,
        "sslscan": 0.75,
        "openssl": 0.70,
        "theharvester": 0.60,
        "curl": 0.55,
    },
    TargetType.CLOUD_SERVICE.value: {
        "nuclei": 0.85,
        "httpx": 0.80,
        "nmap": 0.70,
        "subfinder": 0.75,
        "curl": 0.65,
        "sslscan": 0.70,
    },
}


# ═══════════════════════════════════════════════
# ATTACK PATTERNS — Curated Tool Pipelines
# ═══════════════════════════════════════════════
# Priority-ordered tool sequences for specific scanning scenarios.

ATTACK_PATTERNS: Dict[str, List[Dict[str, Any]]] = {
    "web_reconnaissance": [
        {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True},
         "description": "HTTP probing + technology detection"},
        {"tool": "whatweb", "priority": 2, "params": {},
         "description": "Web technology fingerprinting"},
        {"tool": "wafw00f", "priority": 3, "params": {},
         "description": "WAF detection"},
        {"tool": "katana", "priority": 4, "params": {"depth": 3, "js_crawl": True},
         "description": "JS-aware web crawling"},
        {"tool": "gau", "priority": 5, "params": {"include_subs": True},
         "description": "Historical URL discovery from web archives"},
        {"tool": "waybackurls", "priority": 6, "params": {},
         "description": "Wayback Machine URL extraction"},
        {"tool": "gobuster", "priority": 7, "params": {"mode": "dir"},
         "description": "Directory and file bruteforce"},
        {"tool": "nuclei", "priority": 8, "params": {"severity": "critical,high"},
         "description": "Template-based vulnerability scanning"},
    ],
    "api_testing": [
        {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True},
         "description": "API endpoint probing"},
        {"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": True},
         "description": "HTTP parameter discovery"},
        {"tool": "paramspider", "priority": 3, "params": {"level": 2},
         "description": "Parameter mining from archives"},
        {"tool": "ffuf", "priority": 4,
         "params": {"match_codes": "200,201,204,301,401,403"},
         "description": "Fuzzing API paths and parameters"},
        {"tool": "nuclei", "priority": 5,
         "params": {"tags": "api,graphql,jwt", "severity": "high,critical"},
         "description": "API-specific vulnerability templates"},
        {"tool": "sqlmap", "priority": 6, "params": {"batch": True, "level": 2},
         "description": "SQL injection against API parameters"},
    ],
    "bug_bounty_recon": [
        {"tool": "subfinder", "priority": 1, "params": {"silent": True, "all_sources": True},
         "description": "Passive subdomain discovery"},
        {"tool": "amass", "priority": 2, "params": {"mode": "enum", "passive": True},
         "description": "Subdomain enumeration"},
        {"tool": "httpx", "priority": 3,
         "params": {"probe": True, "tech_detect": True, "status_code": True},
         "description": "Subdomain probing + tech fingerprinting"},
        {"tool": "katana", "priority": 4,
         "params": {"depth": 3, "js_crawl": True, "form_extraction": True},
         "description": "Deep JS-aware crawling"},
        {"tool": "gau", "priority": 5, "params": {"include_subs": True},
         "description": "Archive URL collection"},
        {"tool": "waybackurls", "priority": 6, "params": {},
         "description": "Wayback URL extraction"},
        {"tool": "paramspider", "priority": 7, "params": {"level": 2},
         "description": "Parameter discovery from archives"},
        {"tool": "arjun", "priority": 8, "params": {"method": "GET,POST", "stable": True},
         "description": "Live parameter bruteforcing"},
    ],
    "vulnerability_assessment": [
        {"tool": "nuclei", "priority": 1,
         "params": {"severity": "critical,high,medium", "update": True},
         "description": "Comprehensive template scanning"},
        {"tool": "nikto", "priority": 2, "params": {"comprehensive": True},
         "description": "Web server misconfiguration scanner"},
        {"tool": "dalfox", "priority": 3,
         "params": {"mining_dom": True, "mining_dict": True},
         "description": "XSS detection with DOM mining"},
        {"tool": "sqlmap", "priority": 4, "params": {"crawl": 2, "batch": True},
         "description": "Automated SQL injection testing"},
    ],
    "network_discovery": [
        {"tool": "nmap", "priority": 1,
         "params": {"scan_type": "-sV -sC", "timing": "T4"},
         "description": "Service version detection + default scripts"},
        {"tool": "masscan", "priority": 2,
         "params": {"ports": "1-10000", "rate": 1000},
         "description": "High-speed port scanning"},
    ],
    "ssl_tls_audit": [
        {"tool": "sslscan", "priority": 1, "params": {},
         "description": "SSL/TLS protocol and cipher analysis"},
        {"tool": "sslyze", "priority": 2, "params": {},
         "description": "SSL configuration analysis"},
        {"tool": "openssl", "priority": 3, "params": {},
         "description": "Certificate chain inspection"},
    ],
    "osint_reconnaissance": [
        {"tool": "subfinder", "priority": 1, "params": {},
         "description": "Passive subdomain discovery"},
        {"tool": "amass", "priority": 2, "params": {"passive": True},
         "description": "Subdomain enumeration via OSINT"},
        {"tool": "theharvester", "priority": 3, "params": {},
         "description": "Email and domain OSINT gathering"},
        {"tool": "whois", "priority": 4, "params": {},
         "description": "Domain registration lookup"},
        {"tool": "dig", "priority": 5, "params": {"type": "ANY"},
         "description": "DNS record enumeration"},
    ],
}


# ═══════════════════════════════════════════════
# PHASE → PATTERN MAPPING
# ═══════════════════════════════════════════════

PHASE_PATTERN_MAP: Dict[str, str] = {
    "recon": "web_reconnaissance",
    "reconnaissance": "web_reconnaissance",
    "osint": "osint_reconnaissance",
    "osint_reconnaissance": "osint_reconnaissance",
    "deep_reconnaissance": "bug_bounty_recon",
    "analyze": "vulnerability_assessment",
    "vulnerability_analysis": "vulnerability_assessment",
    "exploit": "vulnerability_assessment",
    "api": "api_testing",
    "network": "network_discovery",
    "ssl": "ssl_tls_audit",
}


# ═══════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════

class ToolEffectivenessEngine:
    """Advisory intelligence layer for the LLM Brain."""

    @classmethod
    def get_tool_scores(cls, profile: TargetProfile) -> Dict[str, float]:
        """Get effectiveness scores for all tools given the target type."""
        target_type = profile.target_type.value
        scores = dict(EFFECTIVENESS_MATRIX.get(target_type, {}))

        # Boost CMS-specific tools
        if profile.has_wordpress:
            scores["wpscan"] = min(scores.get("wpscan", 0.5) + 0.2, 1.0)
            scores["nuclei"] = min(scores.get("nuclei", 0.5) + 0.05, 1.0)

        # Boost SPA-aware tools for Angular/React/Vue
        if profile.has_spa:
            scores["katana"] = min(scores.get("katana", 0.5) + 0.1, 1.0)

        # Boost API parameter tools for API targets
        if profile.is_api:
            for t in ("arjun", "paramspider", "ffuf"):
                scores[t] = min(scores.get(t, 0.5) + 0.1, 1.0)

        return scores

    @classmethod
    def recommend_tools(
        cls,
        profile: TargetProfile,
        phase: str = "recon",
        top_k: int = 8,
        exclude: Optional[set] = None,
    ) -> List[Dict[str, Any]]:
        """Return top-k tool recommendations ranked by effectiveness."""
        scores = cls.get_tool_scores(profile)
        exclude = exclude or set()

        ranked = sorted(
            [(tool, score) for tool, score in scores.items() if tool not in exclude],
            key=lambda x: x[1],
            reverse=True,
        )[:top_k]

        recommendations = []
        for rank, (tool, score) in enumerate(ranked, 1):
            param_hint = cls._get_parameter_hint(tool, profile)
            recommendations.append({
                "rank": rank,
                "tool": tool,
                "effectiveness": round(score, 2),
                "param_hint": param_hint,
            })

        return recommendations

    @classmethod
    def recommend_pattern(cls, profile: TargetProfile, phase: str = "recon") -> Optional[Dict[str, Any]]:
        """Select the best attack pattern for the profile and phase."""
        phase_clean = phase.lower().strip()

        # Map phase to pattern
        pattern_name = PHASE_PATTERN_MAP.get(phase_clean)

        # Auto-detect best pattern from target type if no direct phase match
        if not pattern_name:
            if profile.is_api:
                pattern_name = "api_testing"
            elif profile.target_type == TargetType.NETWORK_HOST:
                pattern_name = "network_discovery"
            else:
                pattern_name = "web_reconnaissance"

        pattern = ATTACK_PATTERNS.get(pattern_name)
        if not pattern:
            return None

        return {
            "pattern_name": pattern_name,
            "steps": pattern,
            "total_tools": len(pattern),
        }

    @classmethod
    def get_brain_recommendations(cls, profile: TargetProfile, phase: str = "recon") -> str:
        """Format tool intelligence as a compact text block for the Brain prompt.

        This is the key integration point — the output is injected directly into
        the LLM's prompt so it can make informed tool choices.
        """
        if profile is None:
            return ""

        lines = ["\nTOOL INTELLIGENCE (HexStrike Engine):"]

        # Tool recommendations
        recs = cls.recommend_tools(profile, phase, top_k=8)
        if recs:
            lines.append("  Recommended tools by effectiveness:")
            for r in recs:
                hint = f" - Use: {r['param_hint']}" if r["param_hint"] else ""
                lines.append(f"    {r['rank']}. {r['tool']} ({r['effectiveness']:.2f}){hint}")

        # Attack pattern
        pattern = cls.recommend_pattern(profile, phase)
        if pattern:
            step_names = " -> ".join(s["tool"] for s in pattern["steps"])
            lines.append(f"  Recommended pattern: {pattern['pattern_name']}")
            lines.append(f"    {step_names}")

        # Technology-specific guidance
        guidance = cls._get_tech_guidance(profile)
        if guidance:
            lines.append("  Tech-specific guidance:")
            for g in guidance:
                lines.append(f"    * {g}")

        return "\n".join(lines)

    # ── Parameter Hints ──

    @classmethod
    def _get_parameter_hint(cls, tool: str, profile: TargetProfile) -> str:
        """Short hint about optimal parameters for the Brain."""
        ext = _recommend_extensions_short(profile.technologies)

        hints = {
            "nmap": "-sV -sC -p 80,443,8080,8443" if profile.target_type == TargetType.WEB_APPLICATION else "-sS -O --top-ports 1000",
            "gobuster": f"-x {ext}" if ext else "",
            "feroxbuster": f"-x {ext}" if ext else "",
            "ffuf": "-mc 200,204,301,302,307,401,403 -t 40",
            "dirsearch": f"-e {ext}" if ext else "",
            "nuclei": cls._nuclei_hint(profile),
            "sqlmap": cls._sqlmap_hint(profile),
            "katana": "-d 3 -jc" if profile.has_spa else "-d 2",
            "nikto": "-Tuning 1 2 3 4 5 6 7 8 9 0",
            "httpx": "-tech-detect -cdn -follow-redirects -json",
            "wpscan": "--enumerate vp,vt,u" if profile.has_wordpress else "",
            "dalfox": "--mining-dom --mining-dict",
            "arjun": "-m GET,POST --stable",
            "wafw00f": "",
        }
        return hints.get(tool, "")

    @classmethod
    def _nuclei_hint(cls, profile: TargetProfile) -> str:
        parts = ["--severity critical,high"]
        tags = []
        if profile.has_wordpress:
            tags.append("wordpress")
        if profile.is_api:
            tags.extend(["api", "graphql", "jwt"])
        if profile.has_php:
            tags.append("php")
        if profile.has_java:
            tags.append("java")
        if tags:
            parts.append(f"--tags {','.join(tags)}")
        return " ".join(parts)

    @classmethod
    def _sqlmap_hint(cls, profile: TargetProfile) -> str:
        if profile.has_php:
            return "--dbms=mysql --batch --level 2"
        if profile.has_dotnet:
            return "--dbms=mssql --batch --level 2"
        if profile.has_java:
            return "--dbms=oracle --batch --level 2"
        return "--batch --level 2"

    # ── Tech-Specific Guidance ──

    @classmethod
    def _get_tech_guidance(cls, profile: TargetProfile) -> List[str]:
        guidance = []
        if profile.has_wordpress:
            guidance.append("WordPress detected - prioritize wpscan with --enumerate vp,vt,u")
        if profile.has_spa:
            spas = [t.value for t in profile.technologies
                    if t in (TechnologyStack.REACT, TechnologyStack.ANGULAR, TechnologyStack.VUE)]
            guidance.append(f"SPA framework ({', '.join(spas)}) - use katana with JS crawling (-jc)")
        if profile.has_php:
            guidance.append("PHP detected - test for LFI/RFI, use sqlmap with --dbms=mysql")
        if profile.has_nodejs:
            guidance.append("Node.js/Express - test for prototype pollution, SSRF, NoSQL injection")
        if profile.is_api:
            guidance.append("API endpoint - prioritize arjun + paramspider for parameter discovery")
        if TechnologyStack.GRAPHQL in profile.technologies:
            guidance.append("GraphQL detected - test for introspection, batch queries, injection")
        if profile.waf_detected:
            guidance.append(f"WAF detected ({profile.waf_detected}) - use tamper scripts, slow scan rate")
        if not profile.security_headers.get("Content-Security-Policy") and not any(
            k.lower() == "content-security-policy" for k in profile.security_headers
        ):
            guidance.append("Missing CSP header - XSS exploitation more likely to succeed")
        return guidance


def _recommend_extensions_short(technologies: List[TechnologyStack]) -> str:
    """Compact extension list for parameter hints."""
    exts = set()
    for tech in technologies:
        if tech in (TechnologyStack.PHP, TechnologyStack.WORDPRESS,
                    TechnologyStack.DRUPAL, TechnologyStack.JOOMLA):
            exts.update({"php", "html", "txt"})
        elif tech in (TechnologyStack.DOTNET, TechnologyStack.IIS):
            exts.update({"asp", "aspx", "html", "txt"})
        elif tech == TechnologyStack.JAVA:
            exts.update({"jsp", "html", "txt", "xml"})
        elif tech in (TechnologyStack.NODEJS, TechnologyStack.EXPRESS):
            exts.update({"js", "json", "html"})
        elif tech in (TechnologyStack.PYTHON, TechnologyStack.DJANGO, TechnologyStack.FLASK):
            exts.update({"py", "json", "html"})
        elif tech in (TechnologyStack.REACT, TechnologyStack.ANGULAR, TechnologyStack.VUE):
            exts.update({"js", "json", "html", "map"})
    if not exts:
        exts = {"php", "html", "js", "txt"}
    return ",".join(sorted(exts))
