"""
Abstract Tool Invocation and Adapter layer.
Decouples LLM planning from raw command line syntax.
Python deterministic code constructs commands strictly from structured parameters.

Enhanced with HexStrike-style stack-aware parameter optimization:
When a TargetProfile is provided, adapters generate smarter CLI flags
based on detected technology stack, CMS, and target type.
"""

import json
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from core.common.exceptions import ToolValidationError

logger = logging.getLogger(__name__)


class ToolInvocation(BaseModel):
    """Abstract model representing a structured tool call proposed by the planner"""
    tool: str
    operation: str
    params: Dict[str, Any] = Field(default_factory=dict)
    target: Optional[str] = None


class NmapAdapter:
    @staticmethod
    def port_scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        ports = params.get("ports") or params.get("port")
        service_detection = params.get("service_detection", True)
        os_detection = params.get("os_detection", False)
        timing = params.get("timing", "T4")

        args = [f"-{timing}"]

        if profile:
            from core.intelligence.target_profiler import TargetType
            if profile.target_type == TargetType.WEB_APPLICATION:
                # Web-focused scan: service detection + default scripts + common web ports
                args = [f"-{timing}", "-sV", "-sC"]
                if not ports:
                    ports = "80,443,8080,8443,8000,8888,3000,9000"
            elif profile.target_type == TargetType.NETWORK_HOST:
                # Network-focused scan: SYN scan + OS detection + top 1000 ports
                args = [f"-{timing}", "-sS", "-O", "--top-ports", "1000"]
                service_detection = True
            elif profile.target_type == TargetType.API_ENDPOINT:
                args = [f"-{timing}", "-sV"]
                if not ports:
                    ports = "80,443,8080,8443,3000,5000,8000"
            # If WAF detected, slow down
            if profile.waf_detected:
                timing_idx = args[0] if args[0].startswith("-T") else "-T4"
                args[0] = "-T2"  # Stealth timing
                args.append("--max-retries 2")
        else:
            if service_detection:
                args.append("-sV")
            if os_detection:
                args.append("-O")

        if ports:
            args.append(f"-p {ports}")
        # Standardize structured XML/JSON output format
        args.append("-oX -")
        args.append(target)
        return {"command": f"nmap {' '.join(args)}"}


class SubfinderAdapter:
    @staticmethod
    def subdomain_discovery(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        from core.intelligence.subdomain_enum import extract_apex_domain
        apex = extract_apex_domain(clean_target)
        # Use apex domain if available to discover all sibling subdomains
        query_domain = apex if apex else clean_target
        flags = [f"-d {query_domain}", "-oJ"]
        # HexStrike-style: use all sources for thorough discovery
        if params.get("all_sources") or params.get("silent"):
            flags.append("-all")
        return {"command": f"subfinder {' '.join(flags)}"}


class AmassAdapter:
    @staticmethod
    def passive_enum(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        from core.intelligence.subdomain_enum import extract_apex_domain
        apex = extract_apex_domain(clean_target)
        query_domain = apex if apex else clean_target
        return {"command": f"amass enum -passive -d {query_domain}"}


class OpenSSLAdapter:
    @staticmethod
    def inspect_cert(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        port = params.get("port", 443)
        return {"command": f"openssl s_client -connect {target}:{port}"}

    @staticmethod
    def check_cipher(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        port = params.get("port", 443)
        cipher = params.get("cipher")
        if cipher:
            return {"command": f"openssl s_client -cipher {cipher} -connect {target}:{port}"}
        return {"command": f"openssl s_client -connect {target}:{port}"}


class HTTPXAdapter:
    @staticmethod
    def technology_detection(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        path = params.get("path", "")
        if path:
            target = target.rstrip("/") + "/" + path.lstrip("/")
        flags = ["-u", target, "-status-code", "-title", "-tech-detect", "-json"]
        # HexStrike enhancement: CDN detection and redirects
        if profile:
            flags.extend(["-cdn", "-follow-redirects"])
        return {"command": f"httpx {' '.join(flags)}"}

    @staticmethod
    def probe(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        path = params.get("path", "")
        if path:
            target = target.rstrip("/") + "/" + path.lstrip("/")
        flags = ["-u", target, "-status-code", "-title", "-tech-detect", "-json"]
        if profile:
            flags.extend(["-cdn", "-follow-redirects"])
        return {"command": f"httpx {' '.join(flags)}"}


class SSLScanAdapter:
    @staticmethod
    def ssl_scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        mode = str(params.get("mode") or params.get("subtask") or params.get("check") or "").lower()
        if mode == "protocols":
            return {"command": f"sslscan --no-ciphersuites --no-fallback --no-heartbleed {target}"}
        elif mode == "ciphers":
            return {"command": f"sslscan --no-failed --no-renegotiation {target}"}
        elif mode == "cert":
            return {"command": f"sslscan --no-ciphersuites --no-preferred {target}"}
        return {"command": f"sslscan --fast --no-failed {target}"}


class WhatWebAdapter:
    @staticmethod
    def tech_detect(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        aggression = params.get("aggression")
        if aggression:
            return {"command": f"whatweb -a {aggression} {target}"}
        return {"command": f"whatweb {target}"}


class GobusterAdapter:
    """Stack-aware directory bruteforcing with smart wordlists."""
    @staticmethod
    def dir_scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        from core.tools.smart_wordlists import SmartWordlistManager
        from core.exploitation.waf_evasion import WAFEvasionManager

        default_wl = SmartWordlistManager.get_wordlist_for_profile(profile)
        w = params.get("wordlist", default_wl)
        flags = [f"dir -u {target} -w {w}"]

        # Stack-aware extension selection
        if profile:
            exts = _get_extensions_for_profile(profile)
            if exts:
                flags.append(f"-x {exts}")
            flags.append("-t 30")
            flags.append("--status-codes 200,204,301,302,307,401,403")

            if profile.waf_detected:
                bypass_headers = WAFEvasionManager.get_403_bypass_headers(target)
                for hk, hv in list(bypass_headers.items())[:2]:
                    flags.append(f"-H '{hk}: {hv}'")
        else:
            exts = params.get("extensions")
            if exts:
                flags.append(f"-x {exts}")

        return {"command": f"gobuster {' '.join(flags)}"}


class FeroxbusterAdapter:
    """Stack-aware recursive directory discovery."""
    @staticmethod
    def scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        from core.tools.smart_wordlists import SmartWordlistManager
        default_wl = SmartWordlistManager.get_wordlist_for_profile(profile)
        w = params.get("wordlist", default_wl)
        flags = [f"-u {target}", f"-w {w}"]

        if profile:
            exts = _get_extensions_for_profile(profile)
            if exts:
                flags.append(f"-x {exts}")
            flags.append("--threads 30")
            flags.append("--depth 2")
            flags.append("--status-codes 200,204,301,302,307,401,403")
        return {"command": f"feroxbuster {' '.join(flags)}"}


class FFufAdapter:
    """Stack-aware fuzzer with tailored wordlists."""
    @staticmethod
    def fuzz(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        from core.tools.smart_wordlists import SmartWordlistManager
        default_wl = SmartWordlistManager.get_wordlist_for_profile(profile)
        w = params.get("wordlist", default_wl)
        flags = [f"-u {target}", f"-w {w}"]

        if profile:
            match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
            flags.append(f"-mc {match_codes}")
            flags.append("-t 40")

            if profile.is_api:
                flags.append("-H 'Content-Type: application/json'")
            if profile.waf_detected:
                flags.append("-H 'X-Forwarded-For: 127.0.0.1'")
        return {"command": f"ffuf {' '.join(flags)}"}


class NucleiAdapter:
    """Stack-aware template vulnerability scanner."""
    @staticmethod
    def scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        flags = [f"-u {target}"]

        # Expert mode: cover every severity (low+info flag chain-attacks and
        # information disclosure the LLM can pivot on) and every relevant tag
        # group so nothing is skipped for speed.
        severity = params.get("severity", "info,low,medium,high,critical")
        flags.append(f"--severity {severity}")

        if profile:
            from core.intelligence.target_profiler import TechnologyStack
            # Broad default tag set (never miss default-login/misconfig/exposure)
            tags = ["cve", "misconfig", "exposure", "tech", "default-login", "takeover"]
            if profile.has_wordpress:
                tags.append("wordpress")
            if profile.is_api:
                tags.extend(["api", "graphql", "jwt"])
            if profile.has_php:
                tags.append("php")
            if profile.has_java:
                tags.append("java")
            if TechnologyStack.ANGULAR in profile.technologies:
                tags.append("angular")
            if TechnologyStack.REACT in profile.technologies:
                tags.append("react")

            custom_tags = params.get("tags", "")
            if custom_tags:
                tags.extend(custom_tags.split(","))
            flags.append(f"--tags {','.join(sorted(set(tags)))}")

            # WAF bypass — throttle but never skip
            if profile.waf_detected:
                flags.append("--rate-limit 5")
                flags.append("--bulk-size 5")
                flags.append("-H 'X-Forwarded-For: 127.0.0.1'")
        else:
            tags = params.get("tags", "cve,misconfig,exposure,tech,default-login,takeover")
            flags.append(f"--tags {tags}")

        # Structured output so the parser can extract every match.
        flags.append("-jsonl -silent")

        return {"command": f"nuclei {' '.join(flags)}"}


class SqlmapAdapter:
    """Stack-aware SQL injection scanner with dynamic WAF bypass tampers."""
    @staticmethod
    def scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        from core.exploitation.waf_evasion import WAFEvasionManager
        flags = [f"-u {target}", "--batch"]

        if profile:
            # DBMS detection from technology stack (HexStrike pattern)
            if profile.has_php:
                flags.append("--dbms=mysql")
            elif profile.has_dotnet:
                flags.append("--dbms=mssql")
            elif profile.has_java:
                flags.append("--dbms=oracle")
            elif profile.has_python_web:
                flags.append("--dbms=postgresql")

            # Expert defaults: maximum coverage. Expert would rather burn 10 min
            # per URL than miss a blind time-based SQLi. All techniques (BEUSTQ),
            # highest level (5) and risk (3), random UA to defeat trivial rate
            # limits, small delay to be polite.
            level = params.get("level", 5)
            risk = params.get("risk", 3)
            technique = params.get("technique", "BEUSTQ")
            flags.append(f"--level {level}")
            flags.append(f"--risk {risk}")
            flags.append(f"--technique={technique}")
            flags.append("--random-agent")
            flags.append("--threads=4")

            crawl = params.get("crawl")
            if crawl:
                flags.append(f"--crawl={crawl}")

            # WAF bypass
            if profile.waf_detected:
                tampers = WAFEvasionManager.get_sqlmap_tamper_scripts()
                flags.append(f"--tamper={tampers}")
                flags.append("--delay=1")
        else:
            flags.extend(["--level 5", "--risk 3", "--technique=BEUSTQ",
                          "--random-agent", "--threads=4"])
        return {"command": f"sqlmap {' '.join(flags)}"}


class KatanaAdapter:
    """Stack-aware web crawler."""
    @staticmethod
    def crawl(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        flags = [f"-u {target}"]

        if profile:
            # SPA targets need JS crawling (HexStrike pattern)
            if profile.has_spa:
                flags.append("-d 3")
                flags.append("-jc")  # JS crawl
                flags.append("-aff")  # Automatic form filling
            else:
                depth = params.get("depth", 2)
                flags.append(f"-d {depth}")

            if params.get("form_extraction") or params.get("js_crawl"):
                if "-jc" not in flags:
                    flags.append("-jc")
        else:
            depth = params.get("depth", 2)
            flags.append(f"-d {depth}")

        return {"command": f"katana {' '.join(flags)}"}


class DalfoxAdapter:
    """Stack-aware XSS scanner."""
    @staticmethod
    def scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        flags = [f"url {target}"]

        if profile:
            # DOM mining for SPA targets
            if profile.has_spa or params.get("mining_dom"):
                flags.append("--mining-dom")
            if params.get("mining_dict"):
                flags.append("--mining-dict")
            # WAF bypass mode
            if profile.waf_detected:
                flags.append("--waf-evasion")
        return {"command": f"dalfox {' '.join(flags)}"}


class ArjunAdapter:
    """Stack-aware parameter discovery."""
    @staticmethod
    def discover(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        flags = [f"-u {target}"]

        method = params.get("method", "GET,POST")
        flags.append(f"-m {method}")

        if params.get("stable"):
            flags.append("--stable")

        return {"command": f"arjun {' '.join(flags)}"}


class WPScanAdapter:
    """WordPress-specific scanner with full enumeration."""
    @staticmethod
    def scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        flags = [f"--url {target}"]

        if profile and profile.has_wordpress:
            # Full WordPress enumeration (HexStrike pattern)
            flags.append("--enumerate vp,vt,u")
            flags.append("--plugins-detection aggressive")
        return {"command": f"wpscan {' '.join(flags)}"}


class DirsearchAdapter:
    """Stack-aware directory scanner."""
    @staticmethod
    def scan(target: str, params: Dict[str, Any], profile=None) -> Dict[str, Any]:
        flags = [f"-u {target}"]

        if profile:
            exts = _get_extensions_for_profile(profile)
            if exts:
                flags.append(f"-e {exts}")
            flags.append("-t 30")

        return {"command": f"dirsearch {' '.join(flags)}"}


# ═══════════════════════════════════════════════
# HELPER: Get file extensions from profile
# ═══════════════════════════════════════════════

def _get_extensions_for_profile(profile) -> str:
    """Return comma-separated file extensions based on detected tech stack."""
    if not profile or not hasattr(profile, "technologies"):
        return ""
    from core.intelligence.target_profiler import TechnologyStack
    exts = set()
    for tech in profile.technologies:
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


# ═══════════════════════════════════════════════
# MAIN ADAPTER
# ═══════════════════════════════════════════════

class ToolAdapter:
    """Translates abstract tool operations into concrete CLI command arguments or parameters.
    
    Enhanced with HexStrike-style stack-aware parameter optimization: when a TargetProfile
    is passed, each adapter tailors CLI flags to the detected technology stack.
    """

    FORBIDDEN_TOOLS = {"bash", "sh", "cmd", "powershell", "zsh"}

    @classmethod
    def adapt(cls, invocation: ToolInvocation, profile=None) -> Dict[str, Any]:
        tool = invocation.tool.lower().strip()
        op = invocation.operation.lower().strip()
        params = invocation.params

        if tool in cls.FORBIDDEN_TOOLS:
            raise ToolValidationError(
                f"Direct execution of generic shell tool '{tool}' is forbidden. "
                "Use structured domain tools (e.g., nmap, subfinder, httpx)."
            )

        # Helper: extract target or return error
        target = (
            invocation.target
            or params.get("target")
            or params.get("url")
            or params.get("domain")
            or params.get("host")
            or ""
        )

        # Domain tool adapters (stack-aware)
        if tool == "nmap":
            if not target:
                raise ToolValidationError("Nmap requires a valid 'target' parameter")
            return NmapAdapter.port_scan(target, params, profile)

        elif tool == "subfinder":
            if not target:
                raise ToolValidationError("Subfinder requires a valid 'target' (domain) parameter")
            return SubfinderAdapter.subdomain_discovery(target, params, profile)

        elif tool == "amass":
            if not target:
                raise ToolValidationError("Amass requires a valid 'target' (domain) parameter")
            return AmassAdapter.passive_enum(target, params, profile)

        elif tool == "openssl":
            if not target:
                raise ToolValidationError("OpenSSL requires a valid 'target' parameter")
            if op == "check_cipher":
                return OpenSSLAdapter.check_cipher(target, params, profile)
            return OpenSSLAdapter.inspect_cert(target, params, profile)

        elif tool == "httpx":
            if not target:
                raise ToolValidationError("HTTPX requires a valid 'target' (URL) parameter")
            if op == "technology_detection":
                return HTTPXAdapter.technology_detection(target, params, profile)
            return HTTPXAdapter.probe(target, params, profile)

        elif tool == "sslscan":
            if not target:
                raise ToolValidationError("SSLScan requires a valid 'target' parameter")
            return SSLScanAdapter.ssl_scan(target, params, profile)

        elif tool == "whatweb":
            if not target:
                raise ToolValidationError("WhatWeb requires a valid 'target' parameter")
            return WhatWebAdapter.tech_detect(target, params, profile)

        elif tool == "gobuster":
            if not target:
                raise ToolValidationError("Gobuster requires a valid 'target' (URL) parameter")
            return GobusterAdapter.dir_scan(target, params, profile)

        elif tool == "feroxbuster":
            if not target:
                raise ToolValidationError("Feroxbuster requires a valid 'target' (URL) parameter")
            return FeroxbusterAdapter.scan(target, params, profile)

        elif tool == "ffuf":
            if not target:
                raise ToolValidationError("FFUF requires a valid 'target' (URL) parameter")
            return FFufAdapter.fuzz(target, params, profile)

        elif tool == "nuclei":
            if not target:
                raise ToolValidationError("Nuclei requires a valid 'target' parameter")
            return NucleiAdapter.scan(target, params, profile)

        elif tool == "sqlmap":
            if not target:
                raise ToolValidationError("Sqlmap requires a valid 'target' parameter")
            return SqlmapAdapter.scan(target, params, profile)

        elif tool == "katana":
            if not target:
                raise ToolValidationError("Katana requires a valid 'target' parameter")
            return KatanaAdapter.crawl(target, params, profile)

        elif tool == "dalfox":
            if not target:
                raise ToolValidationError("Dalfox requires a valid 'target' parameter")
            return DalfoxAdapter.scan(target, params, profile)

        elif tool == "arjun":
            if not target:
                raise ToolValidationError("Arjun requires a valid 'target' parameter")
            return ArjunAdapter.discover(target, params, profile)

        elif tool == "wpscan":
            if not target:
                raise ToolValidationError("WPScan requires a valid 'target' parameter")
            return WPScanAdapter.scan(target, params, profile)

        elif tool == "dirsearch":
            if not target:
                raise ToolValidationError("Dirsearch requires a valid 'target' parameter")
            return DirsearchAdapter.scan(target, params, profile)

        elif tool == "dirb":
            if not target:
                raise ToolValidationError("Dirb requires a valid 'target' parameter")
            return {"command": f"dirb {target}"}

        elif tool == "nikto":
            if not target:
                raise ToolValidationError("Nikto requires a valid 'target' parameter")
            flags = [f"-h {target}"]
            if profile:
                flags.append("-Tuning 1 2 3 4 5 6 7 8 9 0")
            return {"command": f"nikto {' '.join(flags)}"}

        elif tool == "dig":
            if not target:
                raise ToolValidationError("Dig requires a valid 'target' parameter")
            qtype = params.get("type", "A")
            return {"command": f"dig {target} {qtype}"}

        elif tool == "wafw00f":
            if not target:
                raise ToolValidationError("Wafw00f requires a valid 'target' parameter")
            return {"command": f"wafw00f {target}"}

        elif tool == "sslyze":
            if not target:
                raise ToolValidationError("SSLyze requires a valid 'target' parameter")
            return {"command": f"sslyze {target}"}

        elif tool == "paramspider":
            if not target:
                raise ToolValidationError("ParamSpider requires a valid 'target' parameter")
            flags = [f"-d {target}"]
            level = params.get("level")
            if level:
                flags.append(f"--level {level}")
            return {"command": f"paramspider {' '.join(flags)}"}

        elif tool == "gau":
            if not target:
                raise ToolValidationError("gau requires a valid 'target' parameter")
            flags = [target]
            if params.get("include_subs"):
                flags.append("--subs")
            return {"command": f"gau {' '.join(flags)}"}

        elif tool == "waybackurls":
            if not target:
                raise ToolValidationError("waybackurls requires a valid 'target' parameter")
            return {"command": f"waybackurls {target}"}

        elif tool == "chaos":
            if not target:
                raise ToolValidationError("Chaos requires a valid 'target' (domain) parameter")
            return {"command": f"chaos -d {target}"}

        elif tool == "masscan":
            if not target:
                raise ToolValidationError("Masscan requires a valid 'target' parameter")
            ports = params.get("ports", "1-1000")
            rate = params.get("rate", 1000)
            return {"command": f"masscan {target} -p{ports} --rate {rate}"}

        elif tool == "curl":
            if not target:
                raise ToolValidationError("Curl requires a valid 'target' parameter")
            return {"command": f"curl -s -I {target}"}

        elif tool == "theharvester":
            if not target:
                raise ToolValidationError("theHarvester requires a valid 'target' parameter")
            # -b: only reliable free sources (skip ones requiring API keys or that hang)
            # -l: result cap so it terminates in reasonable time
            sources = params.get("sources") or "crtsh,duckduckgo,bing,otx,anubis,hackertarget,rapiddns,urlscan"
            limit = int(params.get("limit", 200))
            return {"command": f"theharvester -d {target} -b {sources} -l {limit}"}

        # Built-in Python tools map directly to Python tool kwargs
        elif tool == "http_request":
            return {
                "url": params.get("url") or target,
                "method": params.get("method", "GET"),
                "headers": params.get("headers"),
                "data": params.get("data"),
                "timeout": params.get("timeout", 10),
                "follow": params.get("follow", True),
            }
        elif tool == "dns_lookup":
            return {"domain": params.get("domain") or target}
        elif tool == "ssl_inspect":
            return {
                "domain": params.get("domain") or target,
                "port": int(params.get("port", 443)),
            }
        elif tool == "port_check":
            return {
                "host": params.get("host") or target,
                "port": int(params.get("port", 80)),
                "timeout": float(params.get("timeout", 2)),
            }
        elif tool == "browser":
            if op == "navigate":
                return {"command": f"navigate {target}"}
            elif op == "js":
                return {"command": f"js {params.get('code', '')}"}
            elif op == "screenshot":
                return {"command": f"screenshot {target}"}
            elif op == "cookies":
                return {"command": f"cookies {target}"}
            elif op == "form":
                fd = params.get("form_data") or params.get("data") or "{}"
                if isinstance(fd, dict):
                    fd = json.dumps(fd)
                return {"command": f"form {target} {fd}"}

        raise ToolValidationError(f"No adapter found for tool '{tool}' operation '{op}'")
