"""
Abstract Tool Invocation and Adapter layer.
Decouples LLM planning from raw command line syntax.
Python deterministic code constructs commands strictly from structured parameters.
"""

import json
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from core.exceptions import ToolValidationError

logger = logging.getLogger(__name__)


class ToolInvocation(BaseModel):
    """Abstract model representing a structured tool call proposed by the planner"""
    tool: str
    operation: str
    params: Dict[str, Any] = Field(default_factory=dict)
    target: Optional[str] = None


class NmapAdapter:
    @staticmethod
    def port_scan(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        ports = params.get("ports") or params.get("port")
        service_detection = params.get("service_detection", True)
        os_detection = params.get("os_detection", False)
        timing = params.get("timing", "T4")
        
        args = [f"-{timing}"]
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
    def subdomain_discovery(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        from core.subdomain_enum import extract_apex_domain
        apex = extract_apex_domain(clean_target)
        # Use apex domain if available to discover all sibling subdomains
        query_domain = apex if apex else clean_target
        return {"command": f"subfinder -d {query_domain} -oJ"}


class AmassAdapter:
    @staticmethod
    def passive_enum(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        from core.subdomain_enum import extract_apex_domain
        apex = extract_apex_domain(clean_target)
        query_domain = apex if apex else clean_target
        return {"command": f"amass enum -passive -d {query_domain}"}


class OpenSSLAdapter:
    @staticmethod
    def inspect_cert(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        port = params.get("port", 443)
        return {"command": f"openssl s_client -connect {target}:{port}"}

    @staticmethod
    def check_cipher(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        port = params.get("port", 443)
        cipher = params.get("cipher")
        if cipher:
            return {"command": f"openssl s_client -cipher {cipher} -connect {target}:{port}"}
        return {"command": f"openssl s_client -connect {target}:{port}"}


class HTTPXAdapter:
    @staticmethod
    def technology_detection(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        path = params.get("path", "")
        if path:
            target = target.rstrip("/") + "/" + path.lstrip("/")
        return {"command": f"httpx -u {target} -status-code -title -tech-detect -json"}

    @staticmethod
    def probe(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        path = params.get("path", "")
        if path:
            target = target.rstrip("/") + "/" + path.lstrip("/")
        flags = ["-u", target, "-status-code", "-title", "-tech-detect", "-json"]
        return {"command": f"httpx {' '.join(flags)}"}


class SSLScanAdapter:
    @staticmethod
    def ssl_scan(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
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
    def tech_detect(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        aggression = params.get("aggression")
        if aggression:
            return {"command": f"whatweb -a {aggression} {target}"}
        return {"command": f"whatweb {target}"}


class ToolAdapter:
    """Translates abstract tool operations into concrete CLI command arguments or parameters"""

    FORBIDDEN_TOOLS = {"bash", "sh", "cmd", "powershell", "zsh"}

    @classmethod
    def adapt(cls, invocation: ToolInvocation) -> Dict[str, Any]:
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

        # Domain tool adapters
        if tool == "nmap":
            if not target:
                raise ToolValidationError("Nmap requires a valid 'target' parameter")
            return NmapAdapter.port_scan(target, params)

        elif tool == "subfinder":
            if not target:
                raise ToolValidationError("Subfinder requires a valid 'target' (domain) parameter")
            return SubfinderAdapter.subdomain_discovery(target, params)

        elif tool == "amass":
            if not target:
                raise ToolValidationError("Amass requires a valid 'target' (domain) parameter")
            return AmassAdapter.passive_enum(target, params)

        elif tool == "openssl":
            if not target:
                raise ToolValidationError("OpenSSL requires a valid 'target' parameter")
            if op == "check_cipher":
                return OpenSSLAdapter.check_cipher(target, params)
            return OpenSSLAdapter.inspect_cert(target, params)

        elif tool == "httpx":
            if not target:
                raise ToolValidationError("HTTPX requires a valid 'target' (URL) parameter")
            if op == "technology_detection":
                return HTTPXAdapter.technology_detection(target, params)
            return HTTPXAdapter.probe(target, params)

        elif tool == "sslscan":
            if not target:
                raise ToolValidationError("SSLScan requires a valid 'target' parameter")
            return SSLScanAdapter.ssl_scan(target, params)

        elif tool == "whatweb":
            if not target:
                raise ToolValidationError("WhatWeb requires a valid 'target' parameter")
            return WhatWebAdapter.tech_detect(target, params)

        elif tool == "dig":
            if not target:
                raise ToolValidationError("Dig requires a valid 'target' parameter")
            qtype = params.get("type", "A")
            return {"command": f"dig {target} {qtype}"}

        elif tool == "gobuster":
            if not target:
                raise ToolValidationError("Gobuster requires a valid 'target' (URL) parameter")
            w = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            return {"command": f"gobuster dir -u {target} -w {w}"}

        elif tool == "feroxbuster":
            if not target:
                raise ToolValidationError("Feroxbuster requires a valid 'target' (URL) parameter")
            return {"command": f"feroxbuster -u {target}"}

        elif tool == "ffuf":
            if not target:
                raise ToolValidationError("FFUF requires a valid 'target' (URL) parameter")
            w = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            return {"command": f"ffuf -u {target} -w {w}"}

        elif tool == "dirb":
            if not target:
                raise ToolValidationError("Dirb requires a valid 'target' parameter")
            return {"command": f"dirb {target}"}

        elif tool == "dirsearch":
            if not target:
                raise ToolValidationError("Dirsearch requires a valid 'target' parameter")
            return {"command": f"dirsearch -u {target}"}

        elif tool == "nikto":
            if not target:
                raise ToolValidationError("Nikto requires a valid 'target' parameter")
            return {"command": f"nikto -h {target}"}

        elif tool == "nuclei":
            if not target:
                raise ToolValidationError("Nuclei requires a valid 'target' parameter")
            return {"command": f"nuclei -u {target}"}

        elif tool == "wafw00f":
            if not target:
                raise ToolValidationError("Wafw00f requires a valid 'target' parameter")
            return {"command": f"wafw00f {target}"}

        elif tool == "sqlmap":
            if not target:
                raise ToolValidationError("Sqlmap requires a valid 'target' parameter")
            return {"command": f"sqlmap -u {target} --batch"}

        elif tool == "wpscan":
            if not target:
                raise ToolValidationError("WPScan requires a valid 'target' parameter")
            return {"command": f"wpscan --url {target}"}

        elif tool == "sslyze":
            if not target:
                raise ToolValidationError("SSLyze requires a valid 'target' parameter")
            return {"command": f"sslyze {target}"}

        elif tool == "arjun":
            if not target:
                raise ToolValidationError("Arjun requires a valid 'target' parameter")
            return {"command": f"arjun -u {target}"}

        elif tool == "paramspider":
            if not target:
                raise ToolValidationError("ParamSpider requires a valid 'target' parameter")
            return {"command": f"paramspider -d {target}"}

        elif tool == "dalfox":
            if not target:
                raise ToolValidationError("Dalfox requires a valid 'target' parameter")
            return {"command": f"dalfox url {target}"}

        elif tool == "katana":
            if not target:
                raise ToolValidationError("Katana requires a valid 'target' parameter")
            return {"command": f"katana -u {target}"}

        elif tool == "gau":
            if not target:
                raise ToolValidationError("gau requires a valid 'target' parameter")
            return {"command": f"gau {target}"}

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
            return {"command": f"masscan {target} -p{ports}"}

        elif tool == "curl":
            if not target:
                raise ToolValidationError("Curl requires a valid 'target' parameter")
            return {"command": f"curl -s -I {target}"}

        elif tool == "theharvester":
            if not target:
                raise ToolValidationError("theHarvester requires a valid 'target' parameter")
            return {"command": f"theharvester -d {target}"}

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
