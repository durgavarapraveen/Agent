"""
ToolRegistry - All available tools (Kali, Python, MCP).
DynamicAgent picks tools from here. Each tool has a standard interface.
"""

import logging
import re
import socket
import ssl
import asyncio
from typing import Dict, List, Optional

import httpx

from agents.kali_executor import KaliDockerExecutor

logger = logging.getLogger(__name__)

# Strips ANSI escape sequences (color/cursor codes) from tool output. Tools like
# sslscan/nmap colorize their output; the raw codes otherwise leak into the
# terminal and "stick" (e.g. everything turns green) when a line is truncated
# before the reset code.
_ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text) if text else text


class ToolResult:
    """Standard result from any tool"""
    def __init__(self, success: bool, output: str = "", error: str = "", data: Dict = None):
        self.success = success
        self.output = output
        self.error = error
        self.data = data or {}

    def __repr__(self):
        status = "OK" if self.success else "FAIL"
        return f"ToolResult({status}, {len(self.output)} chars)"


class Tool:
    """Base tool interface"""
    def __init__(self, name: str, description: str, category: str):
        self.name = name
        self.description = description
        self.category = category  # recon, exploit, util

    def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError


# ═══════════════════════════════════════════════
# KALI TOOLS (via Docker)
# ═══════════════════════════════════════════════

class KaliTool(Tool):
    """Wraps any Kali Linux tool via Docker"""

    def __init__(self, name: str, description: str, category: str = "recon"):
        super().__init__(name, description, category)

    # Tools that use non-zero exit codes for normal results
    _LENIENT_RC_TOOLS = {
        "nikto", "nuclei", "feroxbuster", "gobuster", "dirb", "dirsearch",
        "ffuf", "sqlmap", "whatweb", "wafw00f", "wpscan", "katana",
        "theharvester", "sslscan", "sslyze", "testssl.sh", "commix",
        "xsser", "dalfox", "arjun", "paramspider", "httpx", "httpx-toolkit",
    }

    def run(self, command: str, timeout: int = 600) -> ToolResult:
        """Run raw command in Kali container (kali_executor bumps heavy scanners further)"""
        logger.info(f"  [{self.name}] {command}")
        r = KaliDockerExecutor.run(command, timeout=timeout, auto_install=True)
        stdout = strip_ansi(r.get("stdout", ""))
        stderr = strip_ansi(r.get("stderr", ""))
        rc = r.get("returncode")
        status = r.get("status", "error")
        # Many security tools return non-zero for normal results (nikto=1 when
        # findings exist, nuclei=1 when no matches, feroxbuster for various).
        # New tightened rules:
        #   - rc==0 or explicit `status="success"` → success.
        #   - timeout → always failure.
        #   - lenient tools with rc<128 AND non-empty stdout → success. The
        #     previous heuristic accepted non-empty stdout unconditionally, so
        #     a tool that printed a usage banner and crashed was flagged
        #     successful. Requiring rc<128 excludes signal-kills; requiring
        #     stdout excludes tools that printed only a warning to stderr.
        #   - Everything else → failure, with rc + stderr surfaced.
        if rc == 0 or status == "success":
            success = True
        elif status == "timeout":
            success = False
        elif self.name in self._LENIENT_RC_TOOLS and rc is not None and rc < 128 and stdout.strip():
            success = True
        else:
            success = False
        error = "" if success else (stderr or r.get("error", ""))
        if not success:
            logger.warning(f"  [{self.name}] FAILED rc={rc} stderr={stderr[:300]}")
        return ToolResult(
            success=success,
            output=stdout or (stderr if success else ""),
            error=error,
            data={"returncode": rc, "stderr": stderr},
        )


# ═══════════════════════════════════════════════
# PYTHON TOOLS (built-in, no Docker needed)
# ═══════════════════════════════════════════════

class PythonHTTPTool(Tool):
    """HTTP requests via httpx"""

    def __init__(self):
        super().__init__("http_request", "Make HTTP requests", "util")

    def run(self, url: str, method: str = "GET", headers: Dict = None,
            data: str = None, timeout: int = 10, follow: bool = True) -> ToolResult:
        import asyncio
        import os as _os_thr
        # Blanket `verify=False` is appropriate for pentesting against self-
        # signed targets, but it's an anti-pattern when the tool is used for
        # OSINT / clean-target lookups. Env `HTTP_TOOL_VERIFY_TLS=1` enables
        # verification.
        _verify_tls = _os_thr.environ.get("HTTP_TOOL_VERIFY_TLS", "").strip() == "1"
        try:
            async def _fetch():
                from core.network.network_broker import get_network_broker
                r = await get_network_broker().request(method.upper(), url, follow_redirects=follow, 
                                                       headers=headers, content=data, timeout=timeout, verify=_verify_tls)
                return r

            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    resp = pool.submit(lambda: asyncio.run(_fetch())).result(timeout=timeout+5)
            else:
                resp = asyncio.run(_fetch())

            # Check for 403 / WAF and auto-attempt bypass headers if initially blocked
            bypassed = False
            if resp.status_code == 403 and (headers is None or "X-Forwarded-For" not in headers):
                from core.exploitation.waf_evasion import WAFEvasionManager
                waf = WAFEvasionManager.detect_waf(dict(resp.headers), resp.text[:2000], resp.status_code)
                bypass_hdrs = dict(headers or {})
                bypass_hdrs.update(WAFEvasionManager.get_403_bypass_headers(url))
                try:
                    async def _retry_bypass():
                        from core.network.network_broker import get_network_broker
                        r = await get_network_broker().request(method.upper(), url, follow_redirects=follow,
                                                               headers=bypass_hdrs, content=data, timeout=timeout, verify=False)
                        return r
                    
                    if loop.is_running():
                        with concurrent.futures.ThreadPoolExecutor() as pool:
                            resp_bypass = pool.submit(lambda: asyncio.run(_retry_bypass())).result(timeout=timeout+5)
                    else:
                        resp_bypass = asyncio.run(_retry_bypass())

                    if resp_bypass.status_code == 200:
                        logger.info(f"403_BYPASS_SUCCESSFUL: Target '{url}' accessed successfully with bypass headers!")
                        resp = resp_bypass
                        bypassed = True
                except Exception as ex:
                    logger.debug(f"403 bypass retry failed: {ex}")

            return ToolResult(
                success=True,
                output=resp.text[:5000],
                data={
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "size": len(resp.content),
                    "url": str(resp.url),
                    "bypassed_403": bypassed,
                }
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class PythonDNSTool(Tool):
    """DNS resolution via socket"""

    def __init__(self):
        super().__init__("dns_lookup", "DNS resolution", "recon")

    def run(self, domain: str) -> ToolResult:
        try:
            addrs = socket.getaddrinfo(domain, None)
            ips = sorted(set(r[4][0] for r in addrs))
            try:
                from core.security.policy_engine import get_policy_engine
                engine = get_policy_engine()
                for ip in ips:
                    engine.authorize_target(ip)
            except Exception:
                pass
            return ToolResult(success=True, output="\n".join(ips), data={"ips": ips})
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class PythonSSLTool(Tool):
    """SSL certificate inspection"""

    def __init__(self):
        super().__init__("ssl_inspect", "SSL certificate analysis", "recon")

    def run(self, domain: str, port: int = 443) -> ToolResult:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, port))
                cert = s.getpeercert()

            san = [x[1] for x in cert.get("subjectAltName", [])]
            info = {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "san": san,
            }
            return ToolResult(success=True, output=str(info), data=info)
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class PythonPortScanTool(Tool):
    """Quick port check via socket"""

    def __init__(self):
        super().__init__("port_check", "Check if port is open", "recon")

    def run(self, host: str, port: int, timeout: float = 2) -> ToolResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            is_open = result == 0
            return ToolResult(
                success=True,
                output=f"{port}: {'open' if is_open else 'closed'}",
                data={"port": port, "open": is_open}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


# ═══════════════════════════════════════════════
# HEADLESS BROWSER (via Docker + Playwright)
# ═══════════════════════════════════════════════

class HeadlessBrowserTool(Tool):
    """Headless browser via Docker for JS execution, screenshots, form filling"""

    def __init__(self):
        super().__init__(
            "browser",
            "Headless browser — navigate pages, execute JS, take screenshots, "
            "fill forms, extract cookies/localStorage. "
            "Commands: navigate <url> | js <code> | screenshot <url> | "
            "cookies <url> | form <url> <json_data>",
            "exploit"
        )

    # Static Playwright driver scripts. User-controlled arguments are supplied
    # as a base64-encoded JSON blob, decoded and consumed as a dict at runtime.
    # Previously each script interpolated `url`, `code`, and form `data` directly
    # into a Python source string via f-strings executed as `python3 -c "..."`
    # inside the Kali container. Any quote-breaking / backslash-breaking string
    # would achieve Python code execution in the container. This rewrite makes
    # such injection impossible because base64 output is [A-Za-z0-9+/=] only.
    _DRIVER_NAVIGATE = (
        "import base64,json,sys;"
        "a=json.loads(base64.b64decode(sys.argv[1]).decode());"
        "from playwright.sync_api import sync_playwright;"
        "p=sync_playwright().start();"
        "b=p.chromium.launch(headless=True);"
        "page=b.new_page();"
        "page.goto(a['url'],timeout=15000);"
        "print(page.content()[:8000]);"
        "b.close();p.stop()"
    )
    _DRIVER_JS = (
        "import base64,json,sys;"
        "a=json.loads(base64.b64decode(sys.argv[1]).decode());"
        "from playwright.sync_api import sync_playwright;"
        "p=sync_playwright().start();"
        "b=p.chromium.launch(headless=True);"
        "page=b.new_page();"
        "r=page.evaluate(a['code']);"
        "print(r);"
        "b.close();p.stop()"
    )
    _DRIVER_SCREENSHOT = (
        "import base64,json,sys;"
        "a=json.loads(base64.b64decode(sys.argv[1]).decode());"
        "from playwright.sync_api import sync_playwright;"
        "p=sync_playwright().start();"
        "b=p.chromium.launch(headless=True);"
        "page=b.new_page();"
        "page.goto(a['url'],timeout=15000);"
        "page.screenshot(path='/tmp/screenshot.png');"
        "print('Screenshot saved: /tmp/screenshot.png');"
        "print('Title: '+page.title());"
        "b.close();p.stop()"
    )
    _DRIVER_COOKIES = (
        "import base64,json,sys;"
        "a=json.loads(base64.b64decode(sys.argv[1]).decode());"
        "from playwright.sync_api import sync_playwright;"
        "p=sync_playwright().start();"
        "b=p.chromium.launch(headless=True);"
        "ctx=b.new_context();"
        "page=ctx.new_page();"
        "page.goto(a['url'],timeout=15000);"
        "cookies=ctx.cookies();"
        "import json as _j;print(_j.dumps(cookies,indent=2));"
        "b.close();p.stop()"
    )
    _DRIVER_FORM = (
        "import base64,json,sys;"
        "a=json.loads(base64.b64decode(sys.argv[1]).decode());"
        "from playwright.sync_api import sync_playwright;"
        "p=sync_playwright().start();"
        "b=p.chromium.launch(headless=True);"
        "page=b.new_page();"
        "page.goto(a['url'],timeout=15000);"
        "data=a.get('data') or {};"
        "assert isinstance(data,dict),'data must be object';"
        "for sel,val in data.items():"
        "    page.fill(sel,val);"
        "page.click('button[type=submit],input[type=submit]');"
        "page.wait_for_load_state('networkidle',timeout=10000);"
        "print(page.url);"
        "print(page.content()[:5000]);"
        "b.close();p.stop()"
    )

    def run(self, command: str, timeout: int = 30) -> ToolResult:
        """
        Dispatch browser commands to Playwright in Docker.
        command format: "<action> <args>"
        """
        import base64 as _b64
        import json as _json

        parts = command.strip().split(None, 1)
        action = parts[0].lower() if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        if action == "navigate":
            payload = {"url": args}
            driver = self._DRIVER_NAVIGATE
        elif action == "js":
            payload = {"code": args}
            driver = self._DRIVER_JS
        elif action == "screenshot":
            payload = {"url": args}
            driver = self._DRIVER_SCREENSHOT
        elif action == "cookies":
            payload = {"url": args}
            driver = self._DRIVER_COOKIES
        elif action == "form":
            # args = "<url> <json>"
            sp = args.split(None, 1)
            url = sp[0] if sp else ""
            try:
                data = _json.loads(sp[1]) if len(sp) > 1 else {}
            except Exception:
                return ToolResult(success=False, error="form action requires valid JSON data")
            if not isinstance(data, dict):
                return ToolResult(success=False, error="form action data must be a JSON object")
            payload = {"url": url, "data": data}
            driver = self._DRIVER_FORM
        else:
            return ToolResult(
                success=False,
                error=f"Unknown browser action: {action}. "
                      f"Use: navigate|js|screenshot|cookies|form"
            )

        # Encode user-supplied args as base64 — safe against shell + Python
        # string-literal injection because the alphabet is [A-Za-z0-9+/=] only.
        b64_arg = _b64.b64encode(_json.dumps(payload).encode("utf-8")).decode("ascii")
        # Assemble: `python3 -c "<driver>" <base64arg>`. `driver` is a static
        # source constant defined above; only the base64 argv token varies.
        full_cmd = f'python3 -c "{driver}" {b64_arg}'

        r = KaliDockerExecutor.run(full_cmd, timeout=timeout, auto_install=True)
        return ToolResult(
            success=r["status"] == "success",
            output=r.get("stdout", ""),
            error=r.get("stderr", "") or r.get("error", ""),
        )
        
    def execute(self, tool_name: str, params: Dict = None) -> Dict:
        """Execute a tool and return result dict."""
        if params is None:
            params = {}
        
        tool = self.get(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not found",
                "output": "",
                "data": {}
            }
        
        try:
            result = tool.run(**params)
            return {
                "success": result.success,
                "output": result.output,
                "error": result.error,
                "data": result.data
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "data": {}
            }

# ═══════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════

class ToolRegistry:
    """Central registry of all available tools"""

    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self._register_defaults()

    def _register_defaults(self):
        # Python tools (always available)
        self.register(PythonHTTPTool())
        self.register(PythonDNSTool())
        self.register(PythonSSLTool())
        self.register(PythonPortScanTool())
        self.register(HeadlessBrowserTool())

        # Kali tools (available if Docker running)
        kali_tools = [
            ("nmap", "Port scanning + service detection + vuln scripts"),
            ("masscan", "Fast port scanning"),
            ("subfinder", "Passive subdomain discovery"),
            ("assetfinder", "Asset discovery"),
            ("amass", "In-depth attack surface + subdomain enumeration"),
            ("dnsenum", "DNS enumeration"),
            ("fierce", "DNS reconnaissance"),
            ("dig", "DNS queries"),
            ("whois", "WHOIS lookup"),
            ("gobuster", "Directory/file bruteforce"),
            ("feroxbuster", "Recursive directory discovery"),
            ("ffuf", "Fast web fuzzer"),
            ("dirb", "URL bruteforcer"),
            ("dirsearch", "Web path scanner"),
            ("nikto", "Web server scanner"),
            ("nuclei", "Template-based vulnerability scanner"),
            ("whatweb", "Technology detection"),
            ("wafw00f", "WAF detection"),
            ("httpx", "HTTP probing and fingerprinting"),
            ("sqlmap", "SQL injection exploitation"),
            ("wpscan", "WordPress vulnerability scanner"),
            ("sslscan", "SSL/TLS scanner"),
            ("sslyze", "SSL configuration analyzer"),
            ("openssl", "SSL/TLS certificate analysis"),
            ("arjun", "HTTP parameter discovery"),
            ("paramspider", "Parameter mining from web archives"),
            ("dalfox", "XSS scanner"),
            ("katana", "Web crawler"),
            ("curl", "HTTP client"),
            ("theharvester", "OSINT email/domain gathering"),
        ]

        for name, desc in kali_tools:
            self.register(KaliTool(name, desc, "recon"))

        # P2-8: structured HTTP operations as first-class tools so the
        # LLM can call `http_fetch` / `extract_api_routes` / `parse_html`
        # / `compare_responses` etc. without asking for a shell pipeline.
        try:
            from core.tools.http_ops_tools import register_structured_http_tools
            register_structured_http_tools(self)
        except Exception as _e:
            logger.debug(f"[StructuredHTTP] registration skipped: {_e}")

    def register(self, tool: Tool):
        self.tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self.tools.get(name)

    def list_tools(self) -> str:
        """List available tools for LLM"""
        if hasattr(self, 'available_tools') and self.available_tools:
            return f"Available tools: {', '.join(sorted(self.available_tools.keys()))}"
        return f"Available tools: {', '.join(sorted(self.tools.keys()))}"

    def list_by_category(self, category: str) -> List[Tool]:
        return [t for t in self.tools.values() if t.category == category]

    def get_tools_for_objective(self, objective: str) -> str:
        """Return relevant tool names for a given objective (for LLM context)"""
        # Simple keyword matching — brain can use any tool regardless
        keywords = objective.lower()
        relevant = []
        for name, tool in self.tools.items():
            desc = f"{name} {tool.description}".lower()
            if any(k in desc for k in keywords.split()[:5]):
                relevant.append(f"- {name}: {tool.description}")

        if not relevant:
            return self.list_tools()  # Give all if nothing matches
        return "\n".join(relevant)
    
    async def validate_tools(self) -> dict:
        """Validate which tools exist. Called once at startup."""
        logger.info("Validating tool availability on startup...")
        
        self.available_tools = {}
        
        # Python tools always available
        for tool_name, tool in self.tools.items():
            if isinstance(tool, (PythonHTTPTool, PythonDNSTool, PythonSSLTool,
                                PythonPortScanTool, HeadlessBrowserTool)):
                self.available_tools[tool_name] = tool
                logger.info(f"  [OK] {tool_name}")
            else:
                # Assume Kali/other tools available
                self.available_tools[tool_name] = tool
                logger.debug(f"  [~] {tool_name}")
        
        logger.info(f"Available: {len(self.available_tools)} tools")
        return self.available_tools

    async def execute(self, tool_name: str, params: Dict = None):
        """Execute a tool and return result dict."""
        if params is None:
            params = {}

        # Validate invocation parameters and authorization
        from core.tools.tool_validation import ToolInvocationValidator
        from core.common.exceptions import ToolValidationError, AuthorizationError
        validator = ToolInvocationValidator(self)
        try:
            validator.validate(tool_name, params)
        except ToolValidationError as tve:
            logger.error(f"[ToolRegistry] TOOL_INVOCATION_REJECTED: {tve}")
            return {
                "success": False,
                "error": f"TOOL_INVALID_ARGUMENT: {str(tve)}",
                "output": "",
                "data": {}
            }
        except AuthorizationError as ae:
            logger.error(f"[ToolRegistry] AUTHORIZATION_DENIED: {ae}")
            return {
                "success": False,
                "error": f"AUTHORIZATION_FAILURE: {str(ae)}",
                "output": "",
                "data": {}
            }

        tool = self.get(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"TOOL_NOT_FOUND: Tool '{tool_name}' not found",
                "output": "",
                "data": {}
            }

        try:
            result = tool.run(**params)
            return {
                "success": result.success,
                "output": result.output,
                "error": result.error,
                "data": result.data
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "data": {}
            }

    async def _tool_exists(self, tool_name: str) -> bool:
        """Check if tool exists and is executable"""
        try:
            proc = await asyncio.create_subprocess_exec(
                tool_name, "--version",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            await asyncio.wait_for(proc.communicate(), timeout=2)
            return proc.returncode == 0 or True  # Return True if no crash

        except asyncio.TimeoutError:
            return True  # Tool exists but slow
        except FileNotFoundError:
            return False  # Tool doesn't exist
        except Exception as e:
            logger.debug(f"Error checking {tool_name}: {e}")
            return False
 
