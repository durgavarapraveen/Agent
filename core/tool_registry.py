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
from urllib.parse import urlparse

import httpx

from agents.kali_executor import KaliDockerExecutor

logger = logging.getLogger(__name__)


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

    def run(self, command: str, timeout: int = 120) -> ToolResult:
        """Run raw command in Kali container"""
        logger.info(f"  [{self.name}] {command[:80]}...")
        r = KaliDockerExecutor.run(command, timeout=timeout, auto_install=True)
        return ToolResult(
            success=r["status"] == "success",
            output=r.get("stdout", ""),
            error=r.get("stderr", "") or r.get("error", ""),
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
        try:
            async def _fetch():
                async with httpx.AsyncClient(timeout=timeout, verify=False,
                                              follow_redirects=follow) as client:
                    if method.upper() == "GET":
                        r = await client.get(url, headers=headers)
                    elif method.upper() == "POST":
                        r = await client.post(url, headers=headers, content=data)
                    elif method.upper() == "HEAD":
                        r = await client.head(url, headers=headers)
                    elif method.upper() == "PUT":
                        r = await client.put(url, headers=headers, content=data)
                    elif method.upper() == "DELETE":
                        r = await client.delete(url, headers=headers)
                    else:
                        r = await client.request(method, url, headers=headers, content=data)
                    return r

            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    resp = pool.submit(lambda: asyncio.run(_fetch())).result(timeout=timeout+5)
            else:
                resp = asyncio.run(_fetch())

            return ToolResult(
                success=True,
                output=resp.text[:5000],
                data={
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "size": len(resp.content),
                    "url": str(resp.url),
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

    def run(self, command: str, timeout: int = 30) -> ToolResult:
        """
        Dispatch browser commands to Playwright in Docker.
        command format: "<action> <args>"
        """
        parts = command.strip().split(None, 1)
        action = parts[0].lower() if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        # Build playwright script based on action
        if action == "navigate":
            script = self._script_navigate(args)
        elif action == "js":
            script = self._script_js(args)
        elif action == "screenshot":
            script = self._script_screenshot(args)
        elif action == "cookies":
            script = self._script_cookies(args)
        elif action == "form":
            script = self._script_form(args)
        else:
            return ToolResult(
                success=False,
                error=f"Unknown browser action: {action}. "
                      f"Use: navigate|js|screenshot|cookies|form"
            )

        # Run via Kali Docker with playwright installed
        full_cmd = (
            f"python3 -c \"{script}\""
        )
        r = KaliDockerExecutor.run(full_cmd, timeout=timeout, auto_install=True)
        return ToolResult(
            success=r["status"] == "success",
            output=r.get("stdout", ""),
            error=r.get("stderr", "") or r.get("error", ""),
        )

    def _script_navigate(self, url: str) -> str:
        return (
            "from playwright.sync_api import sync_playwright;"
            "p=sync_playwright().start();"
            "b=p.chromium.launch(headless=True);"
            "page=b.new_page();"
            f"page.goto('{url}',timeout=15000);"
            "print(page.content()[:8000]);"
            "b.close();p.stop()"
        )

    def _script_js(self, code: str) -> str:
        safe_code = code.replace("'", "\\'").replace('"', '\\"')
        return (
            "from playwright.sync_api import sync_playwright;"
            "p=sync_playwright().start();"
            "b=p.chromium.launch(headless=True);"
            "page=b.new_page();"
            f"r=page.evaluate('{safe_code}');"
            "print(r);"
            "b.close();p.stop()"
        )

    def _script_screenshot(self, url: str) -> str:
        return (
            "from playwright.sync_api import sync_playwright;"
            "p=sync_playwright().start();"
            "b=p.chromium.launch(headless=True);"
            "page=b.new_page();"
            f"page.goto('{url}',timeout=15000);"
            "page.screenshot(path='/tmp/screenshot.png');"
            "print('Screenshot saved: /tmp/screenshot.png');"
            "print('Title: '+page.title());"
            "b.close();p.stop()"
        )

    def _script_cookies(self, url: str) -> str:
        return (
            "import json;from playwright.sync_api import sync_playwright;"
            "p=sync_playwright().start();"
            "b=p.chromium.launch(headless=True);"
            "ctx=b.new_context();"
            "page=ctx.new_page();"
            f"page.goto('{url}',timeout=15000);"
            "cookies=ctx.cookies();"
            "print(json.dumps(cookies,indent=2));"
            "b.close();p.stop()"
        )

    def _script_form(self, args: str) -> str:
        # args = "https://target.com/login {\"user\":\"admin\",\"pass\":\"test\"}"
        parts = args.split(None, 1)
        url = parts[0] if parts else ""
        data = parts[1] if len(parts) > 1 else "{}"
        return (
            "import json;from playwright.sync_api import sync_playwright;"
            "p=sync_playwright().start();"
            "b=p.chromium.launch(headless=True);"
            "page=b.new_page();"
            f"page.goto('{url}',timeout=15000);"
            f"data={data};"
            "for sel,val in data.items():"
            "  page.fill(sel,val);"
            "page.click('button[type=submit],input[type=submit]');"
            "page.wait_for_load_state('networkidle',timeout=10000);"
            "print(page.url);"
            "print(page.content()[:5000]);"
            "b.close();p.stop()"
        )


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
            ("amass", "Subdomain enumeration"),
            ("assetfinder", "Asset discovery"),
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
            ("arjun", "HTTP parameter discovery"),
            ("paramspider", "Parameter mining from web archives"),
            ("dalfox", "XSS scanner"),
            ("katana", "Web crawler"),
            ("curl", "HTTP client"),
            ("theharvester", "OSINT email/domain gathering"),
        ]

        for name, desc in kali_tools:
            self.register(KaliTool(name, desc, "recon"))

    def register(self, tool: Tool):
        self.tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self.tools.get(name)

    def list_tools(self) -> str:
        """Formatted tool list for LLM prompt"""
        lines = []
        for name, tool in sorted(self.tools.items()):
            lines.append(f"- {name}: {tool.description} [{tool.category}]")
        return "\n".join(lines)

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
        """Validate which tools actually exist on startup"""
        logger.info("Validating tool availability on startup...")
        
        self.available_tools = {}
        self.unavailable_tools = {}
        
        for tool_name in list(self.local_tools.keys()):
            exists = await self._tool_exists(tool_name)
            
            if exists:
                self.available_tools[tool_name] = self.local_tools[tool_name]
                logger.info(f"  ✓ {tool_name}")
            else:
                self.unavailable_tools[tool_name] = self.local_tools[tool_name]
                logger.warning(f"  ✗ {tool_name} (not found)")
        
        logger.info(f"Available: {len(self.available_tools)}, Unavailable: {len(self.unavailable_tools)}")
        return self.available_tools
 
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
 
    def list_tools(self) -> str:
        """List available tools for LLM"""
        if hasattr(self, 'available_tools') and self.available_tools:
            return f"Available tools: {', '.join(sorted(self.available_tools.keys()))}"
        return f"Available tools: {', '.join(sorted(self.local_tools.keys()))}"
 