"""
MCP Tools Registry - Connect to Model Context Protocol servers for pentesting
Supports: Hexstrike, Metasploit, Kali tools, Nuclei, Nikto
"""

import json
import logging
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MCPServer:
    """MCP Server connection"""
    name: str
    host: str
    port: int
    url: str
    tools: Dict[str, str]
    session: Optional[aiohttp.ClientSession] = None
    connected: bool = False


class MCPToolsRegistry:
    """Registry for MCP-based pentesting tools"""

    def __init__(self):
        self.servers: Dict[str, MCPServer] = {}
        self.tools: Dict[str, Dict[str, str]] = {}

    async def connect_hexstrike(self, host: str = "localhost", port: int = 9000) -> Dict[str, str]:
        """Connect to Hexstrike MCP server"""
        logger.info(f"Connecting to Hexstrike at {host}:{port}...")
        
        try:
            url = f"http://{host}:{port}"
            session = aiohttp.ClientSession()
            
            # Test connection
            async with session.get(f"{url}/health") as resp:
                if resp.status != 200:
                    raise ConnectionError(f"Hexstrike health check failed: {resp.status}")
            
            server = MCPServer(
                name="hexstrike",
                host=host,
                port=port,
                url=url,
                tools={
                    "recon_nmap": "Run nmap scan on target",
                    "recon_shodan": "Query Shodan database",
                    "recon_dns": "DNS enumeration and DNS recon",
                    "recon_ssl": "SSL/TLS certificate analysis",
                    "recon_whois": "WHOIS lookup",
                    "vuln_scan": "Vulnerability scanning (Nessus/Qualys)",
                    "exploit_run": "Run exploitation module",
                    "exploit_web": "Web exploitation (SQLi, XSS, IDOR)",
                    "post_exploit": "Post-exploitation modules",
                },
                session=session,
                connected=True
            )
            
            self.servers["hexstrike"] = server
            self.tools["hexstrike"] = server.tools
            
            logger.info(f"✓ Connected to Hexstrike ({len(server.tools)} tools)")
            return server.tools
            
        except Exception as e:
            logger.error(f"✗ Failed to connect to Hexstrike: {e}")
            raise

    async def connect_metasploit(self, host: str = "localhost", port: int = 9001) -> Dict[str, str]:
        """Connect to Metasploit MCP server"""
        logger.info(f"Connecting to Metasploit at {host}:{port}...")
        
        try:
            url = f"http://{host}:{port}"
            session = aiohttp.ClientSession()
            
            # Test connection
            async with session.get(f"{url}/health") as resp:
                if resp.status != 200:
                    raise ConnectionError(f"Metasploit health check failed: {resp.status}")
            
            server = MCPServer(
                name="metasploit",
                host=host,
                port=port,
                url=url,
                tools={
                    "exploit_run": "Execute exploit module by name",
                    "exploit_search": "Search for exploits by CVE/type",
                    "payload_generate": "Generate payload (meterpreter, shell, etc)",
                    "session_list": "List active Metasploit sessions",
                    "session_interact": "Interact with Metasploit session",
                    "session_shell": "Get shell access via session",
                    "post_exploit": "Run post-exploitation modules",
                    "enum_modules": "Enumerate available modules",
                },
                session=session,
                connected=True
            )
            
            self.servers["metasploit"] = server
            self.tools["metasploit"] = server.tools
            
            logger.info(f"✓ Connected to Metasploit ({len(server.tools)} tools)")
            return server.tools
            
        except Exception as e:
            logger.error(f"✗ Failed to connect to Metasploit: {e}")
            raise

    async def connect_kali_tools(self, host: str = "localhost", port: int = 9002) -> Dict[str, str]:
        """Connect to Kali tools MCP server"""
        logger.info(f"Connecting to Kali tools at {host}:{port}...")
        
        try:
            url = f"http://{host}:{port}"
            session = aiohttp.ClientSession()
            
            # Test connection
            async with session.get(f"{url}/health") as resp:
                if resp.status != 200:
                    raise ConnectionError(f"Kali tools health check failed: {resp.status}")
            
            server = MCPServer(
                name="kali",
                host=host,
                port=port,
                url=url,
                tools={
                    "sqlmap": "SQL injection testing automation",
                    "hydra": "Password brute force attacks",
                    "hashcat": "GPU-accelerated password cracking",
                    "john": "John the Ripper hash cracking",
                    "aircrack": "Wireless network security testing",
                    "wireshark": "Network protocol analysis",
                    "masscan": "High-speed port scanner",
                    "nmap_advanced": "Advanced nmap scanning",
                    "gobuster": "Directory and DNS brute forcing",
                    "ffuf": "Fast web fuzzer",
                    "curl": "HTTP requests and testing",
                    "wget": "File downloads and mirroring",
                    "netcat": "Network communication tool",
                },
                session=session,
                connected=True
            )
            
            self.servers["kali"] = server
            self.tools["kali"] = server.tools
            
            logger.info(f"✓ Connected to Kali tools ({len(server.tools)} tools)")
            return server.tools
            
        except Exception as e:
            logger.error(f"✗ Failed to connect to Kali tools: {e}")
            raise

    async def connect_nuclei(self, host: str = "localhost", port: int = 9003) -> Dict[str, str]:
        """Connect to Nuclei vulnerability scanner MCP"""
        logger.info(f"Connecting to Nuclei at {host}:{port}...")
        
        try:
            url = f"http://{host}:{port}"
            session = aiohttp.ClientSession()
            
            async with session.get(f"{url}/health") as resp:
                if resp.status != 200:
                    raise ConnectionError(f"Nuclei health check failed: {resp.status}")
            
            server = MCPServer(
                name="nuclei",
                host=host,
                port=port,
                url=url,
                tools={
                    "scan_fast": "Fast vulnerability scan (quick templates)",
                    "scan_full": "Full vulnerability scan (all templates)",
                    "scan_custom": "Scan with custom template",
                    "template_list": "List available templates",
                    "template_search": "Search templates by keyword",
                },
                session=session,
                connected=True
            )
            
            self.servers["nuclei"] = server
            self.tools["nuclei"] = server.tools
            
            logger.info(f"✓ Connected to Nuclei ({len(server.tools)} tools)")
            return server.tools
            
        except Exception as e:
            logger.error(f"✗ Failed to connect to Nuclei: {e}")
            raise

    async def call_tool(self, mcp_name: str, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool from an MCP server"""
        server = self.servers.get(mcp_name)
        
        if not server:
            raise ValueError(f"MCP server '{mcp_name}' not connected. Available: {list(self.servers.keys())}")
        
        if tool_name not in server.tools:
            raise ValueError(f"Tool '{tool_name}' not found in {mcp_name}. Available: {list(server.tools.keys())}")
        
        if not server.session:
            raise RuntimeError(f"Session not available for {mcp_name}")
        
        try:
            logger.info(f"Calling {mcp_name}:{tool_name} with params: {params}")
            
            async with server.session.post(
                f"{server.url}/call",
                json={"tool": tool_name, "params": params},
                timeout=aiohttp.ClientTimeout(total=300)
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"Tool call failed: {resp.status} - {error_text}")
                
                result = await resp.json()
                logger.info(f"✓ {mcp_name}:{tool_name} completed")
                return result
                
        except asyncio.TimeoutError:
            logger.error(f"Tool call timeout: {mcp_name}:{tool_name}")
            raise
        except Exception as e:
            logger.error(f"Tool call error: {mcp_name}:{tool_name} - {e}")
            raise

    async def close_all(self):
        """Close all MCP server connections"""
        for server in self.servers.values():
            if server.session:
                await server.session.close()
                logger.info(f"Closed connection to {server.name}")

    def list_all_tools(self) -> Dict[str, Dict[str, str]]:
        """List all available tools from all connected servers"""
        return self.tools.copy()

    def get_tool_description(self, mcp_name: str, tool_name: str) -> str:
        """Get description of a specific tool"""
        if mcp_name in self.tools and tool_name in self.tools[mcp_name]:
            return self.tools[mcp_name][tool_name]
        return "Tool not found"

    async def health_check(self) -> Dict[str, bool]:
        """Check health of all connected servers"""
        health = {}
        
        for name, server in self.servers.items():
            try:
                if not server.session:
                    health[name] = False
                    continue
                
                async with server.session.get(f"{server.url}/health", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    health[name] = resp.status == 200
            except Exception as e:
                logger.warning(f"Health check failed for {name}: {e}")
                health[name] = False
        
        return health