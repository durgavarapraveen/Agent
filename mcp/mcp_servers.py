"""
MCP Server Stubs - Runs inside Kali Docker container
Provides HTTP endpoints for pentesting tools
"""

import asyncio
import json
import subprocess
import logging
from aiohttp import web
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KaliToolsExecutor:
    """Execute Kali tools directly"""
    
    @staticmethod
    async def run_command(cmd: list, timeout: int = 60) -> Dict[str, Any]:
        """Run shell command and return output"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return {"error": f"Command timeout after {timeout}s", "status": "failed"}
            
            return {
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "returncode": proc.returncode,
                "status": "success" if proc.returncode == 0 else "failed"
            }
        except Exception as e:
            return {"error": str(e), "status": "error"}


class MCPServerHandler:
    """Handle MCP tool requests"""
    
    def __init__(self, port: int, name: str):
        self.port = port
        self.name = name
        self.app = web.Application()
        self.setup_routes()
    
    def setup_routes(self):
        self.app.router.add_get('/health', self.health)
        self.app.router.add_post('/call', self.call_tool)
        self.app.router.add_get('/tools', self.list_tools)
    
    async def health(self, request):
        """Health check endpoint"""
        return web.json_response({
            "status": "ok",
            "server": self.name,
            "port": self.port
        })
    
    async def list_tools(self, request):
        """List available tools"""
        tools = self._get_available_tools()
        return web.json_response({"tools": tools})
    
    async def call_tool(self, request):
        """Execute tool"""
        try:
            data = await request.json()
            tool = data.get('tool', '')
            params = data.get('params', {})
            
            logger.info(f"[{self.name}] Calling tool: {tool} with params: {params}")
            
            result = await self.execute_tool(tool, params)
            return web.json_response({
                "success": True,
                "server": self.name,
                "tool": tool,
                "result": result
            })
        except Exception as e:
            logger.error(f"[{self.name}] Error: {e}")
            return web.json_response({
                "success": False,
                "error": str(e),
                "server": self.name
            }, status=400)
    
    async def execute_tool(self, tool: str, params: Dict) -> Dict[str, Any]:
        """Execute tool implementation"""
        
        # Hexstrike tools
        if self.name == "Hexstrike":
            return await self._execute_hexstrike(tool, params)
        
        # Metasploit tools
        elif self.name == "Metasploit":
            return await self._execute_metasploit(tool, params)
        
        # Kali tools
        elif self.name == "Kali":
            return await self._execute_kali(tool, params)
        
        # Default
        else:
            return {"status": "unknown_server", "server": self.name}
    
    async def _execute_hexstrike(self, tool: str, params: Dict) -> Dict:
        """Execute Hexstrike tools"""
        
        if tool == "recon_nmap":
            target = params.get('target', 'localhost')
            cmd = ['nmap', '-sV', '-Pn', target]
            result = await KaliToolsExecutor.run_command(cmd, timeout=120)
            return result
        
        elif tool == "recon_dns":
            target = params.get('target', 'example.com')
            cmd = ['nslookup', target]
            result = await KaliToolsExecutor.run_command(cmd, timeout=30)
            return result
        
        elif tool == "recon_whois":
            target = params.get('target', 'example.com')
            cmd = ['whois', target]
            result = await KaliToolsExecutor.run_command(cmd, timeout=30)
            return result
        
        else:
            return {"status": "tool_not_found", "tool": tool}
    
    async def _execute_metasploit(self, tool: str, params: Dict) -> Dict:
        """Execute Metasploit tools"""
        
        # For now, return stubs
        if tool == "exploit_search":
            keyword = params.get('keyword', '')
            return {
                "status": "stub",
                "message": "Metasploit exploit search",
                "keyword": keyword,
                "note": "Connect to msfconsole for real execution"
            }
        
        elif tool == "payload_generate":
            payload = params.get('payload', 'windows/meterpreter/reverse_tcp')
            return {
                "status": "stub",
                "payload": payload,
                "note": "Use msfvenom for real payload generation"
            }
        
        else:
            return {"status": "tool_not_found", "tool": tool}
    
    async def _execute_kali(self, tool: str, params: Dict) -> Dict:
        """Execute Kali tools"""
        
        if tool == "sqlmap":
            url = params.get('url', '')
            cmd = ['sqlmap', '--help']  # Just show help for safety
            result = await KaliToolsExecutor.run_command(cmd, timeout=30)
            return result
        
        elif tool == "nmap":
            target = params.get('target', 'localhost')
            scan_type = params.get('scan_type', 'basic')
            
            if scan_type == "basic":
                cmd = ['nmap', '-sV', target]
            elif scan_type == "aggressive":
                cmd = ['nmap', '-A', '-T4', target]
            else:
                cmd = ['nmap', '-sV', target]
            
            result = await KaliToolsExecutor.run_command(cmd, timeout=120)
            return result
        
        elif tool == "whois":
            target = params.get('target', 'example.com')
            cmd = ['whois', target]
            result = await KaliToolsExecutor.run_command(cmd, timeout=30)
            return result
        
        else:
            return {"status": "tool_not_found", "tool": tool}
    
    def _get_available_tools(self) -> list:
        """Get list of available tools"""
        if self.name == "Hexstrike":
            return [
                "recon_nmap",
                "recon_dns",
                "recon_ssl",
                "recon_whois",
                "vuln_scan",
                "exploit_web"
            ]
        elif self.name == "Metasploit":
            return [
                "exploit_search",
                "exploit_run",
                "payload_generate",
                "session_list",
                "session_interact"
            ]
        elif self.name == "Kali":
            return [
                "nmap",
                "sqlmap",
                "hydra",
                "whois",
                "masscan",
                "nikto"
            ]
        else:
            return []
    
    async def start(self):
        """Start the server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        logger.info(f"[+] {self.name} MCP server running on 0.0.0.0:{self.port}")
        return runner


async def main():
    """Start all MCP servers"""
    logger.info("[+] Starting MCP servers...")
    
    servers = []
    
    # Hexstrike on 9000
    try:
        hex_server = MCPServerHandler(9000, "Hexstrike")
        runner1 = await hex_server.start()
        servers.append(runner1)
    except Exception as e:
        logger.error(f"Failed to start Hexstrike: {e}")
    
    # Metasploit on 9001
    try:
        msf_server = MCPServerHandler(9001, "Metasploit")
        runner2 = await msf_server.start()
        servers.append(runner2)
    except Exception as e:
        logger.error(f"Failed to start Metasploit: {e}")
    
    # Kali tools on 9002
    try:
        kali_server = MCPServerHandler(9002, "Kali")
        runner3 = await kali_server.start()
        servers.append(runner3)
    except Exception as e:
        logger.error(f"Failed to start Kali: {e}")
    
    logger.info("[+] All MCP servers started")
    
    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        for runner in servers:
            await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())