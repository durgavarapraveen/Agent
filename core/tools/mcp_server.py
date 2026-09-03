import fastmcp
import asyncio
import logging
from core.tools.tool_gateway import ToolGateway

try:
    import fastmcp
except ImportError:
    class MockFastMCP:
        def __init__(self, **kwargs): pass
        def list_tools(self): return lambda f: f
        def call_tool(self): return lambda f: f
        async def run(self, **kwargs): pass
    class fastmcp:
        FastMCP = MockFastMCP


logger = logging.getLogger(__name__)

class MCPBridgeServer:
    """
    MCP server that exposes ToolGateway to Claude.
    
    IMPORTANT: This is OPTIONAL and PARALLEL.
    - DeepSeek still uses Approach A (TaskManager → ToolGateway)
    - Claude CAN use this MCP server IF connected
    - Both feed results to same normalizer
    """
    
    def __init__(self, port: int = 9000, gateway: ToolGateway = None):
        try:
            self.app = fastmcp.FastMCP(name="pentester-tools")
        except Exception as e:
            logger.error(f"FastMCP not fully installed. Mocking. Error: {e}")
            class MockApp:
                def list_tools(self): return lambda f: f
                def call_tool(self): return lambda f: f
                async def run(self, **kwargs): pass
            self.app = MockApp()
            
        self.port = port
        self.gateway = gateway or ToolGateway()
        self._register_handlers()
    
    def _register_handlers(self):
        """Register @list_tools() and @call_tool()"""
        
        @self.app.list_tools()
        def list_all_tools():
            """Claude sees all available tools"""
            tools_list = []
            
            for tool_id, tool_def in self.gateway.registry.tools.items():
                tools_list.append({
                    "name": tool_id,
                    "description": tool_def.description,
                    "inputSchema": getattr(tool_def, 'input_schema', {})
                })
            
            logger.info(f"Exposed {len(tools_list)} tools to MCP clients")
            return tools_list
        
        @self.app.call_tool()
        async def execute_tool(name: str, arguments: dict):
            """Claude calls tool → routes through ToolGateway"""
            
            from core.common.schemas import ToolInvocation
            from core.security.authorization import AuthContext
            
            logger.info(f"MCP client called: {name}")
            
            # Convert MCP call to ToolInvocation
            invocation = ToolInvocation(
                tool_id=name,
                operation=self._get_operation_for_tool(name),
                target=arguments.get("target", ""),
                params=arguments,
                session_id="mcp-session",
                audit_context={"source": "mcp"}
            )
            
            # Get auth context (Claude user)
            auth_context = AuthContext()
            
            # Execute through ToolGateway (same path as DeepSeek!)
            result = await self.gateway.execute(invocation, auth_context)
            
            return {
                "success": result.success,
                "findings": result.findings,
                "errors": result.errors,
                "execution_time_sec": result.execution_time_sec
            }
    
    async def start(self):
        """Start MCP server"""
        logger.info(f"Starting MCP server on port {self.port}")
        # self.app.run() is typically synchronous and blocks, so we run it in a thread
        # to avoid the "Type 'None' is not awaitable" error.
        await asyncio.to_thread(self.app.run, port=self.port)
