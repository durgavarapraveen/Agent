#!/usr/bin/env python3
import asyncio
import logging
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.stdout.reconfigure(encoding='utf-8')

from core.execution_mode import get_execution_config, ExecutionMode
from core.central_brain import CentralBrain
from core.mcp_server import MCPBridgeServer
from core.hybrid_executor_logger import HybridExecutorLogger
from core.tool_gateway import ToolGateway

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def start_hybrid_system():
    config = get_execution_config()
    logger.info(f"Active Execution Mode: {config.mode.name}")
    
    # Initialize components
    hybrid_logger = HybridExecutorLogger()
    brain = CentralBrain(target="example.com")
    
    mcp_task = None
    mcp_port = int(config.mcp_server_port) if config.mcp_server_port else 9000
    is_mcp_enabled = config.is_mode_b_enabled() or config.enable_mcp_server

    print("========================================")
    print("HYBRID SYSTEM STARTED")
    print("========================================")
    if config.should_use_mode_a_primary():
        print("✓ Approach A (DeepSeek) is PRIMARY")
    elif config.should_use_mode_b_primary():
        print("✓ Approach B (Claude MCP) is PRIMARY")
        
    if is_mcp_enabled:
        print(f"✓ MCP Server running on port {mcp_port}")
        
    if config.mode == ExecutionMode.HYBRID:
        print("✓ Hybrid mode: Will fallback from A to B if needed")
    print("========================================")

    if is_mcp_enabled:
        # Create MCP Bridge with brain's gateway
        mcp_server = MCPBridgeServer(port=mcp_port, gateway=brain.tool_gateway)
        mcp_task = asyncio.create_task(mcp_server.start())
        
    try:
        await brain.run()
    except KeyboardInterrupt:
        print("\nShutdown requested via KeyboardInterrupt")
    except Exception as e:
        logger.error(f"Error running CentralBrain: {e}")
    finally:
        if mcp_task:
            logger.info("Cancelling MCP Server task...")
            mcp_task.cancel()
            try:
                await mcp_task
            except asyncio.CancelledError:
                pass
                
        print("\n=== Execution Summary ===")
        hybrid_logger.print_summary()
        print("=========================")

if __name__ == "__main__":
    try:
        asyncio.run(start_hybrid_system())
    except KeyboardInterrupt:
        pass
