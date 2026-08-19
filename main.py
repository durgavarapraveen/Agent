#!/usr/bin/env python3
import asyncio
import argparse
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

from core.context import ExecutionContext
from orchestrator.central import CentralOrchestrator
from scope.manager import ScopeManager
from knowledge.store import KnowledgeStore
from llm.ollama import OllamaProvider
from tools.manager import ToolManager
from mcp.manager import MCPManager

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

async def run_demo():
    """Run in demo mode without a real target."""
    logger.info("AUTONOMOUS SECURITY AGENT - DEMO MODE")
    logger.info("=" * 60)
    
    db_path = Path("workspace/demo.db")
    db_path.parent.mkdir(exist_ok=True)
    
    knowledge_store = KnowledgeStore(str(db_path))
    llm_provider = OllamaProvider(
        base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
        model=os.getenv("OLLAMA_MODEL", "neural-chat")
    )
    
    tool_manager = ToolManager()
    mcp_manager = MCPManager()
    scope_manager = ScopeManager(
        allowed_domains=["*.example.com"],
        allowed_ips=["192.168.0.0/16"],
        execution_mode="PASSIVE"
    )
    
    context = ExecutionContext(
        target="DEMO",
        objective="Perform a complete security assessment",
        knowledge_store=knowledge_store,
        llm_provider=llm_provider,
        tool_manager=tool_manager,
        mcp_manager=mcp_manager,
        scope_manager=scope_manager,
        mode="DEMO"
    )
    
    orchestrator = CentralOrchestrator(context)
    
    try:
        await orchestrator.run()
        logger.info("Demo completed successfully")
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)

async def run_source_analysis(repository_path):
    """Run source code analysis mode."""
    logger.info(f"SOURCE CODE ANALYSIS MODE")
    logger.info(f"Repository: {repository_path}")
    logger.info("=" * 60)
    
    if not Path(repository_path).exists():
        logger.error(f"Repository not found: {repository_path}")
        return
    
    db_path = Path("workspace/source.db")
    db_path.parent.mkdir(exist_ok=True)
    
    knowledge_store = KnowledgeStore(str(db_path))
    llm_provider = OllamaProvider(
        base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
        model=os.getenv("OLLAMA_MODEL", "neural-chat")
    )
    
    tool_manager = ToolManager()
    mcp_manager = MCPManager()
    scope_manager = ScopeManager(
        allowed_paths=[repository_path],
        execution_mode="PASSIVE"
    )
    
    context = ExecutionContext(
        target=repository_path,
        objective="Analyze source code security",
        knowledge_store=knowledge_store,
        llm_provider=llm_provider,
        tool_manager=tool_manager,
        mcp_manager=mcp_manager,
        scope_manager=scope_manager,
        mode="SOURCE"
    )
    
    orchestrator = CentralOrchestrator(context)
    
    try:
        await orchestrator.run()
        logger.info("Source analysis completed")
    except Exception as e:
        logger.error(f"Source analysis failed: {e}", exc_info=True)

async def run_web_target(target_url, mode="PASSIVE"):
    """Run web target analysis mode."""
    logger.info(f"WEB TARGET ANALYSIS MODE")
    logger.info(f"Target: {target_url}")
    logger.info(f"Execution Mode: {mode}")
    logger.info("=" * 60)
    
    db_path = Path(f"workspace/{target_url.replace(':', '_').replace('/', '_')}.db")
    db_path.parent.mkdir(exist_ok=True)
    
    knowledge_store = KnowledgeStore(str(db_path))
    llm_provider = OllamaProvider(
        base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
        model=os.getenv("OLLAMA_MODEL", "neural-chat")
    )
    
    tool_manager = ToolManager()
    mcp_manager = MCPManager()
    
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    domain = parsed.netloc
    
    scope_manager = ScopeManager(
        allowed_domains=[domain],
        execution_mode=mode
    )
    
    context = ExecutionContext(
        target=target_url,
        objective="Perform web security assessment",
        knowledge_store=knowledge_store,
        llm_provider=llm_provider,
        tool_manager=tool_manager,
        mcp_manager=mcp_manager,
        scope_manager=scope_manager,
        mode="WEB"
    )
    
    orchestrator = CentralOrchestrator(context)
    
    try:
        await orchestrator.run()
        logger.info("Web target analysis completed")
    except Exception as e:
        logger.error(f"Web analysis failed: {e}", exc_info=True)

def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Multi-Agent Cybersecurity Assessment Platform"
    )
    parser.add_argument("--demo", action="store_true", help="Run in demo mode")
    parser.add_argument("--target", type=str, help="Web target URL")
    parser.add_argument("--repository", type=str, help="Local repository path")
    parser.add_argument("--mode", choices=["PASSIVE", "SAFE_ACTIVE", "FULL_AUTHORIZED"],
                       default="PASSIVE", help="Execution mode")
    
    args = parser.parse_args()
    print(args)
    
    if args.demo:
        asyncio.run(run_demo())
    elif args.target:
        asyncio.run(run_web_target(args.target, args.mode))
    elif args.repository:
        asyncio.run(run_source_analysis(args.repository))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
