from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class AgentExecutionMixin:
    """Spawn and run dynamic agents (single / parallel wave) and aggregate their
    results back into ctx. Extracted from CentralBrain; DynamicAgent is imported
    method-locally, context assembly resolves via MRO.
    """

    async def _spawn_and_run_agent(self, spec: Dict):
        from core.orchestration.dynamic_agent import DynamicAgent
        
        objective = spec.get("objective", "")
        tools = spec.get("tools", [])
        context_keys = spec.get("context_keys", [])
        max_steps = spec.get("max_steps", 10)
        
        logger.info(f"  Spawning agent: {objective}")
        
        # Build agent context from shared context
        agent_context = self._build_agent_context(context_keys)
        
        # Spawn agent
        agent_id = f"AGENT-{len(self.spawner.agents) + 1:03d}"
        
        agent = DynamicAgent(
            agent_id=agent_id,
            objective=objective,
            tool_registry=self.tools,
            shared_context=self.ctx,
            agent_context=agent_context,
            allowed_tools=tools,
            max_steps=max_steps
        )
        
        # Run agent
        logger.info(f"  Running {agent_id}...")
        result = await agent.execute()
        
        # Handle result
        if result.get("status") == "success":
            logger.info(f"  ✓ {agent_id} succeeded")
            self.ctx.add_event(f"{agent_id}: Success", result.get("results", {}))
        else:
            logger.warning(f"  ✗ {agent_id} failed: {result.get('reason', 'unknown')}")
            self.ctx.add_event(f"{agent_id}: Failed", result)

    async def _spawn_multiple_agents(self, specs: list):
        from core.orchestration.dynamic_agent import DynamicAgent
        
        logger.info(f"  Spawning {len(specs)} agents in parallel...")
        
        agents = []
        for _i, spec in enumerate(specs):
            objective = spec.get("objective", "")
            tools = spec.get("tools", [])
            context_keys = spec.get("context_keys", [])
            max_steps = spec.get("max_steps", 8)
            
            # Build context
            agent_context = self._build_agent_context(context_keys)
            
            # Create agent
            agent_id = f"AGENT-{len(agents) + 1:03d}"
            agent = DynamicAgent(
                agent_id=agent_id,
                objective=objective,
                tool_registry=self.tools,
                shared_context=self.ctx,
                agent_context=agent_context,
                allowed_tools=tools,
                max_steps=max_steps
            )
            agents.append(agent)
        
        # Run all in parallel
        logger.info(f"  Running {len(agents)} agents...")
        results = await asyncio.gather(*[agent.execute() for agent in agents])
        
        # Log results
        for agent, result in zip(agents, results):
            if result.get("status") == "success":
                logger.info(f"  ✓ {agent.agent_id} succeeded")
            else:
                logger.warning(f"  ✗ {agent.agent_id} {result.get('reason', 'failed')}")

    def _aggregate_wave_results(self, agents: List[Any], results: List[Any]) -> None:
        for _i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            
            res_data = result if isinstance(result, dict) else {}
            
            # 1. Aggregate discovered ports
            discovered_ports = res_data.get("open_ports") or res_data.get("ports") or []
            if isinstance(discovered_ports, list):
                for port in discovered_ports:
                    if isinstance(port, (int, str)):
                        self.ctx.ports[str(port)] = "open"
                    elif isinstance(port, dict):
                        p_num = str(port.get("port", ""))
                        if p_num:
                            self.ctx.ports[p_num] = port.get("service", "open")

            # 2. Aggregate discovered endpoints
            endpoints = res_data.get("endpoints") or res_data.get("discovered_endpoints") or []
            if isinstance(endpoints, list):
                for ep in endpoints:
                    if isinstance(ep, str) and ep not in self.ctx.endpoints:
                        self.ctx.endpoints.append(ep)

            # 3. Aggregate discovered subdomains
            subdomains = res_data.get("subdomains") or []
            if isinstance(subdomains, list):
                for sub in subdomains:
                    if isinstance(sub, str) and sub not in self.ctx.subdomains:
                        self.ctx.subdomains.append(sub)

            # 4. Aggregate technologies
            techs = res_data.get("technologies") or res_data.get("tech") or res_data.get("tech_stack") or {}
            target_host = self.ctx.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if isinstance(techs, dict):
                for k, v in techs.items():
                    if isinstance(v, list):
                        self.ctx.add_technologies(k, v)
                    else:
                        self.ctx.add_technologies(target_host, [f"{k}:{v}" if v != "detected" else k])
            elif isinstance(techs, list) and techs:
                self.ctx.add_technologies(target_host, techs)

            # 5. Persist to KnowledgeStore if available
            if hasattr(self, "store") and self.store:
                try:
                    for port, service in self.ctx.ports.items():
                        self.store.add_asset(
                            asset_type="port",
                            value=f"{self.ctx.target}:{port}",
                            metadata={"service": service}
                        )
                    for ep in self.ctx.endpoints:
                        self.store.add_endpoint(
                            target_id=self.ctx.target,
                            url=ep,
                            method="GET"
                        )
                except Exception as e:
                    logger.warning(f"Failed to persist wave aggregation to knowledge store: {e}")

            try:
                self._write_live_results()
            except Exception:
                pass
