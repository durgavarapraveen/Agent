"""
Factory - registers all agents including JS endpoint agent
"""
from typing import Dict, Type, Optional, Any
import logging

from agents.base import BaseAgent
from agents.specialists import (
    ReconAgent, APIAgent, AuthenticationAgent, SourceAnalysisAgent,
    DependencyAgent, ValidationAgent, CorrelationAgent, ReportingAgent
)
from agents.reconnaissance_agents_kali import (
    SubdomainDiscoveryAgent, PortScanAgent, DirectoryBruteforceAgent,
    TechStackAgent, VulnerabilityDetectionAgent, ComprehensiveReconAgent
)
from agents.js_endpoint_agent import JSEndpointAgent

logger = logging.getLogger(__name__)

try:
    from agents.real_agents import (
        RealVulnerabilityAgent, RealDependencyAgent, RealWebServerAgent
    )
    _has_real_agents = True
except ImportError:
    _has_real_agents = False


class AgentRegistry:
    def __init__(self):
        self.agent_classes: Dict[str, Type[BaseAgent]] = {}
        self._register_default_agents()

    def _register_default_agents(self):
        self.register("reconnaissance", ReconAgent)
        self.register("api_analysis", APIAgent)
        self.register("authentication_analysis", AuthenticationAgent)
        self.register("source_analysis", SourceAnalysisAgent)
        self.register("dependency_analysis", DependencyAgent)
        self.register("validation", ValidationAgent)
        self.register("correlation", CorrelationAgent)
        self.register("reporting", ReportingAgent)

        self.register("subdomain_discovery", SubdomainDiscoveryAgent)
        self.register("port_scanning", PortScanAgent)
        self.register("directory_bruteforce", DirectoryBruteforceAgent)
        self.register("tech_detection", TechStackAgent)
        self.register("vulnerability_detection", VulnerabilityDetectionAgent)
        self.register("comprehensive_recon", ComprehensiveReconAgent)

        # NEW: JS endpoint extraction
        self.register("js_endpoint_extraction", JSEndpointAgent)
        self.register("javascript_analysis", JSEndpointAgent)
        self.register("api_discovery", JSEndpointAgent)

        if _has_real_agents:
            self.register("vulnerability_scanning", RealVulnerabilityAgent)
            self.register("web_server_analysis", RealWebServerAgent)
        else:
            self.register("vulnerability_scanning", VulnerabilityDetectionAgent)
            self.register("web_server_analysis", VulnerabilityDetectionAgent)

    def register(self, capability: str, agent_class: Type[BaseAgent]):
        self.agent_classes[capability] = agent_class
        logger.debug(f"Registered: {capability} -> {agent_class.__name__}")

    def get_agent_class(self, capability: str) -> Optional[Type[BaseAgent]]:
        return self.agent_classes.get(capability)

    def get_available_capabilities(self):
        return list(self.agent_classes.keys())


class AgentFactory:
    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.created_agents: Dict[str, BaseAgent] = {}
        self.agent_counter = 0

    async def create_agent(self, capability: str, context: Any) -> Optional[BaseAgent]:
        agent_class = self.registry.get_agent_class(capability)
        if not agent_class:
            logger.error(f"Unknown capability: {capability}")
            return None

        self.agent_counter += 1
        agent_id = f"{capability.upper()}-{self.agent_counter:03d}"

        try:
            agent = agent_class(agent_id, context)
            await agent.initialize()
            self.created_agents[agent_id] = agent
            logger.info(f"Created agent: {agent_id} ({capability})")
            return agent
        except Exception as e:
            logger.error(f"Failed to create agent {agent_id}: {e}")
            return None

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        return self.created_agents.get(agent_id)

    def get_all_agents(self):
        return list(self.created_agents.values())

    def get_agents_by_state(self, state: str):
        return [a for a in self.created_agents.values() if a.state.value == state]


from core.context import ExecutionContext
create_agent = AgentFactory.create_agent