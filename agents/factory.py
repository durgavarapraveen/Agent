from typing import Dict, Type, Optional, Any
from uuid import uuid4
import logging

from agents.base import BaseAgent
from agents.specialists import (
    ReconAgent, APIAgent, AuthenticationAgent, SourceAnalysisAgent,
    DependencyAgent, ValidationAgent, CorrelationAgent, ReportingAgent
)
from agents.real_agents import (
    RealReconAgent, RealVulnerabilityAgent, 
    RealDependencyAgent, RealWebServerAgent
)

from agents.reconnaissance_agents import (
    SubdomainDiscoveryAgent,
    PortScanAgent,
    DirectoryBruteforceAgent,
    TechStackAgent,
    ScreenshotAgent,
    VulnerabilityDetectionAgent,
    ComprehensiveReconAgent
)

logger = logging.getLogger(__name__)

class AgentRegistry:
    """Registry of available agent types."""
    
    def __init__(self):
        self.agent_classes: Dict[str, Type[BaseAgent]] = {}
        self._register_default_agents()
    
    def _register_default_agents(self):
        """Register built-in agent types."""
        self.register("reconnaissance", ReconAgent)
        self.register("api_analysis", APIAgent)
        self.register("authentication_analysis", AuthenticationAgent)
        self.register("source_analysis", SourceAnalysisAgent)
        self.register("dependency_analysis", DependencyAgent)
        self.register("validation", ValidationAgent)
        self.register("correlation", CorrelationAgent)
        self.register("reporting", ReportingAgent)
        self.register("vulnerability_scanning", RealVulnerabilityAgent)
        self.register("dependency_analysis", RealDependencyAgent)
        self.register("web_server_analysis", RealWebServerAgent)
        
        self.register("subdomain_discovery", SubdomainDiscoveryAgent)
        self.register("port_scanning", PortScanAgent)
        self.register("directory_bruteforce", DirectoryBruteforceAgent)
        self.register("tech_detection", TechStackAgent)
        self.register("screenshot", ScreenshotAgent)
        self.register("vulnerability_detection", VulnerabilityDetectionAgent)
        self.register("comprehensive_recon", ComprehensiveReconAgent)
    
    def register(self, capability: str, agent_class: Type[BaseAgent]):
        """Register an agent type."""
        self.agent_classes[capability] = agent_class
        logger.debug(f"Registered agent type: {capability} -> {agent_class.__name__}")
    
    def get_agent_class(self, capability: str) -> Optional[Type[BaseAgent]]:
        """Get agent class for a capability."""
        return self.agent_classes.get(capability)
    
    def get_available_capabilities(self):
        """Get all available agent capabilities."""
        return list(self.agent_classes.keys())

class AgentFactory:
    """Factory for creating agents dynamically."""
    
    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.created_agents: Dict[str, BaseAgent] = {}
        self.agent_counter = 0
    
    async def create_agent(self, capability: str, context: Any) -> Optional[BaseAgent]:
        """Create an agent for a capability."""
        agent_class = self.registry.get_agent_class(capability)
        
        if not agent_class:
            logger.error(f"Unknown capability: {capability}")
            return None
        
        # Generate unique agent ID
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
        """Get an agent by ID."""
        return self.created_agents.get(agent_id)
    
    def get_all_agents(self):
        """Get all created agents."""
        return list(self.created_agents.values())
    
    def get_agents_by_state(self, state: str):
        """Get agents in a specific state."""
        return [a for a in self.created_agents.values() if a.state.value == state]

# Type hint
from core.context import ExecutionContext
create_agent = AgentFactory.create_agent
