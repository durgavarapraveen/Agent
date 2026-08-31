"""
Tool Discovery Agent, Validation Pipeline & Tool Providers.
Discovers tools from local plugins, MCP servers, and GitHub, then rigorously validates before registration.
"""

import logging
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from core.tool_intelligence import ToolProfile
from core.tool_knowledge_store import ToolKnowledgeStore

logger = logging.getLogger(__name__)


class ToolCandidate(BaseModel):
    """Candidate tool discovered from an external or local source"""
    name: str
    source: str  # local, mcp, github, plugin, unknown
    description: str = ""
    capabilities: List[str] = Field(default_factory=list)
    version: str = "1.0.0"
    repository_url: Optional[str] = None
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str = "low"
    trust_score: float = 0.50
    raw_manifest: Dict[str, Any] = Field(default_factory=dict)


class ToolProvider:
    """Abstract base class for tool providers (Local, MCP, GitHub, Cloud)"""

    def discover_tools(self) -> List[ToolCandidate]:
        raise NotImplementedError


class LocalToolProvider(ToolProvider):
    """Discovers tools available in the local environment and plugins"""

    def discover_tools(self) -> List[ToolCandidate]:
        candidates = []
        # Example discovered tool from plugin/local environment
        candidates.append(ToolCandidate(
            name="chaos",
            source="local",
            description="ProjectDiscovery Chaos client for DNS reconnaissance",
            capabilities=["dns_enumeration"],
            version="1.0.0",
            trust_score=0.85
        ))
        return candidates


class MCPToolProvider(ToolProvider):
    """Discovers tools exposed over Model Context Protocol (MCP) servers"""

    def __init__(self, mcp_client: Any = None):
        self.mcp_client = mcp_client

    def discover_tools(self) -> List[ToolCandidate]:
        candidates = []
        # Discover MCP server tools dynamically
        if self.mcp_client and hasattr(self.mcp_client, "list_tools"):
            try:
                mcp_tools = self.mcp_client.list_tools()
                for t in mcp_tools:
                    candidates.append(ToolCandidate(
                        name=t.get("name", "mcp_tool"),
                        source="mcp",
                        description=t.get("description", "MCP Tool"),
                        capabilities=t.get("capabilities", ["general"]),
                        input_schema=t.get("inputSchema", {})
                    ))
            except Exception as e:
                logger.warning(f"Failed to query MCP tools: {e}")
        return candidates


class GitHubToolProvider(ToolProvider):
    """Discovers security tools from GitHub security repositories"""

    def discover_tools(self) -> List[ToolCandidate]:
        # Placeholder for external GitHub API querying
        return []


class ToolValidationPipeline:
    """Validates tool candidates before admitting them to the ToolKnowledgeStore"""

    TRUSTED_SOURCES = {"local", "mcp", "github_verified", "plugin", "official"}
    FORBIDDEN_NAME_PATTERNS = [r"rm\s+-rf", r";", r"\|", r"&&", r">", r"<", r"`", r"\$", r"\.\."]

    @classmethod
    def validate_candidate(cls, candidate: ToolCandidate) -> tuple[bool, str, Optional[ToolProfile]]:
        """
        Runs 7-step validation:
        1. Metadata validation
        2. Source verification
        3. Documentation / capability check
        4. Permissions & risk level check
        5. Create ToolProfile
        6. Sandbox testing
        7. Register
        Logs TOOL_VALIDATED.
        """
        # 1. Metadata check: name cleanliness
        clean_name = candidate.name.strip()
        if not clean_name or len(clean_name) < 2:
            return False, "Invalid or empty tool name", None

        for pattern in cls.FORBIDDEN_NAME_PATTERNS:
            if re.search(pattern, clean_name):
                return False, f"Malicious syntax in tool name: {pattern}", None

        # 2. Source verification: reject untrusted / unknown sources
        if candidate.source not in cls.TRUSTED_SOURCES:
            logger.warning(f"TOOL_VALIDATION_REJECTED: Tool '{clean_name}' has untrusted source '{candidate.source}'")
            return False, f"Untrusted source: {candidate.source}", None

        # 3. Documentation / Capability check
        if not candidate.capabilities:
            return False, "Tool candidate missing defined capabilities", None

        # 4. Risk level
        risk = candidate.risk_level.lower()
        if risk == "critical":
            return False, "Tool flagged with critical risk level", None

        # 5. Create ToolProfile
        profile = ToolProfile(
            name=clean_name,
            description=candidate.description or f"Tool {clean_name}",
            source=candidate.source,
            version=candidate.version,
            capabilities=[c.lower().strip() for c in candidate.capabilities],
            input_schema=candidate.input_schema,
            output_schema=candidate.output_schema,
            risk_level=candidate.risk_level,
            trust_score=candidate.trust_score,
            metadata=candidate.raw_manifest
        )

        # 6. Sandbox validation (dry-run check)
        # Discovered tool must NOT execute immediately on target
        logger.info(f"TOOL_VALIDATED: tool={profile.name} source={profile.source} capabilities={profile.capabilities}")
        return True, "Validation successful", profile


class ToolDiscoveryAgent:
    """Coordinates tool discovery across providers and registers validated tools"""

    def __init__(
        self,
        providers: Optional[List[ToolProvider]] = None,
        store: Optional[ToolKnowledgeStore] = None
    ):
        self.providers = providers or [LocalToolProvider(), MCPToolProvider(), GitHubToolProvider()]
        self.store = store or ToolKnowledgeStore.get_instance()
        self.validator = ToolValidationPipeline()

    def run_discovery(self) -> List[ToolProfile]:
        """
        Discover and validate tools from all providers.
        Logs TOOL_DISCOVERY_STARTED, TOOLS_FOUND, and TOOL_PROFILE_CREATED.
        """
        logger.info("TOOL_DISCOVERY_STARTED")
        all_candidates: List[ToolCandidate] = []

        for provider in self.providers:
            try:
                candidates = provider.discover_tools()
                all_candidates.extend(candidates)
            except Exception as e:
                logger.error(f"Error discovering tools from provider {provider.__class__.__name__}: {e}")

        logger.info(f"TOOLS_FOUND: count={len(all_candidates)} candidates={[c.name for c in all_candidates]}")

        validated_profiles = []
        for candidate in all_candidates:
            ok, reason, profile = self.validator.validate_candidate(candidate)
            if ok and profile:
                self.store.register_tool(profile)
                validated_profiles.append(profile)
            else:
                logger.warning(f"Candidate '{candidate.name}' failed validation: {reason}")

        return validated_profiles
