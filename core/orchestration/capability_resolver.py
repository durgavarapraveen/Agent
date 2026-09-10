
import logging
from typing import List, Optional
from core.common.schemas import TaskSpec
from core.tools.tool_intelligence import ToolProfile
from core.tools.tool_knowledge_store import ToolKnowledgeStore
from core.tools.tool_ranking import ToolRankingEngine

logger = logging.getLogger(__name__)


class CapabilityResolver:

    def __init__(self, store: Optional[ToolKnowledgeStore] = None):
        self.store = store or ToolKnowledgeStore.get_instance()

    def resolve_tools(
        self,
        capability: str,
        objective: str = "",
        task_spec: Optional[TaskSpec] = None,
        top_k: int = 5
    ) -> List[ToolProfile]:
        cap_clean = str(capability).lower().strip()
        candidates = self.store.get_tools_for_capability(cap_clean)

        # Semantic fallback search across tool descriptions if direct index is empty
        if not candidates:
            all_tools = self.store.get_all_tools()
            search_terms = (cap_clean.replace("_", " ") + " " + objective).lower().split()
            for tool in all_tools:
                desc_text = (tool.description + " " + " ".join(tool.capabilities) + " " + tool.name).lower()
                if any(term in desc_text for term in search_terms if len(term) > 3):
                    candidates.append(tool)

        # Rank candidates dynamically
        ranked_tools = ToolRankingEngine.rank_tools(candidates, task_spec=task_spec, limit=top_k)

        tool_names = [t.name for t in ranked_tools]
        logger.info(f"CAPABILITY_RESOLUTION_COMPLETED: capability={cap_clean} tools={tool_names}")

        return ranked_tools
