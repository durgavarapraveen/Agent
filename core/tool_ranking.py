"""
Tool Ranking Engine.
Computes dynamic composite ranking scores for tools based on trust, performance, success rate, and task relevance.
"""

import logging
from typing import List, Tuple, Optional
from core.tool_intelligence import ToolProfile
from core.schemas import TaskSpec

logger = logging.getLogger(__name__)


class ToolRankingEngine:
    """Ranks tool candidates dynamically using empirical metrics and task context"""

    @classmethod
    def rank_tools(
        cls,
        tools: List[ToolProfile],
        task_spec: Optional[TaskSpec] = None,
        limit: Optional[int] = None
    ) -> List[ToolProfile]:
        """
        Rank tools and return sorted list of ToolProfiles.
        Logs TOOLS_RANKED.
        """
        if not tools:
            return []

        scored_tools: List[Tuple[ToolProfile, float]] = []

        for tool in tools:
            base_score = (
                (tool.trust_score * 0.35) +
                (tool.performance_score * 0.35) +
                (tool.success_rate * 0.30)
            )

            # Contextual objective weighting
            context_bonus = 0.0
            if task_spec:
                obj_text = (task_spec.objective + " " + str(task_spec.inputs)).lower()
                desc_text = (tool.description + " " + tool.name).lower()

                # Check keyword relevance
                keywords = ["passive", "active", "crawl", "spider", "fuzz", "archive", "fast", "deep", "stealth"]
                for kw in keywords:
                    if kw in obj_text and kw in desc_text:
                        context_bonus += 0.05

            final_score = min(1.0, round(base_score + context_bonus, 3))
            scored_tools.append((tool, final_score))

        # Sort descending by score
        scored_tools.sort(key=lambda item: item[1], reverse=True)

        if limit:
            scored_tools = scored_tools[:limit]

        ranked_profiles = [item[0] for item in scored_tools]
        tool_names = [p.name for p in ranked_profiles]
        scores = [item[1] for item in scored_tools]

        cap_name = task_spec.capability.value if task_spec else (ranked_profiles[0].capabilities[0] if ranked_profiles[0].capabilities else "unknown")
        logger.info(f"TOOLS_RANKED: capability={cap_name} tools={tool_names} scores={scores}")

        return ranked_profiles
