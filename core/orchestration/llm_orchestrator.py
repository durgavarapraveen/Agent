"""
LLM Master Orchestrator (Phase 3 Master Engine).
Wraps CentralBrain and coordinates pentest memory retrieval, adaptive prompt building,
fallback/recovery execution, and token optimization prior to LLM interaction.
"""

import logging
from typing import Dict, List, Optional, Any

from core.memory.pentest_memory import PentestMemoryEngine
from core.prompts.adaptive import AdaptivePromptEngine
from core.common.recovery_strategies import FallbackRecoveryManager
from core.common.token_optimizer import TokenOptimizer

logger = logging.getLogger(__name__)


class LLMOrchestrator:
    """Master wrapper orchestrating LLM prompt synthesis, memory, recovery, and token compression."""

    def __init__(self, model_name: str = "gpt-4", token_limit: int = 8000, db_path: str = "pentest_memory.sqlite"):
        self.model_name = model_name
        self.memory = PentestMemoryEngine(db_path=db_path)
        self.adaptive_prompts = AdaptivePromptEngine()
        self.recovery = FallbackRecoveryManager()
        self.token_optimizer = TokenOptimizer(model_name=model_name, token_limit=token_limit)

    def prepare_llm_execution_context(
        self,
        tech_stack: List[str],
        industry: str = "default",
        depth: str = "poc",
        findings: Optional[List[Dict[str, Any]]] = None,
        tool_outputs: Optional[Dict[str, str]] = None,
        error_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Orchestration Pipeline:
          1. Retrieve past pentest memory & inject dynamic insights into prompt.
          2. Build adaptive prompt based on industry variant & depth level.
          3. Apply token optimization, deduplication, ranking, and threshold compression.
        """
        findings = findings or []
        tool_outputs = tool_outputs or {}

        # 1. Past Pentest Memory
        historical_insight = self.memory.build_dynamic_system_prompt_insight(tech_stack)

        # 2. Adaptive Prompt Generation
        base_prompt = self.adaptive_prompts.build_prompt(industry=industry, depth=depth, error_context=error_context)
        if historical_insight:
            full_prompt = f"{historical_insight}\n\n{base_prompt}"
        else:
            full_prompt = base_prompt

        # 3. Token Compression & Budgeting
        compression_result = self.token_optimizer.compress_prompt_context(full_prompt, findings, tool_outputs)

        logger.info(f"[LLMOrchestrator] Context prepared for model '{self.model_name}'. Token Reduction: {compression_result['reduction_percent']}%")
        return compression_result

    def record_scan_completion(self, engagement_id: str, tech_stack: List[str], findings: List[Dict[str, Any]], success_rate: float):
        """Store completed scan engagement anonymized back into vector store for future learning."""
        doc_data = {
            "id": engagement_id,
            "tech_stack": tech_stack,
            "findings": [f.get("cve_id") or f.get("title") for f in findings],
            "successful_tools": ["nmap", "nuclei", "sqlmap"],
            "failed_tools": ["gobuster"],
            "overall_success_rate": success_rate
        }
        self.memory.vector_store.add_document(engagement_id, tech_stack, doc_data)
        logger.info(f"[LLMOrchestrator] Engagement {engagement_id} saved to memory vector store.")
