"""LLM task router — routes typed tasks through the canonical UniversalLLMHarness
so the shared LLM budget governor + provider fallback logic apply.

Historical note: this used to hit https://api.deepseek.com/v1/chat/completions
directly with `requests`, bypassing the harness/budget entirely. It now routes
via `agents.llm_harness_adapter.get_llm()`. Public API is preserved."""
import asyncio
import json
import logging
from typing import Any, Dict, List

from core.llm.schemas import LLMResponse
from core.llm.context_builder import ContextBuilder

logger = logging.getLogger(__name__)


class LLMRouter:
    def __init__(self, api_key: str = "", model: str = "deepseek-reasoner"):
        # api_key/model kept for backward compat with existing callers; the
        # harness is authoritative for provider + model selection.
        self.api_key = api_key
        self.model = model

    def _fallback_heuristic(self, task_type: str, candidates: List[Any]) -> Dict[str, Any]:
        """Safe local degradation when the LLM is unreachable."""
        logger.warning(f"Using local fallback heuristic for {task_type}")
        if task_type == "hypothesis_ranking":
            ranked = []
            for i, c in enumerate(candidates):
                score = max(0.0, 1.0 - (i * 0.1))
                cid = c.get("id", str(i)) if isinstance(c, dict) else str(c)
                ranked.append({"id": cid, "score": score, "justification": "Fallback heuristic"})
            return {"candidates": ranked}
        if task_type == "payload_generation":
            return {"payloads": [{"value": "' OR 1=1--", "expected_behavior": "SQLi Bypass",
                                   "justification": "Fallback"}]}
        return {}

    def _run_async(self, coro):
        """Bridge to the async harness from a sync API."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import threading
            box: Dict[str, Any] = {}
            def _worker():
                new_loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(new_loop)
                    box["r"] = new_loop.run_until_complete(coro)
                except Exception as e:
                    box["e"] = e
                finally:
                    new_loop.close()
            t = threading.Thread(target=_worker, daemon=True)
            t.start(); t.join(timeout=60)
            if "e" in box:
                raise box["e"]
            return box.get("r")
        return asyncio.run(coro)

    def route_task(self, task_type: str, context: Dict[str, Any],
                    candidates: List[Any]) -> LLMResponse:
        """Route the typed task through the harness; return LLMResponse."""
        instruction_map = {
            "hypothesis_ranking": (
                "Rank the following hypotheses by likelihood of success (0.0 to 1.0). "
                "Return a JSON object matching "
                "{'candidates': [{'id': '...', 'score': 0.9, 'justification': '...'}]}"
            ),
            "payload_generation": (
                "Generate targeted injection payloads. Return JSON object matching "
                "{'payloads': [{'value': '...', 'expected_behavior': '...', 'justification': '...'}]}"
            ),
        }
        instruction = instruction_map.get(
            task_type, "Provide structured JSON output for the following context."
        )
        prompt = ContextBuilder.format_as_prompt(context, candidates, instruction)
        system = ("You are a deterministic security orchestrator. "
                  "You output ONLY valid JSON without markdown wrapping.")
        try:
            from agents.llm_harness_adapter import get_llm
            from core.common.schemas import TaskTier
            harness = get_llm()
            if not harness:
                raise RuntimeError("LLM harness not initialized")
            data = self._run_async(
                harness.generate_json(prompt, system=system, max_tokens=2048,
                                       tier=TaskTier.LARGE)
            )
            if not isinstance(data, dict) or not data:
                raise RuntimeError("Empty/invalid JSON from harness")
            return LLMResponse(
                reasoning_trace="", structured_data=data,
                raw_response=json.dumps(data),
            )
        except Exception as e:
            logger.error(f"LLM routing failed for {task_type}: {e}")
            fallback = self._fallback_heuristic(task_type, candidates)
            return LLMResponse(
                reasoning_trace="LLM Failed. Fallback executed.",
                structured_data=fallback,
                raw_response=json.dumps(fallback),
            )

    def parse_llm_response(self, response: LLMResponse, schema: Any) -> Any:
        try:
            return schema(**response.structured_data)
        except Exception as e:
            logger.error(f"Failed to parse LLM structured data into schema: {e}")
            raise ValueError(f"Schema validation failed: {e}")
