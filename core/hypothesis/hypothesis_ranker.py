import logging
from typing import List, Dict, Any, Optional
from core.domain.hypothesis import SecurityHypothesis
from core.llm.llm_router import LLMRouter
from core.llm.schemas import LLMResponse

logger = logging.getLogger(__name__)


class StrategyEffectivenessScorer:
    RECENT_WEIGHT = 0.6
    HISTORICAL_WEIGHT = 0.4

    def score(
        self,
        strategy: str,
        target_type: str = "",
        historical_success: float = 0.0,
        recent_success: float = 0.0,
    ) -> float:
        raw = (self.RECENT_WEIGHT * recent_success) + (self.HISTORICAL_WEIGHT * historical_success)
        return max(0.0, min(1.0, raw))


class HypothesisRanker:
    def __init__(self, llm_router: LLMRouter, strategy_scorer: Optional[StrategyEffectivenessScorer] = None):
        self.llm_router = llm_router
        self.strategy_scorer = strategy_scorer or StrategyEffectivenessScorer()

    def rank(self, hypotheses: List[SecurityHypothesis]) -> List[SecurityHypothesis]:
        if not hypotheses:
            return []

        candidates = self._build_candidates(hypotheses)
        llm_response = self._rank_via_llm(candidates)

        if llm_response and llm_response.structured_data:
            self._apply_llm_scores(hypotheses, llm_response)
        else:
            self._apply_heuristic_scores(hypotheses)

        return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)

    def _build_candidates(self, hypotheses: List[SecurityHypothesis]) -> List[Dict[str, Any]]:
        candidates = []
        for h in hypotheses:
            candidates.append({
                "id": h.id,
                "test_id": h.test_id,
                "endpoint_id": h.endpoint_id or "unknown",
                "title": h.title,
                "rationale": h.rationale,
                "attack_type": h.title.split(" on ")[0] if " on " in h.title else h.title,
            })
        return candidates

    def _rank_via_llm(self, candidates: List[Dict[str, Any]]) -> Optional[LLMResponse]:
        context = {
            "task": "hypothesis_ranking",
            "total_candidates": len(candidates),
            "factors": [
                "test likelihood of discovering vulnerability",
                "tool success rate for this attack type",
                "endpoint complexity and attack surface exposure",
            ],
        }
        try:
            return self.llm_router.route_task("hypothesis_ranking", context, candidates)
        except Exception as e:
            logger.error(f"LLM ranking failed: {e}")
            return None

    def _apply_llm_scores(self, hypotheses: List[SecurityHypothesis], response: LLMResponse):
        ranked_data = response.structured_data.get("candidates", [])
        score_map = {item["id"]: item["score"] for item in ranked_data if "id" in item and "score" in item}

        for h in hypotheses:
            if h.id in score_map:
                h.confidence = max(0.0, min(1.0, score_map[h.id]))

    def _apply_heuristic_scores(self, hypotheses: List[SecurityHypothesis]):
        for i, h in enumerate(hypotheses):
            base = h.confidence
            position_penalty = i * 0.02
            h.confidence = max(0.0, min(1.0, base - position_penalty))

    def score_strategy(self, strategy: str, target_type: str = "", historical_success: float = 0.0, recent_success: float = 0.0) -> float:
        return self.strategy_scorer.score(strategy, target_type, historical_success, recent_success)
