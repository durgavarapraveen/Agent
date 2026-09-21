"""LLMEnhancer — the adaptive brain layer (gaps §5).

Turns the deterministic scanner into an attacker-emulating agent WHEN an LLM is
reachable. Everything here is gated on Bedrock availability
(execution_mode.is_bedrock_available) and fails safe to no-op, so the pipeline
runs identically (deterministic) when the model is not authorized.

Two capabilities used by the engine/planner:
  * novel_payloads()  — generate context-specific payload variants the static
    catalog doesn't have (WAF-tuned, tech-tuned, protocol-specific).
  * looks_abusable()  — a cheap "would a human attacker probe this?" signal to
    prioritize surfaces (routed through the same JSON LLM path).

Untrusted observed data is passed as DATA (ContextBuilder already routes it
through the ObservationBoundary), never as instructions.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LLMEnhancer:
    def __init__(self):
        self._router = None
        self._checked = False
        self._available = False

    def is_available(self) -> bool:
        if not self._checked:
            self._checked = True
            try:
                from core.orchestration.execution_mode import get_execution_config
                self._available = get_execution_config().is_bedrock_available()
            except Exception:
                self._available = False
            if os.getenv("DISABLE_LLM_ENHANCER", "").lower() in ("1", "true", "yes"):
                self._available = False
        return self._available

    def _get_router(self):
        if self._router is None:
            from core.llm.llm_router import LLMRouter
            self._router = LLMRouter()
        return self._router

    def novel_payloads(self, vuln_class: str, context: Dict[str, Any],
                       max_n: int = 5) -> List[str]:
        """LLM-generated payload variants for (class, observed context). Empty
        list when unavailable — caller falls back to catalog payloads only."""
        if not self.is_available():
            return []
        try:
            router = self._get_router()
            ctx = {"vuln_class": vuln_class, **context}
            resp = router.route_task("payload_generation", ctx, [vuln_class])
            data = getattr(resp, "structured_data", {}) or {}
            out: List[str] = []
            for item in (data.get("payloads") or []):
                val = item.get("value") if isinstance(item, dict) else str(item)
                if val:
                    out.append(str(val))
            return out[:max_n]
        except Exception as e:
            logger.debug("novel_payloads failed: %s", e)
            return []

    def rank_surfaces(self, surfaces_summary: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ask the LLM to prioritize surfaces ('this looks abusable'). Returns
        the input unchanged when unavailable (deterministic order preserved)."""
        if not self.is_available() or not surfaces_summary:
            return surfaces_summary
        try:
            router = self._get_router()
            resp = router.route_task("hypothesis_ranking",
                                     {"surfaces": surfaces_summary}, surfaces_summary)
            data = getattr(resp, "structured_data", {}) or {}
            ranked = data.get("candidates")
            if not ranked:
                return surfaces_summary
            order = {c.get("id"): c.get("score", 0.0) for c in ranked if isinstance(c, dict)}
            return sorted(surfaces_summary,
                          key=lambda s: order.get(s.get("id"), 0.0), reverse=True)
        except Exception as e:
            logger.debug("rank_surfaces failed: %s", e)
            return surfaces_summary


_enhancer: Optional[LLMEnhancer] = None


def get_enhancer() -> LLMEnhancer:
    global _enhancer
    if _enhancer is None:
        _enhancer = LLMEnhancer()
    return _enhancer
