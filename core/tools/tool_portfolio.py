from __future__ import annotations

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class ToolPortfolio:

    def __init__(self) -> None:
        self._chains: Dict[str, List[str]] = {}

    def register_fallback_chain(self, capability: str, tools: List[str]) -> None:
        self._chains[capability] = list(tools)
        logger.info("Registered fallback chain for '%s': %s", capability, tools)

    def get_tools(self, capability: str) -> List[str]:
        return list(self._chains.get(capability, []))


_GLOBAL_PORTFOLIO: ToolPortfolio | None = None


def get_global_portfolio() -> ToolPortfolio:
    global _GLOBAL_PORTFOLIO
    if _GLOBAL_PORTFOLIO is None:
        _GLOBAL_PORTFOLIO = ToolPortfolio()
    return _GLOBAL_PORTFOLIO


def get_fallback_chain(capability: str) -> List[str]:
    return get_global_portfolio().get_tools(capability)
