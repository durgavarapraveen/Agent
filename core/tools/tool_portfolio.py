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
