"""Dynamic capability registry — a runtime, extensible capability->tools index
that replaces scattered hardcoded maps. Seeded with defaults, extendable at
runtime via register(), and enriched from the typed CapabilityRegistry in
tool_definitions.py when available. Singleton via get_capability_registry()."""
from __future__ import annotations

import logging
import threading
from typing import Dict, List

logger = logging.getLogger(__name__)

_DEFAULT_SEED: Dict[str, List[str]] = {
    "port_scanning": ["masscan", "nmap"],
    "sql_injection": ["sqlmap", "nuclei", "dalfox"],
    "xss": ["dalfox", "nuclei"],
    "idor": ["burp", "nuclei"],
    "cve_scanning": ["nuclei", "nmap"],
    "directory_bruteforce": ["ffuf", "gobuster", "feroxbuster"],
    "subdomain_enum": ["subfinder", "amass", "assetfinder"],
    "web_crawl": ["katana", "hakrawler", "gospider"],
    "ssl_analysis": ["sslscan", "testssl"],
    "vuln_scan": ["nuclei", "nikto"],
    "ssrf": ["nuclei", "interactsh"],
    "lfi": ["nuclei", "ffuf"],
}


class DynamicCapabilityRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._map: Dict[str, List[str]] = {k: list(v) for k, v in _DEFAULT_SEED.items()}
        self._enriched = False

    def register(self, capability: str, tools: List[str]) -> None:
        with self._lock:
            cur = self._map.setdefault(capability.lower(), [])
            for t in tools:
                if t not in cur:
                    cur.append(t)

    def register_tool(self, tool_name: str, capabilities: List[str]) -> None:
        for cap in capabilities:
            self.register(cap, [tool_name])

    def get_tools_for_capability(self, capability: str) -> List[str]:
        self._maybe_enrich()
        with self._lock:
            return list(self._map.get((capability or "").lower(), []))

    def capabilities(self) -> List[str]:
        self._maybe_enrich()
        with self._lock:
            return sorted(self._map)

    def _maybe_enrich(self) -> None:
        """Pull in tools registered in the typed CapabilityRegistry (available
        tools discovered at runtime), so the map reflects what's actually here."""
        if self._enriched:
            return
        self._enriched = True
        try:
            from core.tools.tool_definitions import CapabilityRegistry
            reg = CapabilityRegistry()
            caps = getattr(reg, "capabilities", {}) or {}
            for cap, names in caps.items():
                key = getattr(cap, "value", str(cap)).lower()
                self.register(key, list(names))
        except Exception as e:
            logger.debug("capability enrich skipped: %s", e)


_instance = None
_instance_lock = threading.RLock()


def get_capability_registry() -> DynamicCapabilityRegistry:
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = DynamicCapabilityRegistry()
        return _instance
