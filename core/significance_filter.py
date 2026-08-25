"""
Significance Filter Layer.
Filters raw tool findings to keep high-impact security findings while removing noise.
"""

import logging
from typing import Any, Dict, List
from core.token_optimizer import TokenOptimizer

logger = logging.getLogger(__name__)


class SignificanceFilter:
    """Filter raw extracted security findings for LLM token optimization."""

    @classmethod
    def filter(cls, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter extracted tool findings by significance.
        Returns cleaned/filtered dataset preserving all critical findings.
        """
        if not isinstance(data, dict):
            return data

        tool_clean = (tool_name or "").lower().strip()
        filtered_data = dict(data)

        # 1. Filter Endpoints
        if "endpoints" in filtered_data and isinstance(filtered_data["endpoints"], list):
            endpoints = filtered_data["endpoints"]
            if endpoints and isinstance(endpoints[0], dict):
                filtered_data["endpoints"] = TokenOptimizer.filter_endpoints(endpoints)
            elif endpoints and isinstance(endpoints[0], str):
                ep_dicts = [{"url": url} for url in endpoints]
                filtered_eps = TokenOptimizer.filter_endpoints(ep_dicts)
                filtered_data["endpoints"] = [ep["url"] for ep in filtered_eps]

        # 2. Subdomains: filter out common low-value wildcards or empty entries
        if "subdomains" in filtered_data and isinstance(filtered_data["subdomains"], list):
            subdomains = [s for s in filtered_data["subdomains"] if isinstance(s, str) and s.strip()]
            filtered_data["subdomains"] = list(dict.fromkeys(subdomains))  # retain order, remove exact dupes

        # 3. Ports: prioritize open/filtered ports, remove closed ports noise
        if "ports" in filtered_data and isinstance(filtered_data["ports"], list):
            ports = []
            for p in filtered_data["ports"]:
                if isinstance(p, dict):
                    if p.get("state", "open").lower() in ("open", "filtered"):
                        ports.append(p)
                else:
                    ports.append(p)
            filtered_data["ports"] = ports

        # 4. Technologies
        if "technologies" in filtered_data:
            tech = filtered_data["technologies"]
            if isinstance(tech, dict):
                filtered_data["technologies_summary"] = TokenOptimizer.compress_tech_stack(tech)
            elif isinstance(tech, list):
                filtered_data["technologies"] = list(dict.fromkeys(tech))

        return filtered_data
