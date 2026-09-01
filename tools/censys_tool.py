"""
Censys Reconnaissance Tool for ToolRegistry / ToolManager architecture.
LLM provides target/query; authentication credentials (CENSYS_PAT) are handled strictly by CensysClient from configuration.
"""

import logging
from typing import Any, Dict
from tools.base import Tool, ToolInputSchema, ToolOutputSchema, ToolPermission
from core.intelligence.censys_client import CensysClient

logger = logging.getLogger(__name__)


class CensysTool(Tool):
    """Censys Reconnaissance Tool for IP & Domain threat intelligence."""

    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={"target": "str"},
            optional_params={"search_type": "str"}  # "hosts" or "certificates"
        )
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="Censys reconnaissance search results containing hosts or certificates data"
        )
        super().__init__(
            name="censys_search",
            description="Search Censys Platform API for host infrastructure or TLS certificates. Parameters: target (domain or IP).",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE]
        )

    async def execute(self, target: str, search_type: str = "hosts", **params) -> Dict[str, Any]:
        """
        Execute Censys search against target.
        Credentials (CENSYS_PAT) are retrieved automatically from framework config.
        """
        client = CensysClient()
        if not client.is_configured:
            return {
                "status": "failed",
                "error": "Censys PAT is not configured in .env"
            }

        try:
            if search_type == "certificates":
                query = f"names: {target}"
                data = await client.search_certificates(query)
            else:
                data = await client.search_hosts(target)

            return {
                "status": "success",
                "target": target,
                "search_type": search_type,
                "data": data
            }
        except Exception as e:
            logger.error(f"[CensysTool] Error executing search: {e}")
            return {
                "status": "failed",
                "error": str(e)
            }
