from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def _mk(prefix: str, given: str = None) -> str:
    return given or f"{prefix}_{uuid.uuid4().hex[:8]}"


class KnowledgeStore:

    _logged = False

    def __init__(self, db_path: str = None):
        # No schema creation, no Postgres connection, no deprecation warning.
        if not KnowledgeStore._logged:
            logger.info("KnowledgeStore(kb_*) is retired — writes now route "
                        "through canonical pg_store repos; this shim is a no-op.")
            KnowledgeStore._logged = True

    # ── writers: keep signatures + return ids, persist nothing to kb_* ──────
    def add_target(self, target_id: str, url_or_path: str, target_type: str):
        return None

    def add_asset(self, arg1: str = None, arg2: str = None, arg3: str = None, arg4: str = None,
                  asset_id: str = None, target_id: str = None, asset_type: str = None,
                  value: str = None, metadata: Any = None) -> str:
        # Preserve the historical positional-arg id resolution so a caller that
        # passed its own asset_id gets the same id back.
        if asset_id is None and target_id is None and asset_type is None and value is None:
            if arg4 is not None:
                asset_id = arg1
            elif arg3 is not None:
                asset_id = _mk("ast")
            else:
                asset_id = arg1 or _mk("ast")
        return asset_id or _mk("ast")

    def add_technology(self, arg1: str = None, arg2: str = None, arg3: str = None, arg4: str = None,
                       confidence: float = 1.0, source: str = "", tech_id: str = None,
                       asset_id: str = None, name: str = None, version: str = None) -> str:
        return tech_id or _mk("tch")

    def add_endpoint(self, endpoint_id: str = None, asset_id: str = None, path: str = "",
                     http_method: str = "GET", status_code: int = None, requires_auth: bool = False,
                     target_id: str = None, metadata: Any = None) -> str:
        return _mk("ep", endpoint_id)

    def add_api(self, api_id: str = None, asset_id: str = None, api_type: str = "",
                base_url: str = "", auth_type: str = None) -> str:
        return _mk("api", api_id)

    def add_finding(self, finding_id: str = None, target_id: str = None, title: str = "Unknown",
                    description: str = "", severity: str = "MEDIUM", confidence: float = 0.5,
                    status: str = "OBSERVED", category: str = "", cwe: str = None, cve: str = None,
                    affected_asset: str = "", affected_endpoint: str = "", evidence: str = "",
                    remediation: str = "", source_agent_id: str = "") -> str:
        return _mk("fnd", finding_id)

    def add_evidence(self, evidence_id: str = None, finding_id: str = None,
                     evidence_type: str = "screenshot", content: str = "",
                     tool_name: str = None) -> str:
        return _mk("evd", evidence_id)

    def add_exploit_result(self, target_id: str, vuln_id: str = "", exploit_id: str = "",
                           payload: str = "", success: bool = False, proof: str = "",
                           severity: str = "MEDIUM", executed_at: str = None,
                           result_id: str = None) -> str:
        return _mk("xres", result_id)

    def add_post_exploit_finding(self, target_id: str, type: str = "", host: str = "",
                                 technique: str = "", detail: str = "", severity: str = "MEDIUM",
                                 metadata: Any = None, pe_id: str = None) -> str:
        return _mk("pe", pe_id)

    def update_finding_status(self, finding_id: str, status: str):
        return None

    # ── readers: nothing reads through this store any more ──────────────────
    def get_target_findings(self, target_id: str) -> List[Dict]:
        return []

    def get_target_assets(self, target_id: str) -> List[Dict]:
        return []

    def get_asset_technologies(self, asset_id: str) -> List[Dict]:
        return []

    def get_asset_endpoints(self, asset_id: str) -> List[Dict]:
        return []

    def get_all_findings(self, target_id: str) -> List[Dict]:
        return []

    def export_database_summary(self) -> Dict[str, Any]:
        return {}
