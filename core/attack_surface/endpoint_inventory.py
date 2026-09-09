from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class EndpointInventoryV2:

    def __init__(self) -> None:
        self._endpoints: Dict[str, Dict[str, Any]] = {}
        self._url_index: Dict[str, str] = {}

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        url = endpoint.get("url", endpoint.get("path", ""))
        method = endpoint.get("method", "GET").upper()
        # P3: dedup by the ONE canonical identity (normalizes scheme/host case,
        # default ports, trailing slash, query order) so this projection's unique
        # count matches the authoritative stores instead of splitting on spelling.
        from core.domain.endpoint import canonical_endpoint_key
        dedup_key = canonical_endpoint_key(method, url)

        if dedup_key in self._url_index:
            existing_id = self._url_index[dedup_key]
            existing = self._endpoints[existing_id]
            for k, v in endpoint.items():
                if k not in existing or not existing[k]:
                    existing[k] = v
            params_existing = {p.get("name") for p in existing.get("parameters", [])}
            for p in endpoint.get("parameters", []):
                if p.get("name") not in params_existing:
                    existing.setdefault("parameters", []).append(p)
            return

        eid = endpoint.get("endpoint_id", f"ep-{len(self._endpoints)}")
        endpoint["endpoint_id"] = eid
        self._endpoints[eid] = endpoint
        self._url_index[dedup_key] = eid

    def get_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        return self._endpoints.get(endpoint_id)

    def list_endpoints(self) -> List[Dict[str, Any]]:
        return list(self._endpoints.values())

    def find_by_path(self, path: str) -> List[Dict[str, Any]]:
        return [
            ep for ep in self._endpoints.values()
            if path in ep.get("url", ep.get("path", ""))
        ]

    def update_endpoint(self, endpoint_id: str, updates: Dict[str, Any]) -> None:
        ep = self._endpoints.get(endpoint_id)
        if ep:
            ep.update(updates)
