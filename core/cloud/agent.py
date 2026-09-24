"""Cloud red-team agent (spec §17) — deterministic, provider-agnostic, scoped.

Selects a provider adapter, runs read-only discovery + attack-path synthesis,
and returns structured state. No LLM in the decision path; cloud metadata is
untrusted data. Never mutates the account.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.cloud.providers import PROVIDERS, SnapshotSource

logger = logging.getLogger(__name__)


class CloudAgent:
    def __init__(self, provider: str, source: Any, account_id: str = "account",
                 engagement: Optional[Any] = None):
        key = (provider or "").strip().lower()
        if key not in PROVIDERS:
            raise ValueError(f"unknown cloud provider: {provider!r} "
                             f"(supported: {', '.join(sorted(PROVIDERS))})")
        self.provider = PROVIDERS[key](source, account_id=account_id,
                                       engagement=engagement)

    @classmethod
    def from_snapshot(cls, provider: str, snapshot: Dict[str, Any],
                      account_id: str = "account",
                      engagement: Optional[Any] = None) -> "CloudAgent":
        return cls(provider, SnapshotSource(snapshot), account_id, engagement)

    def run(self) -> Dict[str, Any]:
        result = self.provider.run()
        logger.info("[cloud-agent] %s/%s: %d findings, %d attack paths",
                    result["provider"], result["account_id"],
                    len(result["findings"]), len(result["attack_paths"]))
        return result
