from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SecurityContext:
    target: str
    scope: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    identities: Dict[str, Any] = field(default_factory=dict)
    endpoints: Dict[str, Any] = field(default_factory=dict)
    findings: Dict[str, Any] = field(default_factory=dict)
    experiments: Dict[str, Any] = field(default_factory=dict)
    coverage_state: Dict[str, Any] = field(default_factory=dict)

    def get_endpoint(self, name: str) -> Optional[Any]:
        return self.endpoints.get(name)

    def get_findings(self, category: Optional[str] = None) -> Dict[str, Any]:
        if category is None:
            return self.findings
        return {k: v for k, v in self.findings.items() if v.get("category") == category}

    def get_coverage_state(self) -> Dict[str, Any]:
        return self.coverage_state

    def is_in_scope(self, url: str) -> bool:
        for pattern in self.scope:
            if pattern.startswith("*."):
                domain = pattern[2:]
                if url == domain or url.endswith("." + domain):
                    return True
            elif re.fullmatch(pattern.replace("*", ".*"), url):
                return True
        return False

    def add_identity(self, name: str, data: Any) -> None:
        self.identities[name] = data

    def add_endpoint(self, name: str, data: Any) -> None:
        self.endpoints[name] = data

    def add_finding(self, key: str, data: Any) -> None:
        self.findings[key] = data
