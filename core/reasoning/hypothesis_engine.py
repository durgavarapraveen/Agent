from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, List, Tuple

from core.coverage.security_test_catalog import SecurityTestCatalog


@dataclass
class Hypothesis:
    hypothesis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    test_id: str = ""
    endpoint_id: str = ""
    priority: float = 0.5
    reasoning: str = ""
    prerequisites: List[str] = field(default_factory=list)


CATEGORY_PRIORITY = {
    "sqli": 0.95,
    "authentication": 0.9,
    "authorization": 0.9,
    "xss": 0.85,
    "command_injection": 0.85,
    "ssrf": 0.8,
    "path_traversal": 0.8,
    "xxe": 0.75,
    "ssti": 0.75,
    "file_upload": 0.7,
    "jwt": 0.7,
    "csrf": 0.65,
    "cors": 0.6,
    "nosqli": 0.7,
    "business_logic": 0.6,
    "info_disclosure": 0.5,
}


class HypothesisEngine:

    def __init__(self, test_catalog: SecurityTestCatalog, attack_surface: Any = None, llm_client: Any = None) -> None:
        self.catalog = test_catalog
        self.attack_surface = attack_surface
        self.llm_client = llm_client

    def generate(self, coverage_gaps: List[Tuple[str, str]], attack_surface: Any = None) -> List[Hypothesis]:
        hypotheses = []
        for endpoint_id, test_id in coverage_gaps:
            test = self.catalog.get(test_id)
            if not test:
                continue
            priority = CATEGORY_PRIORITY.get(test.attack_type, 0.5)
            h = Hypothesis(
                test_id=test_id,
                endpoint_id=endpoint_id,
                priority=priority,
                reasoning=f"Coverage gap: {test.name} on {endpoint_id} (CWE-{test.cwe})",
            )
            hypotheses.append(h)
        return hypotheses

    def rank(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        return sorted(hypotheses, key=lambda h: h.priority, reverse=True)
