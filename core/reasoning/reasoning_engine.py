from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Hypothesis:
    id: str
    description: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReasoningEngine:

    def __init__(self, llm_client: Any = None) -> None:
        self.llm_client = llm_client

    def propose_hypothesis(self, context: Dict[str, Any]) -> List[Hypothesis]:
        hypotheses = []
        findings = context.get("findings", {})
        endpoints = context.get("endpoints", {})

        for key, finding in findings.items():
            h = Hypothesis(
                id=f"hyp-{key}",
                description=f"Investigate finding: {finding.get('title', key)}",
                confidence=finding.get("confidence", 0.5),
                evidence=[key],
            )
            hypotheses.append(h)

        for name, ep in endpoints.items():
            if any(p in name.lower() for p in ("admin", "auth", "login", "api")):
                h = Hypothesis(
                    id=f"hyp-ep-{name}",
                    description=f"Test sensitive endpoint: {name}",
                    confidence=0.6,
                    evidence=[name],
                )
                hypotheses.append(h)

        return hypotheses

    def rank_hypotheses(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)

    def explain_reasoning(self, hypothesis: Hypothesis) -> str:
        parts = [f"Hypothesis: {hypothesis.description}"]
        parts.append(f"Confidence: {hypothesis.confidence:.0%}")
        if hypothesis.evidence:
            parts.append(f"Evidence: {', '.join(hypothesis.evidence)}")
        return " | ".join(parts)
