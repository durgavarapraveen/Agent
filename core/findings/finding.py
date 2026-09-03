from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingState(Enum):
    DISCOVERED = "discovered"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Finding:
    title: str
    description: str
    severity: str
    cwe: str = ""
    affected_endpoint: str = ""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: str = FindingState.DISCOVERED.value
    evidence_ids: List[str] = field(default_factory=list)
    rejection_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def state_enum(self) -> FindingState:
        return FindingState(self.state)

    def update_state(self, new_state: FindingState) -> None:
        self.state = new_state.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cwe": self.cwe,
            "affected_endpoint": self.affected_endpoint,
            "state": self.state,
            "evidence_ids": self.evidence_ids,
            "rejection_reason": self.rejection_reason,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Finding:
        return cls(
            finding_id=d["finding_id"],
            title=d["title"],
            description=d["description"],
            severity=d["severity"],
            cwe=d.get("cwe", ""),
            affected_endpoint=d.get("affected_endpoint", ""),
            state=d.get("state", FindingState.DISCOVERED.value),
            evidence_ids=d.get("evidence_ids", []),
            rejection_reason=d.get("rejection_reason"),
            metadata=d.get("metadata", {}),
        )
