"""
Canonical Finding model — single authoritative definition.

Finding lifecycle: DISCOVERED → VALIDATING → CONFIRMED / REJECTED / INCONCLUSIVE

All other Finding definitions (core.common.models, core.domain.finding) should
import from here or use backward-compat aliases.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingState(Enum):
    DISCOVERED = "discovered"
    NORMALIZED = "normalized"
    DEDUPLICATED = "deduplicated"
    VALIDATION_PENDING = "validation_pending"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"
    REPORTABLE = "reportable"
    SUPPRESSED = "suppressed"


class FindingSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    title: str
    description: str
    severity: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: str = FindingState.DISCOVERED.value
    category: str = ""
    cwe: str = ""
    cve: str = ""
    affected_asset: str = ""
    affected_endpoint: str = ""
    parameter: str = ""
    identity: str = ""
    source: str = ""
    discovery_method: str = ""
    confidence: float = 0.0
    evidence_ids: List[str] = field(default_factory=list)
    proof: str = ""
    rejection_reason: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    @property
    def state_enum(self) -> FindingState:
        try:
            return FindingState(self.state)
        except ValueError:
            return FindingState.DISCOVERED

    def update_state(self, new_state: FindingState) -> None:
        self.state = new_state.value
        self.updated_at = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "state": self.state,
            "category": self.category,
            "cwe": self.cwe,
            "cve": self.cve,
            "affected_asset": self.affected_asset,
            "affected_endpoint": self.affected_endpoint,
            "parameter": self.parameter,
            "identity": self.identity,
            "source": self.source,
            "discovery_method": self.discovery_method,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "proof": self.proof,
            "rejection_reason": self.rejection_reason,
            "remediation": self.remediation,
            "references": self.references,
            "related_findings": self.related_findings,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Finding:
        return cls(
            finding_id=d.get("finding_id", str(uuid.uuid4())),
            title=d["title"],
            description=d.get("description", ""),
            severity=d.get("severity", "INFO"),
            state=d.get("state", FindingState.DISCOVERED.value),
            category=d.get("category", ""),
            cwe=d.get("cwe", ""),
            cve=d.get("cve", ""),
            affected_asset=d.get("affected_asset", ""),
            affected_endpoint=d.get("affected_endpoint", ""),
            parameter=d.get("parameter", ""),
            identity=d.get("identity", ""),
            source=d.get("source", ""),
            discovery_method=d.get("discovery_method", ""),
            confidence=d.get("confidence", 0.0),
            evidence_ids=d.get("evidence_ids", []),
            proof=d.get("proof", ""),
            rejection_reason=d.get("rejection_reason"),
            remediation=d.get("remediation", ""),
            references=d.get("references", []),
            related_findings=d.get("related_findings", []),
            metadata=d.get("metadata", {}),
        )
