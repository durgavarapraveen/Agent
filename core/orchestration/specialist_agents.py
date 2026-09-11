"""Phase 15.2 — Specialist agent teams with a shared evidence bus.

Bounded specialist roles communicating through structured artifacts, not
unconstrained chat history. Specialists cannot grant authority to each other.
Cross-agent disagreements are recorded and resolvable.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional

logger = logging.getLogger(__name__)


class SpecialistRole(str, Enum):
    RECON = "recon"
    WEB_SEMANTICS = "web_semantics"
    AUTHZ = "authz"
    WORKFLOW = "workflow"
    SOURCE_ANALYSIS = "source_analysis"
    BROWSER = "browser"
    PROTOCOL = "protocol"
    CLOUD_INFRA = "cloud_infra"
    VERIFICATION = "verification"


@dataclass(frozen=True)
class SpecialistCapability:
    role: SpecialistRole
    allowed_tools: FrozenSet[str] = frozenset()
    allowed_evidence_types: FrozenSet[str] = frozenset()
    max_concurrent_tasks: int = 5
    can_grant_authority: bool = False


@dataclass
class EvidenceArtifact:
    artifact_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    producer_role: SpecialistRole = SpecialistRole.RECON
    artifact_type: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    provenance: str = ""
    timestamp: float = field(default_factory=time.time)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id, "producer": self.producer_role.value,
            "type": self.artifact_type, "confidence": self.confidence,
            "provenance": self.provenance,
        }


@dataclass
class Disagreement:
    disagreement_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_a: SpecialistRole = SpecialistRole.RECON
    agent_b: SpecialistRole = SpecialistRole.RECON
    topic: str = ""
    claim_a: str = ""
    claim_b: str = ""
    resolved: bool = False
    resolution: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.disagreement_id, "agents": [self.agent_a.value, self.agent_b.value],
            "topic": self.topic, "resolved": self.resolved,
            "resolution": self.resolution,
        }


class EvidenceBus:
    """Typed, provenance-aware shared state for specialist agents."""

    def __init__(self):
        self._lock = threading.RLock()
        self._artifacts: Dict[str, EvidenceArtifact] = {}
        self._by_type: Dict[str, List[str]] = {}
        self._by_producer: Dict[str, List[str]] = {}

    def publish(self, artifact: EvidenceArtifact) -> str:
        with self._lock:
            self._artifacts[artifact.artifact_id] = artifact
            self._by_type.setdefault(artifact.artifact_type, []).append(artifact.artifact_id)
            self._by_producer.setdefault(artifact.producer_role.value, []).append(artifact.artifact_id)
        return artifact.artifact_id

    def consume(self, artifact_type: str = "", producer: Optional[SpecialistRole] = None,
                limit: int = 100) -> List[EvidenceArtifact]:
        with self._lock:
            if artifact_type:
                ids = self._by_type.get(artifact_type, [])
            elif producer:
                ids = self._by_producer.get(producer.value, [])
            else:
                ids = list(self._artifacts.keys())
            return [self._artifacts[aid] for aid in ids[-limit:] if aid in self._artifacts]

    def get(self, artifact_id: str) -> Optional[EvidenceArtifact]:
        return self._artifacts.get(artifact_id)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_artifacts": len(self._artifacts),
                "by_type": {k: len(v) for k, v in self._by_type.items()},
                "by_producer": {k: len(v) for k, v in self._by_producer.items()},
            }


class SpecialistAgent:
    """A bounded specialist with role-specific capabilities."""

    def __init__(self, role: SpecialistRole, capability: SpecialistCapability,
                 bus: EvidenceBus):
        self.role = role
        self.capability = capability
        self._bus = bus
        self._lock = threading.RLock()
        self._active_tasks = 0
        self._completed_tasks = 0

    def can_use_tool(self, tool_name: str) -> bool:
        return not self.capability.allowed_tools or tool_name in self.capability.allowed_tools

    def publish_evidence(self, artifact_type: str, data: Dict[str, Any],
                         confidence: float = 1.0, provenance: str = "") -> str:
        artifact = EvidenceArtifact(
            producer_role=self.role, artifact_type=artifact_type,
            data=data, confidence=confidence,
            provenance=provenance or f"agent:{self.role.value}",
        )
        return self._bus.publish(artifact)

    def consume_evidence(self, artifact_type: str = "",
                          limit: int = 100) -> List[EvidenceArtifact]:
        return self._bus.consume(artifact_type=artifact_type, limit=limit)

    def start_task(self) -> bool:
        with self._lock:
            if self._active_tasks >= self.capability.max_concurrent_tasks:
                return False
            self._active_tasks += 1
        return True

    def complete_task(self) -> None:
        with self._lock:
            self._active_tasks = max(0, self._active_tasks - 1)
            self._completed_tasks += 1

    def stats(self) -> Dict[str, Any]:
        return {
            "role": self.role.value, "active": self._active_tasks,
            "completed": self._completed_tasks,
        }


class SpecialistTeam:
    """Manages a team of specialist agents sharing an evidence bus."""

    def __init__(self):
        self._lock = threading.RLock()
        self._bus = EvidenceBus()
        self._agents: Dict[SpecialistRole, SpecialistAgent] = {}
        self._disagreements: List[Disagreement] = []

    def register_agent(self, role: SpecialistRole,
                        capability: Optional[SpecialistCapability] = None) -> SpecialistAgent:
        cap = capability or SpecialistCapability(role=role)
        if cap.can_grant_authority:
            raise ValueError("Specialists cannot grant authority to each other")
        agent = SpecialistAgent(role=role, capability=cap, bus=self._bus)
        with self._lock:
            self._agents[role] = agent
        return agent

    def get_agent(self, role: SpecialistRole) -> Optional[SpecialistAgent]:
        return self._agents.get(role)

    def record_disagreement(self, agent_a: SpecialistRole, agent_b: SpecialistRole,
                             topic: str, claim_a: str, claim_b: str) -> str:
        d = Disagreement(agent_a=agent_a, agent_b=agent_b, topic=topic,
                         claim_a=claim_a, claim_b=claim_b)
        with self._lock:
            self._disagreements.append(d)
        return d.disagreement_id

    def resolve_disagreement(self, disagreement_id: str, resolution: str) -> bool:
        with self._lock:
            for d in self._disagreements:
                if d.disagreement_id == disagreement_id:
                    d.resolved = True
                    d.resolution = resolution
                    return True
        return False

    def get_disagreements(self, resolved: Optional[bool] = None) -> List[Disagreement]:
        with self._lock:
            out = list(self._disagreements)
        if resolved is not None:
            out = [d for d in out if d.resolved == resolved]
        return out

    @property
    def bus(self) -> EvidenceBus:
        return self._bus

    def team_stats(self) -> Dict[str, Any]:
        return {
            "agents": {r.value: a.stats() for r, a in self._agents.items()},
            "bus": self._bus.stats(),
            "disagreements": {
                "total": len(self._disagreements),
                "unresolved": sum(1 for d in self._disagreements if not d.resolved),
            },
        }
