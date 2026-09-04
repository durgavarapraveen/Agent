"""
SecurityHypothesis model (Phase 22).

A hypothesis is a testable claim about a target's vulnerability.
Generated from attack surface analysis, technology detection, and
prior experiment results. Each hypothesis spawns one or more experiments.
"""
from core.domain.base import DomainModel
from pydantic import Field
from typing import Any, Dict, List, Optional


class HypothesisState:
    PROPOSED = "PROPOSED"
    ACCEPTED = "ACCEPTED"
    TESTING = "TESTING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class SecurityHypothesis(DomainModel):
    title: str = Field(...)
    rationale: str = Field(...)
    expected_signals: List[str] = Field(default_factory=list)
    test_id: str = Field(...)
    endpoint_id: Optional[str] = Field(default=None)
    identity_ids: List[str] = Field(default_factory=list)
    status: str = Field(default=HypothesisState.PROPOSED)
    priority: float = Field(default=0.5)
    attack_type: str = Field(default="")
    technology_hint: str = Field(default="")
    payload_ids: List[str] = Field(default_factory=list)
    experiment_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    parent_hypothesis_id: Optional[str] = Field(default=None)
    generation_method: str = Field(default="manual")
    feedback: Dict[str, Any] = Field(default_factory=dict)
