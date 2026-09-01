from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class TestState(str, Enum):
    NOT_TESTED = "NOT_TESTED"
    READY = "READY"
    RUNNING = "RUNNING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SecurityTestDefinition(BaseModel):
    """
    Deterministic definition of a security coverage test.
    """
    test_id: str
    category: str
    description: str
    prerequisites: List[str] = Field(default_factory=list)
    applicability_rules: List[Dict[str, Any]] = Field(default_factory=list)
    execution_strategies: List[str] = Field(default_factory=list)
    required_evidence: List[str] = Field(default_factory=list)
    oracle: str  # e.g. "regex_match" or programmatic description 
    risk_level: str
