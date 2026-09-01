from pydantic import BaseModel, Field
from typing import List, Optional


class LLMHypothesis(BaseModel):
    hypothesis_id: str
    test_id: str
    endpoint_id: Optional[str] = None
    identity_ids: List[str] = Field(default_factory=list)
    rationale: str
    expected_signals: List[str] = Field(default_factory=list)
    priority: float


class LLMDecision(BaseModel):
    action: str
    hypotheses: List[LLMHypothesis] = Field(default_factory=list)
    confidence: float


class LLMExperimentSuggestion(BaseModel):
    test_id: str
    strategy_id: str
    rationale: str
    expected_signal: List[str] = Field(default_factory=list)
    priority: float
