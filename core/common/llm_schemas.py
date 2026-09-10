from pydantic import BaseModel, Field
from typing import List, Optional

class LLMHypothesis(BaseModel):
    hypothesis_id: str = Field(...)
    test_id: str = Field(...)
    endpoint_id: Optional[str] = Field(default=None)
    identity_ids: List[str] = Field(default_factory=list)
    rationale: str = Field(...)
    expected_signals: List[str] = Field(default_factory=list)
    priority: float = Field(default=0.5, ge=0.0, le=1.0)

class LLMDecision(BaseModel):
    action: str = Field(...)
    hypotheses: List[LLMHypothesis] = Field(default_factory=list)
    reasoning: str = Field(...)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)

class HypothesisProposal(BaseModel):
    hypothesis_id: str = Field(...)
    test_id: str = Field(...)
    endpoint_id: Optional[str] = Field(default=None)
    identity_ids: List[str] = Field(default_factory=list)
    rationale: str = Field(...)
    expected_signal: List[str] = Field(default_factory=list)
    priority: float = Field(default=0.5, ge=0.0, le=1.0)

class DeepSeekMetrics(BaseModel):
    llm_calls: int = 0
    valid_outputs: int = 0
    invalid_outputs: int = 0
    retries: int = 0
    deterministic_fallbacks: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    average_latency_ms: float = 0.0
