from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class RankedCandidate(BaseModel):
    id: str
    score: float = Field(..., ge=0.0, le=1.0)
    justification: str

class RankedCandidatesResult(BaseModel):
    candidates: List[RankedCandidate]
    
class GeneratedPayload(BaseModel):
    value: str
    expected_behavior: str
    justification: str

class GeneratedPayloadsResult(BaseModel):
    payloads: List[GeneratedPayload]

class LLMResponse(BaseModel):
    reasoning_trace: Optional[str] = None
    structured_data: Dict[str, Any]
    raw_response: str
