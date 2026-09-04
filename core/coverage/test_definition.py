from core.domain.base import DomainModel
from core.domain.endpoint import Endpoint
from pydantic import Field, validator
from typing import List, Dict, Any, Callable

class ApplicabilityRule(DomainModel):
    condition: str = Field(...)
    parameters: Dict[str, str] = Field(default_factory=dict)
    
    def evaluate(self, endpoint: Endpoint) -> bool:
        """
        Abstract evaluation method. Actual implementation provided by the 
        CoverageEngine's rule registry mapped to the condition string.
        """
        raise NotImplementedError("evaluate() must be implemented or delegated to a registry.")

class SecurityTestDefinition(DomainModel):
    test_id: str = Field(...)
    category: str = Field(...)
    description: str = Field(...)
    prerequisites: List[str] = Field(default_factory=list)
    applicability_rules: List[ApplicabilityRule] = Field(default_factory=list)
    execution_strategies: List[str] = Field(default_factory=list)
    required_evidence: List[str] = Field(default_factory=list)
    oracle: str = Field(...)
    risk_level: str = Field(default="medium")

    @validator('category')
    def validate_category(cls, v):
        valid_categories = {
            "authentication", "authorization", "session", "identity", "access_control",
            "input_validation", "sql_injection", "nosql_injection", "xss", "ssti",
            "command_injection", "csrf", "cors", "ssrf", "xxe", "path_traversal",
            "file_upload", "file_download", "jwt", "graphql", "api_security",
            "business_logic", "race_condition", "secrets", "information_disclosure",
            "misconfiguration", "cryptography", "client_side", "dependency", "websocket"
        }
        if v not in valid_categories:
            raise ValueError(f"Category '{v}' is not in the recognized categories list.")
        return v
    
    @validator('risk_level')
    def validate_risk(cls, v):
        if v not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"Risk level '{v}' is invalid.")
        return v
