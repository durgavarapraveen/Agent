from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from core.evidence.evidence import Evidence
from core.evidence.oracle import Oracle

ORACLE_CONFIDENCE = {
    "differential_response": 0.7,
    "error_signature": 0.85,
    "timing_difference": 0.5,
    "reflection": 0.8,
    "dom_execution": 0.9,
}


@dataclass
class ValidationResult:
    valid: bool
    confidence: float
    reason: str


class EvidenceValidator:

    def validate(self, evidence: Evidence, oracle: Oracle, expected_signal: str) -> ValidationResult:
        if not evidence.is_credible():
            return ValidationResult(valid=False, confidence=0.0, reason="Evidence not credible")

        response: Dict[str, Any] = {
            "body": evidence.stdout,
            "stderr": evidence.stderr,
        }

        confirmed, oracle_name = oracle.apply(response, evidence)

        if confirmed:
            confidence = ORACLE_CONFIDENCE.get(oracle_name, 0.6)
            return ValidationResult(
                valid=True,
                confidence=confidence,
                reason=f"Oracle '{oracle_name}' confirmed signal '{expected_signal}'",
            )

        return ValidationResult(
            valid=False,
            confidence=0.0,
            reason=f"Oracle '{oracle_name}' did not confirm signal '{expected_signal}'",
        )
