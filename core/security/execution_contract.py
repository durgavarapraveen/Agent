from __future__ import annotations

import hmac
import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional

from core.security.encryption import get_encryption_key
from core.security.platform_contract import ContractViolation

@dataclass(frozen=True)
class ExecutionContract:
    scan_id: str
    experiment_id: str
    target: str
    capability: str
    identity: str
    impact_class: str
    budget: int
    expiry_ts: float
    authorization_ref: str
    signature: str = ""

    def _get_signing_payload(self) -> bytes:
        """Returns deterministic representation of the contract minus signature."""
        d = asdict(self)
        d.pop("signature", None)
        # Sort keys to ensure deterministic serialization
        payload_str = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return payload_str.encode("utf-8")

    def sign(self, key: Optional[bytes] = None) -> "ExecutionContract":
        """Returns a new ExecutionContract with the cryptographic signature applied."""
        if not key:
            key = get_encryption_key()
        
        payload = self._get_signing_payload()
        sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
        
        # We must return a new instance because dataclass is frozen
        return ExecutionContract(
            scan_id=self.scan_id,
            experiment_id=self.experiment_id,
            target=self.target,
            capability=self.capability,
            identity=self.identity,
            impact_class=self.impact_class,
            budget=self.budget,
            expiry_ts=self.expiry_ts,
            authorization_ref=self.authorization_ref,
            signature=sig
        )

    def verify(self, key: Optional[bytes] = None) -> bool:
        """
        Verifies the contract hasn't been tampered with and hasn't expired.
        Raises ContractViolation on failure.
        """
        if not key:
            key = get_encryption_key()

        if not self.signature:
            raise ContractViolation("execution_contract.verify", "Contract is missing a signature")

        payload = self._get_signing_payload()
        expected_sig = hmac.new(key, payload, hashlib.sha256).hexdigest()

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(self.signature, expected_sig):
            raise ContractViolation("execution_contract.tamper", "Contract signature validation failed (tampering detected)")

        if time.time() > self.expiry_ts:
            raise ContractViolation("execution_contract.expired", f"Contract expired at {self.expiry_ts}")

        return True
