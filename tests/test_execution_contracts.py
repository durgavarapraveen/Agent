import time
import pytest
from core.security.execution_contract import ExecutionContract
from core.security.platform_contract import ContractViolation
from core.security.authorization_authority import AuthorizationAuthority, AuthorizationScope
from core.security.policy_engine import PolicyEngine

def test_contract_signing_and_verification():
    contract = ExecutionContract(
        scan_id="scan-123",
        experiment_id="exp-456",
        target="example.com",
        capability="nmap",
        identity="agent-1",
        impact_class="safe",
        budget=100,
        expiry_ts=time.time() + 3600,
        authorization_ref="auth-789"
    )
    
    # Contract should fail without a signature
    with pytest.raises(ContractViolation, match="missing a signature"):
        contract.verify()
        
    signed_contract = contract.sign()
    
    # Verification should succeed
    assert signed_contract.verify() is True
    
def test_contract_tampering():
    contract = ExecutionContract(
        scan_id="scan-1",
        experiment_id="exp-1",
        target="example.com",
        capability="nmap",
        identity="agent-1",
        impact_class="safe",
        budget=100,
        expiry_ts=time.time() + 3600,
        authorization_ref="auth-1"
    ).sign()
    
    # Tamper with the target
    object.__setattr__(contract, "target", "evil.com")
    
    with pytest.raises(ContractViolation, match="tampering detected"):
        contract.verify()

def test_contract_expiry():
    contract = ExecutionContract(
        scan_id="scan-1",
        experiment_id="exp-1",
        target="example.com",
        capability="nmap",
        identity="agent-1",
        impact_class="safe",
        budget=100,
        expiry_ts=time.time() - 10, # Expired 10 seconds ago
        authorization_ref="auth-1"
    ).sign()
    
    with pytest.raises(ContractViolation, match="Contract expired"):
        contract.verify()

def test_policy_engine_integration():
    auth_authority = AuthorizationAuthority.get()
    
    # Setup an authorized scope
    scope = AuthorizationScope(
        hosts={"example.com"},
        capabilities={"nmap"},
        identities={"agent-1"},
        request_budget=10,
        lab_mode=False
    )
    auth_authority.register_scope("auth-123", scope)
    
    contract = ExecutionContract(
        scan_id="scan-1",
        experiment_id="exp-1",
        target="example.com",
        capability="nmap",
        identity="agent-1",
        impact_class="safe",
        budget=1,
        expiry_ts=time.time() + 3600,
        authorization_ref="auth-123"
    ).sign()
    
    engine = PolicyEngine.get()
    
    # Should allow
    decision = engine.authorize_contract(contract)
    assert decision.allowed is True
    
    # Create a contract with bad target
    bad_contract = ExecutionContract(
        scan_id="scan-2",
        experiment_id="exp-2",
        target="evil.com", # out of scope
        capability="nmap",
        identity="agent-1",
        impact_class="safe",
        budget=1,
        expiry_ts=time.time() + 3600,
        authorization_ref="auth-123"
    ).sign()
    
    decision = engine.authorize_contract(bad_contract)
    assert decision.allowed is False
    assert decision.reason_code == "TARGET_OUT_OF_SCOPE"
