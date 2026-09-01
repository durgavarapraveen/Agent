import logging
from core.common.llm_schemas import LLMDecision, LLMHypothesis
from core.intelligence.decision_guard import DecisionGuard
from core.memory.shared_context_v2 import SharedContextV2
from core.memory.failure_store import FailureStore
from core.memory.strategy_store import StrategyStore
from core.intelligence.llm_context_builder import LLMContextBuilder

logging.basicConfig(level=logging.INFO)

def test_integration():
    print("Starting integration test...")
    
    # 1. Setup shared context
    context = SharedContextV2(target="example.com")
    context.endpoints = [{"id": "ep_1", "url": "/login"}]
    context.target_fingerprint = "fp_123"
    
    builder = LLMContextBuilder(context)
    llm_context = builder.build_context("hypothesis_generation")
    assert "target_profile" in llm_context
    assert "observations" in llm_context
    print("Context sliced successfully.")
    
    failure_store = FailureStore()
    strategy_store = StrategyStore()
    scope_config = {"allowed_domains": ["example.com"]}
    
    guard = DecisionGuard(failure_store, strategy_store, scope_config)

    # 2. Simulate valid LLM decision
    mock_decision = LLMDecision(
        action="run_tests",
        confidence=0.8,
        hypotheses=[
            LLMHypothesis(
                hypothesis_id="hyp_1",
                test_id="test_sqli",
                endpoint_id="example.com/login",
                rationale="Testing SQL injection.",
                expected_signals=["SQL syntax error"],
                priority=0.9
            )
        ]
    )
    
    safe_decision = guard.validate_decision(mock_decision, context.target_fingerprint)
    assert safe_decision is not None, "Valid decision should be accepted."
    print("First run valid decision accepted.")

    # 3. Simulate failure recording
    failure_store.record_failure(
        hypothesis="SQLi login", 
        strategy="fuzzing", 
        tool="sqlmap", 
        failure_reason="WAF blocked",
        target_fingerprint="fp_123",
        endpoint_pattern="/login"
    )
    
    assert failure_store.has_failed_before("fuzzing", "fp_123") is True
    print("Failure recorded and retrieved.")

    # 4. Simulate guard rejecting duplicate failed strategy
    mock_decision_fail = LLMDecision(
        action="run_tests",
        confidence=0.8,
        hypotheses=[
            LLMHypothesis(
                hypothesis_id="hyp_2",
                test_id="fuzzing",
                endpoint_id="example.com/login",
                rationale="Retrying fuzzing.",
                expected_signals=[],
                priority=0.9
            )
        ]
    )
    
    safe_decision2 = guard.validate_decision(mock_decision_fail, context.target_fingerprint)
    assert safe_decision2 is None, "Decision should be rejected due to previous failure."
    print("Duplicate strategy correctly rejected by DecisionGuard.")

    # 5. Simulate guard rejecting out of scope
    mock_decision_oos = LLMDecision(
        action="run_tests",
        confidence=0.8,
        hypotheses=[
            LLMHypothesis(
                hypothesis_id="hyp_3",
                test_id="scan",
                endpoint_id="outofscope.com",
                rationale="Scanning outside.",
                expected_signals=[],
                priority=0.9
            )
        ]
    )
    safe_decision3 = guard.validate_decision(mock_decision_oos, context.target_fingerprint)
    assert safe_decision3 is None, "Decision should be rejected due to out of scope."
    print("Out of scope correctly rejected by DecisionGuard.")
    
    print("All integration tests passed.")

if __name__ == "__main__":
    test_integration()
