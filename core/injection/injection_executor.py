from typing import List, Tuple
from core.injection.models import InjectionTest, InjectionResult, TestStatus
from core.injection.payloads import PayloadGenerator
from core.injection.tool_router import InjectionToolRouter
from core.injection.oracles.oracles import ReflectionOracle, DifferentialResponseOracle
from core.domain.request import ResponseData
from core.domain.endpoint import Endpoint
import time

class InjectionExecutor:
    def __init__(self):
        self.router = InjectionToolRouter()
        self.oracles = {
            "reflection": ReflectionOracle(),
            "differential": DifferentialResponseOracle()
        }
        
    def execute(self, test: InjectionTest, endpoint: Endpoint) -> InjectionResult:
        """
        Orchestrates payload generation, tool routing, and oracle validation.
        """
        # 1. Select Tools (Mocked usage here)
        tools = self.router.select_tools(test)
        
        # 2. Generate payloads based on test_type
        if "sqli" in test.test_type:
            payloads = PayloadGenerator.generate_sql_payloads("query")
        elif "xss" in test.test_type:
            payloads = PayloadGenerator.generate_xss_payloads()
        elif "ssti" in test.test_type:
            payloads = PayloadGenerator.generate_ssti_payloads()
        elif "command" in test.test_type:
            payloads = PayloadGenerator.generate_command_payloads()
        elif "path_traversal" in test.test_type:
            payloads = PayloadGenerator.generate_path_traversal_payloads()
        else:
            payloads = []
            
        if not payloads:
            test.status = TestStatus.INCONCLUSIVE
            return InjectionResult(test_id=test.test_id, status=TestStatus.INCONCLUSIVE, evidence="No payloads generated")

        # 3. Simulate execution and oracle application
        for payload in payloads:
            oracle_type = payload.oracle_hints.get("type")
            oracle = self.oracles.get(oracle_type)
            
            if not oracle:
                continue
                
            # MOCK: We simulate a positive response if the payload expected behavior matches test design
            # In real execution, this sends the payload via the ReplayEngine or FuzzerAdapter
            simulated_response = ResponseData(status_code=500, body=payload.value.encode()) if "execution" in payload.expected_behavior or "reads passwd" in payload.expected_behavior else ResponseData(status_code=200, body=b"OK")
            baseline = ResponseData(status_code=200, body=b"OK")
            
            if oracle.validate(simulated_response, payload.value, baseline, endpoint):
                test.status = TestStatus.CONFIRMED
                return InjectionResult(
                    test_id=test.test_id, 
                    status=TestStatus.CONFIRMED, 
                    evidence=f"Payload {payload.value} triggered {oracle_type} oracle",
                    oracle_used=oracle_type,
                    timestamp=time.time()
                )

        test.status = TestStatus.REJECTED
        return InjectionResult(
            test_id=test.test_id, 
            status=TestStatus.REJECTED, 
            evidence="All payloads exhausted without oracle match",
            timestamp=time.time()
        )
