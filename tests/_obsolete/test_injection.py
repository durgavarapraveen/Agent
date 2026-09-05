import unittest
from core.domain.endpoint import Endpoint
from core.injection.eligibility import InjectionEligibilityChecker
from core.injection.injection_matrix import InjectionMatrix
from core.injection.injection_executor import InjectionExecutor
from core.injection.injection_reporter import InjectionReporter
from core.injection.models import TestStatus

class TestInjectionMatrix(unittest.TestCase):
    def setUp(self):
        # Create 69 mock endpoints
        self.endpoints = []
        for i in range(69):
            ep = Endpoint(
                endpoint_id=f"EP-{i}",
                path=f"/api/v1/resource/{i}",
                url=f"https://target.com/api/v1/resource/{i}",
                method_set={"GET"} if i % 2 == 0 else {"POST"}
            )
            self.endpoints.append(ep)

    def test_build_matrix(self):
        matrix_builder = InjectionMatrix()
        matrix = matrix_builder.build_matrix(self.endpoints)
        
        self.assertEqual(matrix.endpoints, 69)
        # We mocked the param evaluation to return 2 parameters tested per endpoint,
        # but the logic only adds them if applicable.
        # So we just ensure it populated tests.
        self.assertGreater(matrix.eligible_parameters, 0)
        self.assertIn("sqli", matrix.tests_by_type)
        self.assertIn("xss_reflected", matrix.tests_by_type)

    def test_execution_and_oracles(self):
        executor = InjectionExecutor()
        
        # Test XSS Reflected (should be CONFIRMED because mock executes reflection)
        ep = self.endpoints[0]
        ep.method_set = {"GET"}
        tests = InjectionEligibilityChecker.is_eligible(ep, "q", "text/html", None)
        xss_test = next(t for t in tests if t.test_type == "xss_reflected")
        
        res = executor.execute(xss_test, ep)
        self.assertEqual(res.status, TestStatus.CONFIRMED)
        self.assertEqual(res.oracle_used, "reflection")
        
        # Test SSTI (should be REJECTED because mock does not execute templates)
        ssti_ep = self.endpoints[1]
        ssti_ep.method_set = {"POST"}
        ssti_tests = InjectionEligibilityChecker.is_eligible(ssti_ep, "template", "text/html", None)
        ssti_test = next(t for t in ssti_tests if t.test_type == "ssti")
        
        res_ssti = executor.execute(ssti_test, ssti_ep)
        self.assertEqual(res_ssti.status, TestStatus.REJECTED)

    def test_reporter(self):
        matrix_builder = InjectionMatrix()
        matrix = matrix_builder.build_matrix(self.endpoints[:10]) # Use a subset
        
        # Manually force some stats to match the specific report requirements
        matrix.endpoints = 69
        matrix.eligible_parameters = 25
        
        matrix.status_by_type["sqli"] = {"tested": 18, "confirmed": 3, "rejected": 15, "blocked": 0}
        matrix.status_by_type["xss_reflected"] = {"tested": 12, "confirmed": 2}
        matrix.status_by_type["xss_dom"] = {"tested": 8, "confirmed": 1}
        matrix.status_by_type["xss_stored"] = {"tested": 5, "confirmed": 0}
        matrix.status_by_type["ssti"] = {"tested": 4, "confirmed": 0, "rejected": 4}
        matrix.status_by_type["command"] = {"tested": 3, "confirmed": 0}
        matrix.status_by_type["path_traversal"] = {"tested": 6, "confirmed": 1}
        
        report = InjectionReporter.generate_report(matrix)
        
        self.assertIn("endpoints=69", report)
        self.assertIn("eligible_parameters=25", report)
        self.assertIn("tested=18", report.split("SQLI")[1].split("XSS")[0])
        self.assertIn("confirmed=3", report.split("SQLI")[1].split("XSS")[0])
        self.assertIn("reflected_tested=12", report)

if __name__ == '__main__':
    unittest.main()
