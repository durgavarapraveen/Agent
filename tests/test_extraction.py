import unittest
from core.extraction.endpoint_extractor import EndpointExtractor
from core.extraction.parameter_extractor import ParameterExtractor
from core.domain.request import CapturedRequest, ResponseData
from core.domain.parameter import ParameterType

class TestExtraction(unittest.TestCase):
    def test_parameter_inference(self):
        req = CapturedRequest(
            request_id="REQ-1",
            method="POST",
            url="https://api.com/search?q=test&limit=10",
            full_headers={"Authorization": "Bearer token", "X-Custom": "value"},
            body=b'{"user_id": 42, "is_active": true}',
            identity_id="user_a",
            response=ResponseData(status_code=200)
        )
        
        params = ParameterExtractor.extract_from_request(req)
        
        # Check query params
        q_param = next(p for p in params if p.name == "q")
        self.assertEqual(q_param.parameter_type, ParameterType.QUERY)
        self.assertEqual(q_param.inferred_data_type, "string")
        
        limit_param = next(p for p in params if p.name == "limit")
        self.assertEqual(limit_param.inferred_data_type, "int")
        
        # Check body params
        user_id_param = next(p for p in params if p.name == "user_id")
        self.assertEqual(user_id_param.parameter_type, ParameterType.BODY)
        self.assertEqual(user_id_param.inferred_data_type, "int")
        
        active_param = next(p for p in params if p.name == "is_active")
        self.assertEqual(active_param.inferred_data_type, "bool")
        
    def test_endpoint_deduplication(self):
        extractor = EndpointExtractor()
        
        reqs = [
            CapturedRequest(
                request_id="REQ-1",
                method="GET",
                url="https://api.com/v1/users/1",
                full_headers={"Authorization": "Bearer token"},
                identity_id="user_a",
                response=ResponseData(status_code=200)
            ),
            CapturedRequest(
                request_id="REQ-2",
                method="GET",
                url="https://api.com/v2/users/2",
                full_headers={"Authorization": "Bearer token"},
                identity_id="user_a",
                response=ResponseData(status_code=200)
            ),
            CapturedRequest(
                request_id="REQ-3",
                method="POST",
                url="https://api.com/v1/users/1",
                full_headers={},
                identity_id="anonymous",
                response=ResponseData(status_code=200)
            )
        ]
        
        endpoints = extractor.extract(reqs)
        
        # They should all merge into /users/{id}
        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        
        self.assertEqual(ep.path, "/users/{id}")
        self.assertIn("GET", ep.method_set)
        self.assertIn("POST", ep.method_set)
        
        self.assertTrue(ep.auth_required)
        self.assertEqual(len(ep.auth_contexts), 1)
        self.assertEqual(ep.auth_contexts[0].identity_id, "user_a")
        
    def test_confidence_scoring(self):
        extractor = EndpointExtractor()
        
        # 1 observation -> 0.55 (0.5 + 1 * 0.05)
        # Wait, the formula is min(1.0, 0.5 + count * 0.05)
        # In extract, discovered_endpoints increments by 1 per request.
        
        reqs = [
            CapturedRequest(
                request_id=f"REQ-{i}",
                method="GET",
                url="https://api.com/status",
                response=ResponseData(status_code=200)
            ) for i in range(12)
        ]
        
        endpoints = extractor.extract(reqs)
        self.assertEqual(len(endpoints), 1)
        
        ep = endpoints[0]
        self.assertEqual(ep.discovered_endpoints, 12)
        self.assertEqual(ep.confidence, 1.0) # maxes out at 1.0

if __name__ == '__main__':
    unittest.main()
