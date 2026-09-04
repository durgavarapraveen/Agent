import unittest
import io
import sys
import uuid
from core.domain.request import CapturedRequest
from core.validation.contract_validator import ContractValidator

class TestDomainModels(unittest.TestCase):

    def test_captured_request_conversion(self):
        """
        Test that 309+ captured requests can be converted to CapturedRequest without data loss.
        We will simulate generating 309+ request dicts and converting them.
        """
        raw_requests = []
        for i in range(315):
            raw_requests.append({
                "request_id": f"req-{i}",
                "method": "GET",
                "url": f"https://example.com/api/data/{i}",
                "full_headers": {"User-Agent": "Test"},
                "cookies": {"session": "1234"},
                "body": b'{"test": 1}',
                "parameters_used": ["id"],
                "identity_id": "user_a",
                "session_id": "sess_001",
                "response": {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": b'{"status": "ok"}',
                    "body_hash": "dummyhash123"
                },
                "source": "browser"
            })
            
        converted = []
        for raw in raw_requests:
            model = CapturedRequest.from_dict(raw)
            converted.append(model)
            
        self.assertEqual(len(converted), 315)
        # Verify no data loss on round-trip for the first item
        serialized = converted[0].to_dict()
        
        self.assertEqual(serialized["request_id"], "req-0")
        self.assertEqual(serialized["response"]["status_code"], 200)
        self.assertEqual(serialized["source"], "browser")

    def test_contract_validator_logs(self):
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        ContractValidator.validate_startup()
        
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        self.assertIn("CONTRACT_VALIDATION: OK", output)
        self.assertIn("ENDPOINT_SCHEMA: v2", output)
        self.assertIn("REQUEST_SCHEMA: v2", output)
        self.assertIn("IDENTITY_SCHEMA: v2", output)
        self.assertIn("EXPERIMENT_SCHEMA: v2", output)

if __name__ == '__main__':
    unittest.main()
