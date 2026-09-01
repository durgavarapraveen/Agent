import unittest
from unittest.mock import patch, MagicMock
import json
from core.domain.endpoint import Endpoint
from core.llm.llm_router import LLMRouter
from core.llm.schemas import RankedCandidatesResult, GeneratedPayloadsResult
from core.llm.context_builder import ContextBuilder

class TestLLMRouter(unittest.TestCase):
    def setUp(self):
        self.router = LLMRouter(api_key="mock_key")
        self.endpoint = Endpoint(
            endpoint_id="EP-1",
            path="/api/login",
            url="https://target.com/api/login",
            method_set={"POST"}
        )

    @patch("core.llm.llm_router.requests.post")
    def test_hypothesis_ranking_success(self, mock_post):
        # Mock DeepSeek API response structure
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "reasoning_content": "Hypothesis 1 is most likely because the endpoint accepts SQL parameters.",
                    "content": json.dumps({
                        "candidates": [
                            {"id": "H-1", "score": 0.95, "justification": "High probability of SQLi"},
                            {"id": "H-2", "score": 0.10, "justification": "Low probability"}
                        ]
                    })
                }
            }]
        }
        mock_post.return_value = mock_response
        
        context = ContextBuilder.build_for_hypothesis_ranking(self.endpoint, [], [])
        response = self.router.route_task("hypothesis_ranking", context, ["H-1", "H-2"])
        
        self.assertIn("most likely because the endpoint", response.reasoning_trace)
        
        # Parse into Pydantic schema
        parsed = self.router.parse_llm_response(response, RankedCandidatesResult)
        self.assertEqual(len(parsed.candidates), 2)
        self.assertEqual(parsed.candidates[0].id, "H-1")
        self.assertEqual(parsed.candidates[0].score, 0.95)

    @patch("core.llm.llm_router.requests.post")
    def test_llm_error_fallback(self, mock_post):
        # Force a timeout/500 error
        mock_post.side_effect = Exception("Connection Timeout")
        
        context = ContextBuilder.build_for_hypothesis_ranking(self.endpoint, [], [])
        response = self.router.route_task("hypothesis_ranking", context, [{"id": "H-1"}, {"id": "H-2"}])
        
        # Ensure it didn't crash and returned the fallback reasoning
        self.assertEqual(response.reasoning_trace, "LLM Failed. Fallback executed.")
        
        # Ensure fallback data parses properly
        parsed = self.router.parse_llm_response(response, RankedCandidatesResult)
        self.assertEqual(len(parsed.candidates), 2)
        
        # The fallback heuristic gives decreasing scores
        self.assertEqual(parsed.candidates[0].id, "H-1")
        self.assertEqual(parsed.candidates[0].score, 1.0)
        self.assertEqual(parsed.candidates[1].score, 0.9)

if __name__ == '__main__':
    unittest.main()
