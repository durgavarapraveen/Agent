import unittest
import sys
import io
import logging
import uuid

from core.attack_surface.graph import AttackSurfaceGraph, NodeType, EdgeType, CanonicalEndpoint
from core.attack_surface.endpoint_inventory import EndpointInventory
from core.attack_surface.request_inventory import RequestInventory
from core.attack_surface.parameter_inventory import ParameterInventory
from core.attack_surface.object_inventory import ObjectInventory
from core.attack_surface.workflow_inventory import WorkflowInventory

logging.getLogger("core.attack_surface").setLevel(logging.INFO)

class TestAttackSurfaceGraphPhase5Refined(unittest.TestCase):

    def setUp(self):
        self.graph = AttackSurfaceGraph()
        self.endpoints = EndpointInventory(self.graph)
        self.requests = RequestInventory(self.graph, self.endpoints)
        self.parameters = ParameterInventory(self.graph)
        self.objects = ObjectInventory(self.graph)
        self.workflows = WorkflowInventory(self.graph)

    def test_300_plus_requests_and_queries(self):
        """Test proving that 300+ captured requests can be represented without schema errors."""
        
        # 1. Generate 300+ mock requests
        # We will create groups: SPA routes, REST API (UUIDs, IDs), static files
        req_nodes = []
        
        # 100 API Requests with IDs
        for i in range(100):
            req = self.requests.ingest_request("GET", f"/api/users/{i}", source="http", is_api=True)
            req_nodes.append(req)
            
        # 100 API Requests with UUIDs
        for i in range(100):
            mock_uuid = str(uuid.uuid4())
            req = self.requests.ingest_request("POST", f"/api/transactions/{mock_uuid}/process", source="js", is_api=True)
            req_nodes.append(req)
            
        # 50 SPA Fragments
        for i in range(50):
            # Normalization should strip host and preserve hash
            req = self.requests.ingest_request("GET", f"https://example.com/#/dashboard/view/{i}", source="browser", is_api=False)
            req_nodes.append(req)
            
        # 50 Static files
        for i in range(50):
            req = self.requests.ingest_request("GET", f"/static/css/style_{i}.css", source="browser", is_api=False)
            req_nodes.append(req)
            
        # 2. Add some parameters to an endpoint
        ep_user = self.endpoints.get_or_create_endpoint("GET", "/api/users/99") # Should hit the normalized endpoint /api/users/{id}
        self.parameters.ingest_parameters(ep_user, [{"name": "auth_token", "type": "header"}])
        
        # 3. Add object
        self.objects.ingest_objects(ep_user, [{"object_type": "UserProfile", "fields": ["name", "email"]}])
        
        # 4. Verify Total Requests = 300
        self.assertEqual(len(self.graph.get_nodes_by_type(NodeType.REQUEST)), 300)
        
        # 5. Verify Endpoints collapsed drastically
        # 100 User GETs -> 1 endpoint: /api/users/{id}
        # 100 Transaction POSTs -> 1 endpoint: /api/transactions/{uuid}/process
        # 50 SPA -> 1 endpoint: /#/dashboard/view/{id}
        # 50 Static -> 50 endpoints (since they just vary by name without matching an ID pattern, wait style_{i} won't match standard id unless it's just digits. Let's see: /static/css/style_1.css - won't match ID pattern natively. So maybe 50 endpoints).
        
        endpoints = self.graph.get_nodes_by_type(NodeType.ENDPOINT)
        # We expect at least the 3 collapsed ones + 50 static
        self.assertTrue(len(endpoints) > 3)
        self.assertTrue(len(endpoints) < 100) # Ensure collapse happened
        
        # 6. Test Queries
        apis = self.graph.get_apis()
        self.assertTrue(len(apis) >= 2) # The users and transactions endpoints
        
        obj_eps = self.graph.object_identifier_endpoints()
        self.assertTrue(len(obj_eps) >= 2) # Endpoints with {id} or {uuid}
        
        params = self.graph.parameters_for_endpoint(ep_user.id)
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].name, "auth_token")
        
        eps_requests = self.graph.requests_for_endpoint(ep_user.id)
        self.assertEqual(len(eps_requests), 100) # 100 GET requests map to this endpoint
        
        # Print summary
        captured_output = io.StringIO()
        sys.stdout = captured_output
        self.graph.print_summary()
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        self.assertIn("ATTACK_SURFACE_GRAPH", output)
        self.assertIn("requests=300", output)
        self.assertIn("api_requests=200", output)

if __name__ == '__main__':
    unittest.main()
