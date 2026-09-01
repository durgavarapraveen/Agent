import unittest
from core.attack_surface.route_normalizer import RouteNormalizer
from core.attack_surface.endpoint_inventory import EndpointInventory
from core.attack_surface.graph import AttackSurfaceGraph
from core.domain.endpoint import Endpoint
from core.domain.request import CapturedRequest
from core.domain.parameter import Parameter, ParameterType


class TestAttackSurface(unittest.TestCase):
    def test_route_normalizer(self):
        norm = RouteNormalizer()

        http, spa = norm.normalize_spa_route("https://host/#/users/42")
        self.assertEqual(http, "/")
        self.assertEqual(spa, "/users/42")

        http, spa = norm.normalize_spa_route("https://host/api/users/42")
        self.assertEqual(http, "/api/users/42")
        self.assertIsNone(spa)

        http, spa = norm.normalize_spa_route("https://host/#!/dashboard")
        self.assertEqual(http, "/")
        self.assertEqual(spa, "/dashboard")

    def test_endpoint_deduplication(self):
        inv = EndpointInventory()
 
        ep1 = Endpoint(
            endpoint_id="EP-1",
            path="/api/users",
            url="https://host/api/users",
            method_set={"GET"}
        )

        ep2 = Endpoint(
            endpoint_id="EP-2",
            path="/api/users",
            url="https://host/api/users",
            method_set={"GET"}
        )

        inv.add_endpoint(ep1)
        inv.add_endpoint(ep2)

        self.assertEqual(len(inv.get_endpoints()), 2)

        deduped = inv.deduplicate()
        self.assertEqual(len(deduped), 1)

    def test_graph_queries(self):
        graph = AttackSurfaceGraph()

        ep = Endpoint(
            endpoint_id="EP-1",
            path="/api/test",
            url="https://host/api/test",
            method_set={"POST"}
        )
        graph.add_endpoint(ep)

        param = Parameter(
            name="test_param",
            parameter_type=ParameterType.QUERY
        )
        graph.add_parameter("EP-1", param)

        from core.domain.request import ResponseData
        resp = ResponseData(status_code=200)
        
        req = CapturedRequest(
            request_id="REQ-1",
            method="POST",
            url="https://host/api/test",
            full_headers={},
            identity_id="user_a",
            response=resp
        )
        # The graph expects the endpoint_id mapping to either be on the request object 
        # or managed externally. Since CapturedRequest doesn't have an endpoint_id field
        # by default, we'll map it using the graph's internal method directly.
        graph.requests.add_captured_request(req, endpoint_id="EP-1")
        graph.edges_count += 1 # ENDPOINT -> ACCEPTS -> REQUEST
        
        # Test endpoints_by_parameter_type
        eps_with_param = graph.endpoints_by_parameter_type("query")
        self.assertEqual(len(eps_with_param), 1)
        self.assertEqual(eps_with_param[0].endpoint_id, "EP-1")
        
        # Test requests_for_endpoint
        reqs = graph.requests_for_endpoint("EP-1")
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0].request_id, "REQ-1")

if __name__ == '__main__':
    unittest.main()
