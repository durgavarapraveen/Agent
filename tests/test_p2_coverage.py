import json
import os
import tempfile
import unittest

from core.coverage.security_test_catalog import SecurityTest, SecurityTestCatalog, build_default_catalog
from core.coverage.applicability_engine import ApplicabilityEngine
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.coverage.convergence_engine_v2 import ConvergenceEngine
from core.attack_surface.endpoint_inventory_v2 import EndpointInventoryV2


class TestSecurityTestCatalog(unittest.TestCase):

    def test_security_test_catalog_registration(self):
        catalog = build_default_catalog()
        all_tests = catalog.list_all()
        self.assertGreaterEqual(len(all_tests), 40)
        sqli_tests = catalog.list_by_category("sqli")
        self.assertGreaterEqual(len(sqli_tests), 3)
        t = catalog.get("sqli_basic_01")
        self.assertIsNotNone(t)
        self.assertEqual(t.name, "SQL Injection Basic")
        self.assertIsNone(catalog.get("nonexistent"))


class TestApplicability(unittest.TestCase):

    def setUp(self):
        self.catalog = build_default_catalog()
        self.engine = ApplicabilityEngine(self.catalog)

    def test_applicability_sqli_requires_input(self):
        ep_with_params = {"path": "/search", "parameters": [{"name": "q", "location": "query"}]}
        ep_no_params = {"path": "/static", "parameters": []}
        sqli = self.catalog.get("sqli_basic_01")
        self.assertTrue(self.engine.is_applicable(sqli, ep_with_params))
        self.assertFalse(self.engine.is_applicable(sqli, ep_no_params))

    def test_applicability_idor_requires_multiple_identities(self):
        ep = {"path": "/api/users/{id}/profile", "parameters": []}
        idor = self.catalog.get("authz_idor_01")
        self.assertFalse(self.engine.is_applicable(idor, ep, identities=["admin"]))
        self.assertTrue(self.engine.is_applicable(idor, ep, identities=["admin", "user"]))

    def test_applicability_xss_reflected_requires_html_response(self):
        ep_html = {"path": "/search", "parameters": [{"name": "q", "location": "query"}], "content_type": "text/html"}
        ep_json = {"path": "/api/data", "parameters": [{"name": "q", "location": "query"}], "content_type": "application/json"}
        xss = self.catalog.get("xss_reflected_01")
        self.assertTrue(self.engine.is_applicable(xss, ep_html))
        self.assertFalse(self.engine.is_applicable(xss, ep_json))


class TestCoverageMatrix(unittest.TestCase):

    def test_coverage_matrix_state_update(self):
        m = CoverageMatrix(["ep1", "ep2"], ["sqli_01", "xss_01"])
        self.assertEqual(m.get_state("ep1", "sqli_01"), CoverageState.NOT_TESTED)
        m.update_state("ep1", "sqli_01", CoverageState.CONFIRMED, "ev-1")
        self.assertEqual(m.get_state("ep1", "sqli_01"), CoverageState.CONFIRMED)

    def test_coverage_matrix_get_coverage_percentage(self):
        m = CoverageMatrix(["ep1"], ["t1", "t2", "t3", "t4"])
        m.update_state("ep1", "t1", CoverageState.CONFIRMED)
        m.update_state("ep1", "t2", CoverageState.REJECTED)
        # t3, t4 remain NOT_TESTED → 2/4 = 50%
        self.assertAlmostEqual(m.get_coverage(), 0.5)

    def test_coverage_by_category(self):
        m = CoverageMatrix(["ep1"], ["sqli_01", "sqli_02", "xss_01"])
        cat_map = {"sqli_01": "sqli", "sqli_02": "sqli", "xss_01": "xss"}
        m.update_state("ep1", "sqli_01", CoverageState.CONFIRMED)
        m.update_state("ep1", "sqli_02", CoverageState.REJECTED)
        # sqli: 2/2 = 100%, xss: 0/1 = 0%
        by_cat = m.get_coverage_by_category(cat_map)
        self.assertAlmostEqual(by_cat["sqli"], 1.0)
        self.assertAlmostEqual(by_cat["xss"], 0.0)

    def test_blocked_test_in_matrix(self):
        m = CoverageMatrix(["ep1"], ["t1", "t2"])
        m.update_state("ep1", "t1", CoverageState.BLOCKED)
        blocked = m.get_blocked()
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0], ("ep1", "t1"))
        # Blocked does not count as resolved
        m.update_state("ep1", "t2", CoverageState.CONFIRMED)
        self.assertAlmostEqual(m.get_coverage(), 0.5)


class TestConvergence(unittest.TestCase):

    def test_convergence_requires_85_percent(self):
        m = CoverageMatrix(["ep1"], ["t1", "t2", "t3", "t4", "t5"])
        eng = ConvergenceEngine(m)
        # 4/5 = 80% → not converged
        for t in ["t1", "t2", "t3", "t4"]:
            m.update_state("ep1", t, CoverageState.CONFIRMED)
        self.assertFalse(eng.is_converged())
        # 5/5 = 100% → converged
        m.update_state("ep1", "t5", CoverageState.REJECTED)
        self.assertTrue(eng.is_converged())

    def test_uncovered_endpoint_prevents_convergence(self):
        m = CoverageMatrix(["ep1", "ep2"], ["t1"])
        eng = ConvergenceEngine(m)
        m.update_state("ep1", "t1", CoverageState.CONFIRMED)
        # ep2/t1 is still NOT_TESTED → gap exists → not converged
        self.assertFalse(eng.is_converged())

    def test_scanner_zero_findings_not_converged(self):
        m = CoverageMatrix(["ep1"], ["sqli_01", "xss_01", "idor_01"])
        eng = ConvergenceEngine(m)
        # Scanner ran and found nothing, but tests still NOT_TESTED
        self.assertFalse(eng.is_converged())
        self.assertEqual(len(eng.get_remaining_gaps()), 3)


class TestEndpointInventory(unittest.TestCase):

    def test_endpoint_inventory_no_duplicates(self):
        inv = EndpointInventoryV2()
        inv.add_endpoint({"url": "/api/users", "method": "GET"})
        inv.add_endpoint({"url": "/api/users", "method": "GET"})
        inv.add_endpoint({"url": "/api/users", "method": "POST"})
        self.assertEqual(len(inv.list_endpoints()), 2)

    def test_endpoint_inventory_persists(self):
        inv = EndpointInventoryV2()
        inv.add_endpoint({"url": "/api/login", "method": "POST", "parameters": [{"name": "user"}]})
        ep = inv.find_by_path("/api/login")
        self.assertEqual(len(ep), 1)
        self.assertEqual(ep[0]["url"], "/api/login")
        eid = ep[0]["endpoint_id"]
        loaded = inv.get_endpoint(eid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["url"], "/api/login")


if __name__ == "__main__":
    unittest.main()
