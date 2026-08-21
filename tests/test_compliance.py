"""Unit tests for compliance mapping and reporting."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.mapper import ComplianceMapper
from compliance.reporter import ComplianceReporter
from compliance.frameworks import category_for_cwe, available_frameworks


class TestCWECategory(unittest.TestCase):

    def test_known_cwe(self):
        self.assertEqual(category_for_cwe("CWE-89"), "sqli")
        self.assertEqual(category_for_cwe("89"), "sqli")   # normalizes prefix
        self.assertEqual(category_for_cwe("CWE-79"), "xss")

    def test_unknown_cwe(self):
        self.assertEqual(category_for_cwe("CWE-99999"), "")
        self.assertEqual(category_for_cwe(""), "")


class TestMapper(unittest.TestCase):

    def test_sqli_maps_across_frameworks(self):
        m = ComplianceMapper(["pci", "cis", "nist"])
        hits = m.map_finding({"category": "sqli"})
        frameworks = {h.framework for h in hits}
        # sqli appears in PCI 6.2, CIS 16, NIST RA-5
        self.assertIn("pci", frameworks)
        self.assertIn("cis", frameworks)
        self.assertIn("nist", frameworks)

    def test_map_by_cwe_only(self):
        m = ComplianceMapper(["pci"])
        hits = m.map_finding({"cwe": "CWE-89"})   # -> sqli
        self.assertTrue(any(h.control_id == "6.2" for h in hits))

    def test_vulnerable_component_hits_si5(self):
        m = ComplianceMapper(["nist"])
        hits = m.map_finding({"category": "vulnerable_component"})
        ids = {h.control_id for h in hits}
        self.assertIn("SI-5", ids)
        self.assertIn("SI-2", ids)

    def test_unknown_category_no_hits(self):
        m = ComplianceMapper(["pci"])
        self.assertEqual(m.map_finding({"category": "nonexistent"}), [])

    def test_invalid_framework_falls_back_to_all(self):
        m = ComplianceMapper(["bogus"])
        self.assertEqual(set(m.active), set(available_frameworks()))


class TestReporter(unittest.TestCase):

    def test_pass_fail_status(self):
        rep = ComplianceReporter(["pci"])
        findings = [{"id": "F1", "category": "sqli"}]
        summary = rep.build(findings)
        pci = summary["frameworks"]["pci"]
        # 6.2 should FAIL (sqli maps to it); some control should PASS
        statuses = {c["control_id"]: c["status"] for c in pci["controls"]}
        self.assertEqual(statuses["6.2"], "FAIL")
        self.assertGreaterEqual(pci["controls_failed"], 1)

    def test_evidence_references(self):
        rep = ComplianceReporter(["cis"])
        findings = [{"id": "VULN-001", "category": "xss"}]
        summary = rep.build(findings)
        ctrl16 = next(c for c in summary["frameworks"]["cis"]["controls"]
                      if c["control_id"] == "16")
        self.assertIn("VULN-001", ctrl16["evidence"])

    def test_markdown_renders(self):
        rep = ComplianceReporter(["pci", "soc2"])
        md = rep.render_markdown([{"id": "F1", "category": "auth"}])
        self.assertIn("## Compliance Summary", md)
        self.assertIn("PCI-DSS 4.0", md)


if __name__ == "__main__":
    unittest.main()
