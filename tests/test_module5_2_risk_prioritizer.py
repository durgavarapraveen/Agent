"""
Unit tests for Phase 5 Module 5.2: Risk Prioritization (core/risk_prioritizer.py)
"""

import unittest
from core.reporting.risk_prioritizer import (
    compute_exploitability_score,
    compute_business_impact,
    RiskPrioritizer
)


class TestModule5_2_RiskPrioritizer(unittest.TestCase):

    def test_exploitability_score_bounds(self):
        """Verify exploitability score point additions and bounding [0, 100]."""
        finding_max = {
            "public_exploit_available": True,
            "easy_to_chain": True,
            "no_authentication_required": True,
            "complex_attack_vector": False
        }
        score_max = compute_exploitability_score(finding_max)
        self.assertEqual(score_max, 90.0)  # 40 + 30 + 20

        finding_complex = {
            "public_exploit_available": True,
            "easy_to_chain": False,
            "no_authentication_required": False,
            "complex_attack_vector": True
        }
        score_complex = compute_exploitability_score(finding_complex)
        self.assertEqual(score_complex, 30.0)  # 40 - 10

    def test_business_impact_calculation(self):
        """Verify business impact normalized multiplier (0–1 scale)."""
        sqli_finding = {"type": "SQLI", "severity": "HIGH"}
        impact_sqli = compute_business_impact(sqli_finding)
        self.assertEqual(impact_sqli, 1.0)  # max(data_exposed=10, reputation_damage=8) / 10 = 1.0

        info_finding = {"type": "INFO_DISCLOSURE", "severity": "LOW"}
        impact_info = compute_business_impact(info_finding)
        self.assertEqual(impact_info, 0.5)  # information_disclosure=5 / 10 = 0.5

    def test_combined_risk_score_and_ranking(self):
        """Verify combined risk score formula and descending ranking order."""
        prioritizer = RiskPrioritizer()
        findings = [
            {
                "cve": "CVE-2023-0001",
                "type": "INFO_DISCLOSURE",
                "severity": "LOW",
                "cvss": 3.0,
                "public_exploit_available": False,
                "remediation": "Update headers"
            },
            {
                "cve": "CVE-2023-9999",
                "type": "RCE",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "public_exploit_available": True,
                "easy_to_chain": True,
                "no_authentication_required": True,
                "remediation": "Update Apache to 2.4.49"
            }
        ]

        ranked = prioritizer.prioritize_findings(findings)
        self.assertEqual(ranked[0]["cve"], "CVE-2023-9999")
        self.assertTrue(ranked[0]["risk_score"] > ranked[1]["risk_score"])

    def test_risk_tiers_and_roadmap(self):
        """Verify risk tier grouping and ordered action list generation."""
        prioritizer = RiskPrioritizer()
        findings = [
            {
                "cve": "CVE-2023-12345",
                "type": "RCE",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "public_exploit_available": True,
                "easy_to_chain": True,
                "remediation": "Update Apache to 2.4.49"
            },
            {
                "cve": "CVE-2022-1234",
                "type": "MISCONFIGURATION",
                "severity": "LOW",
                "cvss": 2.0,
                "public_exploit_available": False,
                "remediation": "Patch OpenSSH"
            }
        ]

        tiers = prioritizer.group_by_risk_tiers(findings)
        self.assertTrue(len(tiers["CRITICAL_RISK"]) > 0 or len(tiers["HIGH_RISK"]) > 0)

        roadmap = prioritizer.generate_prioritized_roadmap(findings)
        self.assertEqual(len(roadmap), 2)
        self.assertIn("1. Fix CVE-2023-12345", roadmap[0])
        self.assertIn("Update Apache to 2.4.49", roadmap[0])


if __name__ == "__main__":
    unittest.main()
