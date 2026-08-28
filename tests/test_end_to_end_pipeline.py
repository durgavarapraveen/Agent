"""
End-to-End System Integration Test Suite for AntiGravity Framework (Phases 1 - 4).
Validates that all modules are interconnected, data flows seamlessly between phases,
and results match expected outputs for sample targets.
"""

import json
import os
import tempfile
import unittest

from core.authorization import TargetScopeValidator
from core.lateral_movement import LateralMovementPlanner
from core.credential_simulator import CredentialSimulator
from core.persistence_auditor import PersistenceAuditor
from core.vulnerability_intelligence import VulnerabilityIntelligence
from core.llm_orchestrator import LLMOrchestrator
from core.quality_gate import QualityGate


class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        # Configure scope for sample target
        TargetScopeValidator.set(TargetScopeValidator(["httpbin.org", "127.0.0.1", "example.com"]))
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "integration_test.sqlite")
        self.sam_path = os.path.join(self.tmp_dir.name, "decoy_sam.hive")
        with open(self.sam_path, "w", encoding="utf-8") as f:
            f.write("Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n")

        # Initialize Master Pipeline Orchestrators
        self.vuln_intel = VulnerabilityIntelligence(db_path=self.db_path, offline_mode=True)
        self.llm_orchestrator = LLMOrchestrator(model_name="gpt-4", token_limit=2000, db_path=self.db_path)
        self.quality_gate = QualityGate(db_path=self.db_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_full_pipeline_flow(self):
        target_domain = "httpbin.org"
        target_ip = "127.0.0.1"

        # ----------------------------------------------------
        # 1. Phase 1: Recon & Post-Exploitation Simulation
        # ----------------------------------------------------
        cred_sim = CredentialSimulator(dry_run=True)
        sam_decoy = cred_sim.parse_decoy_sam(self.sam_path)
        self.assertGreaterEqual(len(sam_decoy), 1)

        auditor = PersistenceAuditor()
        base_snap = auditor.generate_current_inventory()
        self.assertIn("scheduled_tasks", base_snap)

        lat_planner = LateralMovementPlanner(self.vuln_intel)
        smb_res = lat_planner.smb_enumerate_shares(target_ip)
        self.assertGreaterEqual(len(smb_res), 1)

        # ----------------------------------------------------
        # 2. Phase 2: Vulnerability Intelligence & Correlation
        # ----------------------------------------------------
        vuln_results = self.vuln_intel.correlate(
            service_name="apache httpd",
            version="2.4.49",
            target_ip=target_ip,
            target_port=80,
            is_critical_asset=True,
            is_public_facing=True
        )
        self.assertGreaterEqual(len(vuln_results), 1)
        cve_finding = vuln_results[0]
        self.assertIn("cve_id", cve_finding)
        self.assertIn("adjusted_cvss_score", cve_finding)
        self.assertIn("manual_cmd", cve_finding)
        self.assertIn("patch_urgency_score", cve_finding)

        # ----------------------------------------------------
        # 3. Phase 3: LLM Context Preparation & Optimization
        # ----------------------------------------------------
        llm_context = self.llm_orchestrator.prepare_llm_execution_context(
            tech_stack=["apache", "python"],
            industry="finance",
            depth="deep",
            findings=vuln_results,
            tool_outputs={"nmap": "PORT 80 OPEN Apache 2.4.49"}
        )
        self.assertIn("compressed_payload", llm_context)
        self.assertIn("Finance", llm_context["compressed_payload"]["prompt"])
        self.assertGreater(llm_context["final_token_count"], 0)

        # ----------------------------------------------------
        # 4. Phase 4: Quality Gate, Retest & Calibration
        # ----------------------------------------------------
        raw_findings = [
            {
                "cve_id": cve_finding["cve_id"],
                "type": "SQLI_ERROR_BASED",
                "title": "Apache Path Traversal",
                "url": f"https://{target_domain}/get",
                "status_code": 200,
                "content_length": 512,
                "public_exploit_available": True
            },
            {
                "title": "Known False Positive",
                "status_code": 200,
                "content_length": 0  # Should be filtered out by FP rule
            }
        ]

        quality_report = self.quality_gate.process_findings(
            scan_id="scan_integration_001",
            target=target_domain,
            raw_findings=raw_findings,
            first_scan_mode=True
        )

        self.assertEqual(quality_report["fp_rejected_count"], 1)
        self.assertEqual(len(quality_report["final_findings"]), 1)

        final_f = quality_report["final_findings"][0]
        self.assertEqual(final_f["cve_id"], cve_finding["cve_id"])
        self.assertGreaterEqual(final_f["confidence_score"], 0.85)
        self.assertTrue(final_f["auto_accepted"])

        print("\n=======================================================")
        print("  END-TO-END PIPELINE INTEGRATION TEST SUCCESSFUL")
        print(f"  Target: {target_domain} ({target_ip})")
        print(f"  Correlated CVE: {final_f['cve_id']}")
        print(f"  Adjusted CVSS Score: {cve_finding['adjusted_cvss_score']}")
        print(f"  Patch Urgency Score: {cve_finding['patch_urgency_score']}")
        print(f"  Final Confidence Score: {final_f['confidence_score']} (Auto-accepted: {final_f['auto_accepted']})")
        print("=======================================================\n")


if __name__ == "__main__":
    unittest.main()
