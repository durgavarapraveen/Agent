"""
Unit tests for Post-Exploitation Simulator (Module 1.1).
Tests core/lateral_movement.py, core/credential_simulator.py, and core/persistence_auditor.py.
"""

import os
import json
import tempfile
import unittest

from core.authorization import TargetScopeValidator
from core.shared_context import SharedContext
from core.lateral_movement import LateralMovementPlanner
from core.credential_simulator import CredentialSimulator
from core.persistence_auditor import PersistenceAuditor


class TestModule1PostExploitationSimulator(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["192.168.1.0/24", "192.168.1.1", "192.168.1.10", "192.168.1.50", "example.com"]))
        self.ctx = SharedContext("example.com")
        self.planner = LateralMovementPlanner(self.ctx)
        self.cred_sim = CredentialSimulator(dry_run=True)
        self.pers_audit = PersistenceAuditor()

    def test_smb_enum_shares(self):
        shares = self.planner.smb_enumerate_shares("192.168.1.10")
        self.assertIsInstance(shares, list)
        self.assertGreaterEqual(len(shares), 1)

    def test_ping_sweep_scope_enforcement(self):
        live_hosts = self.planner.ping_sweep_subnet("192.168.1")
        self.assertIsInstance(live_hosts, list)
        self.assertGreaterEqual(len(live_hosts), 1)

    def test_ssh_trust_chain_parsing(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC user@hostB\n")
            f_path = f.name

        chains = self.planner.parse_ssh_trust_chains(f_path)
        os.unlink(f_path)
        self.assertEqual(len(chains), 1)
        self.assertIn("user@hostB", chains[0])

    def test_bloodhound_lite_render(self):
        graph = self.planner.bloodhound_lite_collector()
        self.assertIn("BLOODHOUND-LITE DOMAIN ADMIN PATHS", graph)

    def test_decoy_sam_dump(self):
        results = self.cred_sim.parse_decoy_sam("nonexistent_sam.save")
        self.assertTrue(self.cred_sim.dry_run)

    def test_decoy_shadow_and_secret_scanning(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write('AKIA1234567890ABCDEF\n')
            f.write('root:$6$salt$encryptedhash:18000:0:99999:7:::\n')
            f_path = f.name

        secrets = self.cred_sim.scan_uploaded_secrets(f_path)
        os.unlink(f_path)
        self.assertGreaterEqual(len(secrets), 1)
        self.assertIn("AKIA****", secrets[0]["masked_value"])

    def test_persistence_baseline_diff(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            json.dump({"scheduled_tasks": [], "cron_jobs": [], "ssh_keys": []}, f)
            b_path = f.name

        diff = self.pers_audit.compare_against_baseline(b_path)
        os.unlink(b_path)
        self.assertIn("new_scheduled_tasks", diff)


if __name__ == "__main__":
    unittest.main()
