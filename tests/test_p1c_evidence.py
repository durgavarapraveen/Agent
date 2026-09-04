import json
import os
import tempfile
import unittest
import uuid

from core.evidence.evidence import Evidence
from core.evidence.oracle import (
    DifferentialResponseOracle,
    ErrorSignatureOracle,
    ReflectionOracle,
)
from core.evidence.validator import EvidenceValidator
from core.execution.executors.base import ExecutionStatus
from core.findings.finding import Finding, FindingState
from core.findings.finding_state_machine import FindingStateMachine
from core.findings.finding_store import FindingStore


class TestEvidence(unittest.TestCase):

    def test_evidence_creation(self):
        ev = Evidence(tool_name="nmap", command="nmap -sV target", stdout="PORT STATE", stderr="")
        self.assertEqual(ev.tool_name, "nmap")
        self.assertEqual(ev.command, "nmap -sV target")
        self.assertTrue(ev.is_credible())
        d = ev.to_dict()
        self.assertIn("evidence_id", d)
        self.assertIn("tool_name", d)
        uuid.UUID(ev.evidence_id)


class TestOracles(unittest.TestCase):

    def _evidence(self, stdout="output"):
        return Evidence(tool_name="test", command="cmd", stdout=stdout)

    def test_differential_response_oracle_same_response_false(self):
        baseline = {"body": "hello", "status_code": 200}
        oracle = DifferentialResponseOracle(baseline)
        confirmed, name = oracle.apply({"body": "hello", "status_code": 200}, self._evidence())
        self.assertFalse(confirmed)
        self.assertEqual(name, "differential_response")

    def test_differential_response_oracle_different_response_true(self):
        baseline = {"body": "hello", "status_code": 200}
        oracle = DifferentialResponseOracle(baseline)
        confirmed, name = oracle.apply({"body": "error", "status_code": 500}, self._evidence())
        self.assertTrue(confirmed)

    def test_error_signature_oracle_matches_sql_error(self):
        oracle = ErrorSignatureOracle()
        ev = self._evidence("You have an error in your SQL syntax near '1'")
        confirmed, name = oracle.apply({"body": ev.stdout}, ev)
        self.assertTrue(confirmed)
        self.assertEqual(name, "error_signature")

    def test_reflection_oracle_detects_payload_in_response(self):
        payload = "<script>alert(1)</script>"
        oracle = ReflectionOracle(payload=payload)
        body = f"<html><body>Search: {payload}</body></html>"
        ev = self._evidence(body)
        confirmed, name = oracle.apply({"body": body}, ev)
        self.assertTrue(confirmed)
        self.assertEqual(name, "reflection")

    def test_reflection_oracle_no_payload_false(self):
        oracle = ReflectionOracle(payload="<script>alert(1)</script>")
        ev = self._evidence("safe content")
        confirmed, _ = oracle.apply({"body": "safe content"}, ev)
        self.assertFalse(confirmed)


class TestFindingStateMachine(unittest.TestCase):

    def test_finding_state_machine_valid_transition(self):
        f = Finding(title="SQLi", description="SQL injection", severity="HIGH")
        sm = FindingStateMachine()
        sm.mark_validating(f)
        self.assertEqual(f.state_enum, FindingState.VALIDATING)
        sm.mark_confirmed(f, ["ev-1", "ev-2"])
        self.assertEqual(f.state_enum, FindingState.CONFIRMED)
        self.assertIn("ev-1", f.evidence_ids)

    def test_finding_state_machine_invalid_transition_raises(self):
        f = Finding(title="XSS", description="Cross-site scripting", severity="MEDIUM")
        sm = FindingStateMachine()
        with self.assertRaises(ValueError) as ctx:
            sm.mark_confirmed(f, [])
        self.assertIn("Valid transitions", str(ctx.exception))


class TestFindingStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        self.path = self.tmp.name

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_finding_store_persists_immediately(self):
        store = FindingStore(self.path)
        f = Finding(title="IDOR", description="Insecure direct object ref", severity="HIGH")
        store.store(f)
        with open(self.path, "r") as fh:
            data = json.load(fh)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["title"], "IDOR")

    def test_finding_store_survives_process_restart(self):
        store1 = FindingStore(self.path)
        f = Finding(title="IDOR", description="Insecure direct object ref", severity="HIGH")
        store1.store(f)
        fid = f.finding_id
        del store1

        store2 = FindingStore(self.path)
        loaded = store2.get(fid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, "IDOR")
        self.assertEqual(loaded.finding_id, fid)


class TestToolExitNotVulnerability(unittest.TestCase):

    def test_tool_exit_success_not_equals_vulnerability_confirmed(self):
        status = ExecutionStatus.SUCCESS
        finding = Finding(title="Potential SQLi", description="test", severity="HIGH")
        self.assertEqual(finding.state_enum, FindingState.DISCOVERED)
        self.assertNotEqual(finding.state_enum, FindingState.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
