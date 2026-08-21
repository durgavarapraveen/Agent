"""Unit tests for validation.dedup fingerprinting and cross-scan classification."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validation.dedup import (fingerprint, DedupStore, NEW, RECURRING, RESOLVED)


class TestFingerprint(unittest.TestCase):

    def test_deterministic(self):
        a = fingerprint("CVE-2021-23337", "pkg/lodash", "merge", "4.17.20")
        b = fingerprint("CVE-2021-23337", "pkg/lodash", "merge", "4.17.20")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)  # sha256 hex

    def test_case_and_whitespace_normalized(self):
        a = fingerprint("cve-2021-23337", " pkg/lodash", "merge", "4.17.20 ")
        b = fingerprint("CVE-2021-23337", "pkg/lodash", "merge", "4.17.20")
        self.assertEqual(a, b)

    def test_distinct_inputs_differ(self):
        a = fingerprint("CVE-1", "f.py", "foo", "1.0")
        b = fingerprint("CVE-1", "f.py", "foo", "1.1")   # version differs
        self.assertNotEqual(a, b)


class TestDedupStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.store = DedupStore(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _f(self, cve="CVE-1", sev="HIGH", ver="1.0"):
        return {"cve_id": cve, "file_path": "app.py",
                "function_name": "handler", "package_version": ver, "severity": sev}

    def test_new_then_recurring(self):
        r1 = self.store.classify(self._f(), "scan-1")
        self.assertEqual(r1.status, NEW)
        r2 = self.store.classify(self._f(), "scan-2")
        self.assertEqual(r2.status, RECURRING)
        self.assertTrue(r2.suppressed)          # severity unchanged -> suppressed

    def test_recurring_severity_change_not_suppressed(self):
        self.store.classify(self._f(sev="LOW"), "scan-1")
        r = self.store.classify(self._f(sev="CRITICAL"), "scan-2")
        self.assertEqual(r.status, RECURRING)
        self.assertTrue(r.severity_changed)
        self.assertFalse(r.suppressed)          # escalation surfaces

    def test_resolved(self):
        self.store.classify(self._f(cve="CVE-1"), "scan-1")
        # Next scan does NOT include CVE-1
        self.store.classify(self._f(cve="CVE-2"), "scan-2")
        resolved = self.store.mark_resolved("scan-2")
        self.assertEqual(len(resolved), 1)      # CVE-1 resolved

    def test_process_scan_suppresses_recurring(self):
        findings = [self._f(cve="CVE-1"), self._f(cve="CVE-2")]
        self.store.process_scan(findings, "s1")
        out = self.store.process_scan(findings, "s2")
        self.assertEqual(out["suppressed"], 2)  # both recurring, unchanged
        self.assertEqual(len(out["report"]), 0)


if __name__ == "__main__":
    unittest.main()
