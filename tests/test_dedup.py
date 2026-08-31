"""Unit tests for validation.dedup fingerprinting and cross-scan classification."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validation.dedup import (fingerprint, generate_dedup_key, DedupStore, NEW, RECURRING)


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

    def test_generate_dedup_key(self):
        key1 = generate_dedup_key("port_scanning", "millisecond.speshway.com", "80")
        key2 = generate_dedup_key("port_scanning", "www.speshway.com", "80")
        self.assertEqual(key1, "port_scanning:millisecond.speshway.com:80")
        self.assertEqual(key2, "port_scanning:www.speshway.com:80")
        self.assertNotEqual(key1, key2)

    def test_subdomains_produce_distinct_fingerprints(self):
        fp1 = fingerprint("CVE-1", "f.py", "foo", "1.0", target="millisecond.speshway.com")
        fp2 = fingerprint("CVE-1", "f.py", "foo", "1.0", target="www.speshway.com")
        self.assertNotEqual(fp1, fp2)


class TestDedupStore(unittest.TestCase):

    def setUp(self):
        from core.memory.dedup_tracker import DeduplicationTracker
        DeduplicationTracker().reset_all()
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

    def test_distinct_missing_headers_on_same_host_are_not_deduplicated(self):
        from core.memory.shared_context import SharedContext

        ctx = SharedContext("target.com")

        v1 = {
            "type": "missing_security_header",
            "title": "Missing Security Header: Content-Security-Policy",
            "header_name": "Content-Security-Policy",
            "proof": "Header missing",
            "target": "target.com"
        }
        v2 = {
            "type": "missing_security_header",
            "title": "Missing Security Header: X-Frame-Options",
            "header_name": "X-Frame-Options",
            "proof": "Header missing",
            "target": "target.com"
        }
        v3 = {
            "type": "missing_security_header",
            "title": "Missing Security Header: Strict-Transport-Security",
            "header_name": "Strict-Transport-Security",
            "proof": "Header missing",
            "target": "target.com"
        }

        res1 = ctx.add_vulnerability(v1)
        res2 = ctx.add_vulnerability(v2)
        res3 = ctx.add_vulnerability(v3)

        self.assertTrue(res1)
        self.assertTrue(res2)
        self.assertTrue(res3)
        self.assertEqual(len(ctx.vulnerabilities), 3)


if __name__ == "__main__":
    unittest.main()
