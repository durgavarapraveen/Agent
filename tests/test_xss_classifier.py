"""XSS context-aware classifier tests (#094)."""
from __future__ import annotations

import pytest

from core.execution.executors.xss import _classify_reflection


class TestXSSReflection:
    def test_no_reflection(self):
        r = _classify_reflection("Hello world", "<script>alert(1)</script>")
        assert r["reflected"] is False
        assert r["likely_exploitable"] is False

    def test_raw_reflection_in_html_is_likely_exploitable(self):
        body = "<html><body><h1><script>alert(1)</script></h1></body></html>"
        r = _classify_reflection(body, "<script>alert(1)</script>")
        assert r["raw"] is True
        assert r["likely_exploitable"] is True

    def test_reflection_inside_textarea_is_not_likely_exploitable(self):
        body = "<textarea><script>alert(1)</script></textarea>"
        r = _classify_reflection(body, "<script>alert(1)</script>")
        assert r["raw"] is True
        assert r["textarea"] is True
        assert r["likely_exploitable"] is False

    def test_html_encoded_reflection_flagged(self):
        body = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>"
        r = _classify_reflection(body, "<script>alert(1)</script>")
        assert r["html_encoded"] is True
        assert r["reflected"] is True

    def test_json_only_reflection_not_exploitable(self):
        body = '{"echo": "<script>alert(1)</script>"}'
        r = _classify_reflection(body, "<script>alert(1)</script>")
        assert r["raw"] is True
        assert r["json_only"] is True
        assert r["likely_exploitable"] is False

    def test_reflection_inside_script_block(self):
        body = "<script>var x = '<script>alert(1)</script>';</script>"
        r = _classify_reflection(body, "<script>alert(1)</script>")
        assert r["js_string"] is True

    def test_empty_input_is_safe(self):
        r = _classify_reflection("", "")
        assert r["reflected"] is False
