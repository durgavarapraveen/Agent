import re
import urllib.parse

from core.intelligence.parser_differential import ParserDifferentialEngine
from core.intelligence.parser_differential.engine import _MARKER_A, _MARKER_B


class FakeServer:

    def __init__(self, precedence="first", body_overrides_query=False,
                 double_decode=False, case_insensitive_names=False, param="q"):
        self.precedence = precedence
        self.body_overrides_query = body_overrides_query
        self.double_decode = double_decode
        self.case_insensitive_names = case_insensitive_names
        self.param = param

    def _matches(self, name):
        if name == self.param:
            return True
        return self.case_insensitive_names and name.lower() == self.param.lower()

    def _winner(self, q_pairs, b_pairs):
        q_vals = [v for n, v in q_pairs if self._matches(n)]
        b_vals = [v for n, v in b_pairs if self._matches(n)]
        source = None
        if b_vals and self.body_overrides_query:
            source = b_vals
        elif q_vals:
            source = q_vals
        elif b_vals:
            source = b_vals
        if not source:
            return None
        return source[-1] if self.precedence == "last" else source[0]

    def __call__(self, url, method="GET", headers=None, data=None):
        parsed = urllib.parse.urlsplit(url)
        q_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        b_pairs = []
        ct = (headers or {}).get("Content-Type", "")
        if data:
            text = data.decode() if isinstance(data, bytes) else str(data)
            if "json" in ct:
                b_pairs = re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', text)
            else:
                b_pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
        winner = self._winner(q_pairs, b_pairs)
        if winner is not None and self.double_decode:
            winner = urllib.parse.unquote(winner)
        body = '{"value":null}' if winner is None else '{"value":"%s"}' % winner
        return 200, body, {"Content-Type": "application/json"}


def test_control_reflection_detected():
    eng = ParserDifferentialEngine(FakeServer())
    analysis = eng.analyze("https://t.example/api/echo", "q")
    assert analysis.reflective is True


def test_safe_server_no_material_findings():
    eng = ParserDifferentialEngine(FakeServer(precedence="first"))
    analysis = eng.analyze("https://t.example/api/echo", "q")
    material = [o for o in analysis.observations if o.severity in ("low", "medium", "high")]
    assert material == []


def test_vulnerable_server_flags_precedence_and_encoding():
    eng = ParserDifferentialEngine(FakeServer(
        precedence="last", body_overrides_query=True,
        double_decode=True, case_insensitive_names=True))
    analysis = eng.analyze("https://t.example/api/echo", "q")
    techniques = {o.technique for o in analysis.observations}
    assert "query_vs_body" in techniques        # body overrode query
    assert "double_encoding" in techniques       # layered URL-decoding
    assert "case_variant_name" in techniques     # case-insensitive key handling
    # every flagged mismatch reports the value it wrongly acted on
    qvb = next(o for o in analysis.observations if o.technique == "query_vs_body")
    assert qvb.reflected == "B" and qvb.expected == "A"


def test_dup_param_rule_reported_as_info():
    eng = ParserDifferentialEngine(FakeServer(precedence="last"))
    analysis = eng.analyze("https://t.example/api/echo", "q")
    rules = [o for o in analysis.observations if o.technique == "dup_param_rule"]
    assert rules and rules[0].severity == "info"
    assert "last-wins" in rules[0].detail


def test_non_reflective_order_sensitivity_uses_structural_fallback():
    def probe(url, method="GET", headers=None, data=None):
        q = urllib.parse.urlsplit(url).query
        # Block when marker A appears before marker B in a duplicated param.
        if re.search(re.escape(_MARKER_A) + r".*" + re.escape(_MARKER_B), q):
            return 403, "blocked", {"Content-Type": "text/plain"}
        return 200, "allowed", {"Content-Type": "text/plain"}

    analysis = ParserDifferentialEngine(probe).analyze("https://t.example/s", "q")
    assert analysis.reflective is False
    assert any(o.technique == "dup_param_order_divergence" for o in analysis.observations)
