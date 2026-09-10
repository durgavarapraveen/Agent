import urllib.parse

from core.intelligence.differential.representations import HttpRequest
from core.intelligence.metamorphic import MetamorphicEngine


def test_stable_server_no_violations():
    def probe(url, method="GET", headers=None, data=None):
        return 200, "<html>ok</html>", {"Content-Type": "text/html",
                                         "X-Content-Type-Options": "nosniff"}

    src = HttpRequest("home", "https://t.example/page?a=1&b=2", headers={"Accept": "*/*"})
    result = MetamorphicEngine(probe).run(src)
    assert not result.violated
    assert "query_param_order" in result.relations_run


def test_query_order_sensitivity_violates_relation():
    def probe(url, method="GET", headers=None, data=None):
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)
        first_val = pairs[0][1] if pairs else ""
        return 200, f"<html>{first_val}</html>", {"Content-Type": "text/html"}

    src = HttpRequest("q", "https://t.example/s?a=1&b=2", headers={"Accept": "*/*"})
    result = MetamorphicEngine(probe).run(src)
    assert any(v.relation == "query_param_order" for v in result.violations)


def test_header_case_sensitivity_violates_relation():
    def probe(url, method="GET", headers=None, data=None):
        h = headers or {}
        # Server wrongly treats lowercased header names as different.
        body = "DIFF" if ("accept" in h and "Accept" not in h) else "NORMAL"
        return 200, f"<html>{body}</html>", {"Content-Type": "text/html"}

    src = HttpRequest("h", "https://t.example/page", headers={"Accept": "*/*"})
    result = MetamorphicEngine(probe).run(src)
    viol = [v for v in result.violations if v.relation == "header_name_case_insensitivity"]
    assert viol and viol[0].severity == "medium"


def test_nondeterministic_gate_downgrades_low_signals():
    counter = {"n": 0}

    def probe(url, method="GET", headers=None, data=None):
        counter["n"] += 1
        # Body changes every call => endpoint is non-deterministic.
        return 200, f"<html>{counter['n']}</html>", {"Content-Type": "text/html"}

    src = HttpRequest("nd", "https://t.example/s?a=1&b=2", headers={"Accept": "*/*"})
    result = MetamorphicEngine(probe).run(src)
    assert result.nondeterministic is True
    # low/info relations must be downgraded to info, not reported as real bugs
    assert all(v.severity == "info" for v in result.violations
               if v.relation in ("query_param_order", "trailing_slash_equivalence"))
