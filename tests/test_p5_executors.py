"""PHASE 5 — executor wrappers integrate the research engines (offline)."""
import re
import urllib.parse

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionStatus
from core.execution.executors.differential_research import (
    DifferentialResearchExecutor,
    InvariantOracleExecutor,
    MetamorphicConsistencyExecutor,
)


def _exp(url, endpoints):
    return SecurityExperiment(
        hypothesis_id="h1", endpoint_id=url, capability="differential_research",
        input_parameters={"url": url, "endpoints": endpoints})


def test_no_url_is_schema_error():
    exp = SecurityExperiment(hypothesis_id="h", endpoint_id="", capability="c",
                             input_parameters={})
    assert DifferentialResearchExecutor().execute(exp).status == ExecutionStatus.SCHEMA_ERROR


def test_differential_executor_flags_vulnerable_parser():
    def probe(url, method="GET", headers=None, data=None):
        parsed = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        b = []
        if data:
            text = data.decode() if isinstance(data, bytes) else str(data)
            if "json" in (headers or {}).get("Content-Type", ""):
                b = re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', text)
            else:
                b = urllib.parse.parse_qsl(text, keep_blank_values=True)
        qv = [v for n, v in q if n == "q"]
        bv = [v for n, v in b if n == "q"]
        winner = (bv or qv or [None])[-1]        # body-overrides-query, last-wins
        if winner is not None:
            winner = urllib.parse.unquote(winner)  # double-decodes
        body = '{"value":null}' if winner is None else '{"value":"%s"}' % winner
        return 200, body, {"Content-Type": "application/json"}

    ex = DifferentialResearchExecutor()
    ex._probe = probe  # type: ignore[method-assign]
    result = ex.execute(_exp("https://t.example", ["https://t.example/api/echo?q=1"]))
    assert result.status == ExecutionStatus.SUCCESS
    assert "parser_findings" in result.evidence
    assert result.evidence["parser_findings"], "expected the vulnerable parser to be flagged"


def test_metamorphic_executor_flags_header_case_bug():
    def probe(url, method="GET", headers=None, data=None):
        h = headers or {}
        body = "DIFF" if ("accept" in h and "Accept" not in h) else "NORMAL"
        return 200, f"<html>{body}</html>", {"Content-Type": "text/html"}

    ex = MetamorphicConsistencyExecutor()
    ex._probe = probe  # type: ignore[method-assign]
    result = ex.execute(_exp("https://t.example", ["https://t.example/page"]))
    assert result.status == ExecutionStatus.SUCCESS
    assert result.evidence["metamorphic_findings"]


def test_invariant_executor_flags_stack_trace():
    def probe(url, method="GET", headers=None, data=None):
        return 500, "Traceback (most recent call last):\n File x", {"Content-Type": "text/plain"}

    ex = InvariantOracleExecutor()
    ex._probe = probe  # type: ignore[method-assign]
    result = ex.execute(_exp("https://t.example", ["https://t.example/api/data"]))
    assert result.status == ExecutionStatus.SUCCESS
    assert any(f["test"] == "invariant_no_stack_trace" for f in result.evidence["invariant_findings"])
