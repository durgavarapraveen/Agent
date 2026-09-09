"""
PHASE 5 executors — bridge the differential / parser / metamorphic / invariant
research engines into the V2 executor pipeline.

Each executor reuses the discovery helpers and the scope-checked ``_probe`` of
``GenericHTTPExecutor`` and emits evidence dicts whose keys end in ``_findings``
so ``CentralBrain._ingest_executor_findings`` picks them up. They are tuned for
precision: representation-differential ignores "method not supported" statuses,
parser analysis only fires on reflected values, and metamorphic low-signals are
downgraded on non-deterministic endpoints.
"""
from __future__ import annotations

import time
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus
from core.execution.executors.generic import GenericHTTPExecutor
from core.intelligence.differential import DifferentialEngine, HttpRequest, ResponseSnapshot
from core.intelligence.invariants import InvariantEngine
from core.intelligence.metamorphic import MetamorphicEngine
from core.intelligence.parser_differential import ParserDifferentialEngine

_SEVERE = ("low", "medium", "high")
_UNSUPPORTED = {404, 405, 501}


class _ResearchBase(GenericHTTPExecutor):
    """Shared endpoint-selection helpers for the PHASE 5 executors."""

    def _param_targets(self, experiment: SecurityExperiment,
                       limit: int = 6) -> List[Tuple[str, str]]:
        """(url_without_query, param_name) pairs from discovered endpoints."""
        base = self._base(experiment)
        out: List[Tuple[str, str]] = []
        for ep in self._discovered_endpoints(experiment):
            full = ep if ep.startswith("http") else f"{base}/{ep.lstrip('/')}"
            parsed = urlparse(full)
            for pname in parse_qs(parsed.query):
                out.append((full.split("?")[0], pname))
        if not out:
            # Fall back to search/data endpoints with a conventional param.
            for path in self._to_paths(
                    self._endpoints_by_role(experiment, "search", "data"), base):
                out.append((f"{base}{path}", "q"))
        return list(dict.fromkeys(out))[:limit]

    def _url_targets(self, experiment: SecurityExperiment, limit: int = 8) -> List[str]:
        base = self._base(experiment)
        urls = [ep if ep.startswith("http") else f"{base}/{ep.lstrip('/')}"
                for ep in self._discovered_endpoints(experiment)]
        return list(dict.fromkeys(urls))[:limit] or [base]


class DifferentialResearchExecutor(_ResearchBase):
    """Parser-differential + request-representation differential testing."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        if not self._url_from_experiment(experiment):
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                   error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        auth = self._auth_headers(experiment)
        parser_findings: List[Dict] = []
        differential_findings: List[Dict] = []

        for clean_url, param in self._param_targets(experiment):
            try:
                analysis = ParserDifferentialEngine(self._probe).analyze(
                    clean_url, param, auth_headers=auth)
                for obs in analysis.observations:
                    if obs.severity in _SEVERE:
                        parser_findings.append(
                            {"test": "parser_differential", "path": clean_url,
                             "param": param, **obs.to_dict()})
            except Exception:  # never let one endpoint abort the sweep
                pass

            try:
                diff = DifferentialEngine(self._probe, ignore_statuses=_UNSUPPORTED)
                result = diff.run_equivalence(clean_url, {param: "1"}, auth_headers=auth)
                if result.max_severity() in ("medium", "high"):
                    for d in result.divergences:
                        if d.severity in ("medium", "high"):
                            differential_findings.append(
                                {"test": "representation_differential",
                                 "path": clean_url, "param": param, **d.to_dict()})
            except Exception:
                pass

        evidence = self.collect_evidence({
            "parser_findings": parser_findings,
            "differential_findings": differential_findings,
            "findings_count": len(parser_findings) + len(differential_findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class MetamorphicConsistencyExecutor(_ResearchBase):
    """Metamorphic-relation testing over discovered endpoints."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        if not self._url_from_experiment(experiment):
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                   error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        auth = self._auth_headers(experiment)
        findings: List[Dict] = []
        engine = MetamorphicEngine(self._probe)

        for url in self._url_targets(experiment):
            try:
                src = HttpRequest(label=url, url=url, headers=dict(auth))
                result = engine.run(src)
                for v in result.violations:
                    if v.severity in _SEVERE:
                        findings.append({"test": f"metamorphic_{v.relation}",
                                         "url": url, **v.to_dict()})
            except Exception:
                pass

        evidence = self.collect_evidence({
            "metamorphic_findings": findings, "findings_count": len(findings)})
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class InvariantOracleExecutor(_ResearchBase):
    """Run security invariants over sampled responses (incl. a 404 error page)."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        if not self._url_from_experiment(experiment):
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                   error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        auth = self._auth_headers(experiment)
        engine = InvariantEngine()
        findings: List[Dict] = []

        base = self._base(experiment)
        targets = self._url_targets(experiment, limit=10)
        # Sample the server's error page too — a common source of leakage.
        targets.append(f"{base}/antigravity-not-found-9f3a2b")

        for url in targets:
            try:
                status, body, headers = self._probe(url, headers=dict(auth))
                if status == 0:
                    continue
                snap = ResponseSnapshot(label=url, status=status, body=body,
                                        headers=dict(headers))
                for v in engine.check(snap):
                    findings.append({"test": f"invariant_{v.invariant}",
                                     "url": url, **v.to_dict()})
            except Exception:
                pass

        evidence = self.collect_evidence({
            "invariant_findings": findings, "findings_count": len(findings)})
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)
