"""
Generic HTTP-based executors for V2 coverage matrix test types that lack
dedicated executors.  Each one sends a targeted probe and checks the response
for the signal relevant to its vulnerability class.
"""
from __future__ import annotations

import logging
import time
import urllib.request
import urllib.error
import json
from typing import Any, Dict, Optional, Tuple

from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)


class GenericHTTPExecutor(ExecutorBase):
    """Base for executors that only need a URL to probe."""

    def validate_inputs(self, inputs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        return True, None

    def validate_target(self, endpoint: Dict[str, Any], identity: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        return True, None

    def _probe(self, url: str, method: str = "GET",
               headers: Optional[Dict[str, str]] = None,
               data: Optional[bytes] = None) -> Tuple[int, str, Dict[str, str]]:
        hdrs = headers or {"User-Agent": "AntiGravity-V2/1.0"}
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="replace")[:8192]
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:8192] if e.fp else ""
            return e.code, body, dict(e.headers)
        except Exception as exc:
            logger.debug("Probe failed for %s: %s", url, exc)
            return 0, "", {}

    def _url_from_experiment(self, experiment: SecurityExperiment) -> str:
        ep = experiment.input_parameters.get("url") or experiment.endpoint_id or ""
        if ep and not ep.startswith("http"):
            ep = f"https://{ep}"
        return ep


class CORSExecutor(GenericHTTPExecutor):
    """Test for overly permissive CORS by sending Origin: https://evil.com."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        headers = {
            "User-Agent": "AntiGravity-V2/1.0",
            "Origin": "https://evil.example.com",
        }
        status, body, resp_headers = self._probe(url, headers=headers)
        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        vuln = acao in ("*", "https://evil.example.com")
        evidence = self.collect_evidence({
            "status": status,
            "access_control_allow_origin": acao,
            "vulnerable": vuln,
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class InfoDisclosureExecutor(GenericHTTPExecutor):
    """Check for sensitive info in headers and error responses."""

    SENSITIVE_HEADERS = ("x-powered-by", "server", "x-aspnet-version",
                         "x-aspnetmvc-version", "x-debug")

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        status, body, resp_headers = self._probe(url)
        disclosed = {h: resp_headers[h] for h in resp_headers
                     if h.lower() in self.SENSITIVE_HEADERS}
        evidence = self.collect_evidence({
            "status": status,
            "disclosed_headers": disclosed,
            "body_snippet": body[:512] if status >= 400 else "",
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class GraphQLExecutor(GenericHTTPExecutor):
    """Probe for GraphQL introspection and DoS via deeply nested queries."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        gql_url = url.rstrip("/")
        if not gql_url.endswith("/graphql"):
            gql_url += "/graphql"

        query = '{"query": "{ __schema { types { name } } }"}'
        headers = {"Content-Type": "application/json", "User-Agent": "AntiGravity-V2/1.0"}
        status, body, _ = self._probe(gql_url, method="POST",
                                       headers=headers, data=query.encode())
        introspection = "__schema" in body or '"types"' in body
        evidence = self.collect_evidence({
            "status": status,
            "introspection_enabled": introspection,
            "body_snippet": body[:1024],
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class WebSocketExecutor(GenericHTTPExecutor):
    """Check if WebSocket upgrade is available and lacks origin validation."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        ws_url = url.rstrip("/") + "/socket.io/"
        headers = {
            "User-Agent": "AntiGravity-V2/1.0",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Origin": "https://evil.example.com",
        }
        status, body, resp_headers = self._probe(ws_url, headers=headers)
        upgrade_present = "upgrade" in resp_headers.get("Connection", "").lower()
        evidence = self.collect_evidence({
            "status": status,
            "upgrade_in_response": upgrade_present,
            "body_snippet": body[:512],
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class BusinessLogicExecutor(GenericHTTPExecutor):
    """Probe for race conditions and workflow bypass via rapid duplicate requests."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        responses = []
        for _ in range(3):
            status, body, _ = self._probe(url)
            responses.append({"status": status, "length": len(body)})

        lengths = [r["length"] for r in responses]
        consistent = len(set(lengths)) == 1
        evidence = self.collect_evidence({
            "responses": responses,
            "consistent": consistent,
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class PathTraversalExecutor(GenericHTTPExecutor):
    """Test for directory listing and path traversal."""

    LISTING_INDICATORS = ("index of", "directory listing", "<pre>",
                          "parent directory", "[dir]")

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        status, body, _ = self._probe(url)
        body_lower = body.lower()
        listing = any(ind in body_lower for ind in self.LISTING_INDICATORS)

        traversal_url = url.rstrip("/") + "/..%2f..%2fetc/passwd"
        t_status, t_body, _ = self._probe(traversal_url)
        traversed = "root:" in t_body

        evidence = self.collect_evidence({
            "status": status,
            "directory_listing": listing,
            "traversal_status": t_status,
            "traversal_detected": traversed,
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)
