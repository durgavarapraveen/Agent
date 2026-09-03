from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = ("resource_url", "resource_id", "target_identity")


class AuthorizationExecutor(ExecutorBase):

    def validate_inputs(self, inputs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        missing = [k for k in REQUIRED_INPUTS if k not in inputs]
        if missing:
            return False, f"Missing required inputs: {', '.join(missing)}"
        return True, None

    def validate_target(self, endpoint: Dict[str, Any], identity: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        url = endpoint.get("url", "")
        if "{id}" not in url:
            return False, "Endpoint URL must contain '{id}' placeholder for IDOR testing"
        return True, None

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        params = experiment.input_parameters
        valid, err = self.validate_inputs(params)
        if not valid:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR, error_code="INVALID_INPUT", error_message=err)

        start = time.monotonic()
        try:
            import urllib.request
            import urllib.error

            resource_url = params["resource_url"].replace("{id}", str(params["resource_id"]))

            req = urllib.request.Request(resource_url, method="GET")

            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout_seconds)
                status_code = resp.getcode()
                body = resp.read().decode("utf-8", errors="replace")[:4096]
            except urllib.error.HTTPError as e:
                status_code = e.code
                body = e.read().decode("utf-8", errors="replace")[:4096]

            elapsed = (time.monotonic() - start) * 1000
            evidence = self.collect_evidence({
                "status_code": status_code,
                "response_body": body,
                "response_length": len(body),
            })

            return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence, execution_time_ms=elapsed)

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("AuthorizationExecutor failed: %s", exc)
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                error_code="EXECUTION_ERROR",
                error_message=str(exc),
                execution_time_ms=elapsed,
            )
