from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = ("username", "password", "login_url")


class AuthenticationExecutor(ExecutorBase):

    def validate_inputs(self, inputs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        missing = [k for k in REQUIRED_INPUTS if not inputs.get(k)]
        if missing:
            return False, f"Missing required inputs: {', '.join(missing)}"
        return True, None

    def has_credentials(self, inputs: Dict[str, Any]) -> bool:
        return bool(inputs.get("username") and inputs.get("password"))

    def validate_target(self, endpoint: Dict[str, Any], identity: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not endpoint.get("url"):
            return False, "Endpoint must have a 'url' field"
        return True, None

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        params = experiment.input_parameters
        valid, err = self.validate_inputs(params)
        if not valid:
            if not self.has_credentials(params):
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    error_code="NO_CREDENTIALS",
                    error_message="No credentials harvested — auth tests skipped (not a schema error)",
                )
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR, error_code="INVALID_INPUT", error_message=err)

        role = params.get("role", "default")
        logger.info(f"AuthenticationExecutor: testing role={role} user={params['username']} url={params['login_url']}")

        start = time.monotonic()
        try:
            import urllib.request
            import urllib.parse
            import urllib.error

            login_url = params["login_url"]
            data = urllib.parse.urlencode({
                "username": params["username"],
                "password": params["password"],
            }).encode()

            req = urllib.request.Request(login_url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout_seconds)
                status_code = resp.getcode()
                headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="replace")[:4096]
                cookie_header = resp.headers.get("Set-Cookie", "")
            except urllib.error.HTTPError as e:
                status_code = e.code
                headers = dict(e.headers)
                body = e.read().decode("utf-8", errors="replace")[:4096]
                cookie_header = e.headers.get("Set-Cookie", "")

            elapsed = (time.monotonic() - start) * 1000
            evidence = self.collect_evidence({
                "status_code": status_code,
                "response_headers": headers,
                "response_body": body,
                "cookies": cookie_header,
            })

            result_status = ExecutionStatus.SUCCESS if status_code < 400 else ExecutionStatus.FAILURE
            return ExecutionResult(status=result_status, evidence=evidence, execution_time_ms=elapsed)

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("AuthenticationExecutor failed: %s", exc)
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                error_code="EXECUTION_ERROR",
                error_message=str(exc),
                execution_time_ms=elapsed,
            )
