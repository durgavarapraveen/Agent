from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = ("injection_url", "injectable_param", "payloads")


class XSSExecutor(ExecutorBase):

    def validate_inputs(self, inputs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        missing = [k for k in REQUIRED_INPUTS if k not in inputs]
        if missing:
            return False, f"Missing required inputs: {', '.join(missing)}"
        if not isinstance(inputs.get("payloads"), list) or not inputs["payloads"]:
            return False, "payloads must be a non-empty list"
        return True, None

    def validate_target(self, endpoint: Dict[str, Any], identity: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        accepts = endpoint.get("accepts_params", endpoint.get("parameters"))
        if not accepts:
            return False, "Endpoint must accept parameters"
        content_type = endpoint.get("content_type", "text/html")
        if "html" not in content_type.lower():
            return False, f"Endpoint must return HTML, got {content_type}"
        return True, None

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        params = experiment.input_parameters
        valid, err = self.validate_inputs(params)
        if not valid:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR, error_code="INVALID_INPUT", error_message=err)

        start = time.monotonic()
        evidence_list: List[Dict[str, Any]] = []

        try:
            import urllib.request
            import urllib.parse
            import urllib.error

            base_url = params["injection_url"]
            param_name = params["injectable_param"]

            for payload in params["payloads"]:
                encoded = urllib.parse.urlencode({param_name: payload})
                sep = "&" if "?" in base_url else "?"
                url = f"{base_url}{sep}{encoded}"

                try:
                    req = urllib.request.Request(url, method="GET")
                    try:
                        resp = urllib.request.urlopen(req, timeout=self.timeout_seconds)
                        status_code = resp.getcode()
                        body = resp.read().decode("utf-8", errors="replace")[:8192]
                    except urllib.error.HTTPError as e:
                        status_code = e.code
                        body = e.read().decode("utf-8", errors="replace")[:8192]

                    reflection_detected = payload in body
                    evidence_list.append({
                        "payload": payload,
                        "status_code": status_code,
                        "response_body": body,
                        "reflection_detected": reflection_detected,
                    })
                except Exception as payload_exc:
                    logger.warning("Payload failed: %s — %s", payload, payload_exc)
                    evidence_list.append({
                        "payload": payload,
                        "status_code": 0,
                        "response_body": "",
                        "reflection_detected": False,
                    })

            elapsed = (time.monotonic() - start) * 1000
            evidence = self.collect_evidence({"results": evidence_list})
            return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence, execution_time_ms=elapsed)

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("XSSExecutor failed: %s", exc)
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                evidence=self.collect_evidence({"results": evidence_list}),
                error_code="EXECUTION_ERROR",
                error_message=str(exc),
                execution_time_ms=elapsed,
            )
