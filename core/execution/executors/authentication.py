from __future__ import annotations

import logging
import re as _re
import time
from typing import Any, Dict, Optional, Tuple

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = ("username", "password", "login_url")

# Patterns that a login response containing them almost certainly means the
# credentials were REJECTED. Case-insensitive. A 200 OK with any of these in
# the body is a "wrong password" page — reporting it as SUCCESS was the source
# of hundreds of false auth-bypass findings.
_LOGIN_FAILURE_PATTERNS = [
    _re.compile(p, _re.IGNORECASE) for p in (
        r"\binvalid\s+(user|username|login|credentials|password)\b",
        r"\bincorrect\s+(user|username|login|credentials|password)\b",
        r"\blogin\s+(failed|failure|denied)\b",
        r"\bauthentication\s+(failed|failure|denied)\b",
        r"\bwrong\s+password\b",
        r"\baccess\s+denied\b",
        r"\bbad\s+credentials\b",
        r"try\s+again",
        r"\bunauthori[sz]ed\b",
    )
]

# Patterns that suggest the response is a SIGNED-IN dashboard / redirect
# target — reinforces the "success" verdict beyond just status code.
_LOGIN_SUCCESS_PATTERNS = [
    _re.compile(p, _re.IGNORECASE) for p in (
        r"\bwelcome[,!]?\s+\w+",
        r"\bsign[\s-]?out\b",
        r"\blog[\s-]?out\b",
        r"\bmy\s+account\b",
        r"\bdashboard\b",
    )
]


def _classify_login_response(status_code: int, body: str,
                             cookie_header: str) -> Dict[str, Any]:
    """Decide whether the login response actually granted access.

    Returns a dict with `verdict` in {SUCCESS, FAILURE, INCONCLUSIVE} and a
    `reason` string explaining why.
    """
    body = body or ""
    cookie_header = cookie_header or ""

    for rx in _LOGIN_FAILURE_PATTERNS:
        if rx.search(body):
            return {"verdict": "FAILURE",
                    "reason": f"login failure signal: {rx.pattern!r}",
                    "matched_failure": rx.pattern}

    # 3xx redirects to `/login` or `/error` are failures.
    if 300 <= status_code < 400:
        loc = ""
        # `resp.headers` was flattened into `body` for headers-in-body responses;
        # the caller passes cookie header separately. We only see the Location
        # header if the caller elected to include it — treat 3xx as ambiguous
        # unless the body clearly indicates failure (handled above).
        pass

    # A session cookie being set is a strong positive signal.
    cookie_signal = False
    if cookie_header:
        low = cookie_header.lower()
        for name in ("session", "sess", "sid", "auth", "token", "jwt", "phpsessid"):
            if name in low:
                cookie_signal = True
                break

    body_signal = any(rx.search(body) for rx in _LOGIN_SUCCESS_PATTERNS)

    if 200 <= status_code < 400 and (cookie_signal or body_signal):
        return {"verdict": "SUCCESS",
                "reason": "session cookie set" if cookie_signal else "signed-in-page markers matched"}

    if 200 <= status_code < 400 and not body_signal and not cookie_signal:
        # Ambiguous 200 — no error markers, but no success markers either.
        # Treat as INCONCLUSIVE to avoid false positives; a signed-in check
        # against a protected page is the next step for the caller.
        return {"verdict": "INCONCLUSIVE",
                "reason": "2xx with no failure or success markers"}

    if status_code >= 400:
        return {"verdict": "FAILURE",
                "reason": f"HTTP {status_code}"}

    return {"verdict": "INCONCLUSIVE", "reason": "unclassified"}


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
            classification = _classify_login_response(status_code, body, cookie_header)

            evidence = self.collect_evidence({
                "status_code": status_code,
                "response_headers": headers,
                "response_body": body,
                "cookies": cookie_header,
                "login_verdict": classification["verdict"],
                "login_verdict_reason": classification["reason"],
            })

            # Only report SUCCESS when the response actually shows signs of a
            # signed-in session. Previously any `status_code < 400` was
            # SUCCESS, which flagged every "wrong password" 200 page as an
            # auth bypass.
            if classification["verdict"] == "SUCCESS":
                result_status = ExecutionStatus.SUCCESS
            elif classification["verdict"] == "FAILURE":
                result_status = ExecutionStatus.FAILURE
            else:
                # INCONCLUSIVE — surface as FAILURE with a specific error code
                # so the retest engine can pick it up rather than being logged
                # as a credential compromise.
                result_status = ExecutionStatus.FAILURE
            return ExecutionResult(
                status=result_status, evidence=evidence, execution_time_ms=elapsed,
                error_code=None if result_status == ExecutionStatus.SUCCESS else (
                    "LOGIN_REJECTED" if classification["verdict"] == "FAILURE" else "LOGIN_INCONCLUSIVE"
                ),
                error_message=None if result_status == ExecutionStatus.SUCCESS else classification["reason"],
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("AuthenticationExecutor failed: %s", exc)
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                error_code="EXECUTION_ERROR",
                error_message=str(exc),
                execution_time_ms=elapsed,
            )
