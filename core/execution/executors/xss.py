from __future__ import annotations

import html as _html
import json as _json
import logging
import re as _re
import time
from typing import Any, Dict, List, Optional, Tuple

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = ("injection_url", "injectable_param", "payloads")


def _classify_reflection(body: str, payload: str) -> Dict[str, Any]:
    """Context-aware XSS reflection analysis.

    Naive `payload in body` (the previous implementation) missed real XSS in
    HTML-attribute / JS-string / URL contexts where the payload is entity-
    encoded but still executable, and false-positived on any page that echoed
    the payload back in a safe context (e.g. inside `<textarea>` or a JSON
    blob).

    We now return a small dict describing WHERE and HOW the payload appeared:

        {
          "reflected": bool,          # any form of reflection
          "raw":        bool,          # exact bytes reflected as-is
          "html_encoded": bool,        # `<` → `&lt;` etc.
          "js_string":  bool,          # inside a JS string literal
          "attribute":  bool,          # inside an HTML attribute value
          "textarea":   bool,          # inside a <textarea> (usually safe)
          "json_only":  bool,          # only inside application/json content
          "likely_exploitable": bool,  # heuristic — see below
        }

    `likely_exploitable` = raw reflection outside a safe container (textarea,
    JSON, HTML comment), OR HTML-encoded reflection inside an unquoted
    attribute (still exploitable via broken-out event handlers).
    """
    if not payload or not body:
        return {"reflected": False, "raw": False, "html_encoded": False,
                "js_string": False, "attribute": False, "textarea": False,
                "json_only": False, "likely_exploitable": False}

    raw = payload in body
    encoded_variants = [
        _html.escape(payload),
        _html.escape(payload, quote=True),
    ]
    html_encoded = any(v in body for v in encoded_variants if v and v != payload)

    # Extract quick containers to disambiguate context.
    textarea_hits = _re.findall(r"<textarea[^>]*>(.*?)</textarea>", body,
                                 flags=_re.IGNORECASE | _re.DOTALL)
    inside_textarea = raw and any(payload in t for t in textarea_hits)

    comment_hits = _re.findall(r"<!--(.*?)-->", body, flags=_re.DOTALL)
    inside_comment = raw and any(payload in c for c in comment_hits)

    # Inside a JS string literal — a payload like `');alert(1);//` would
    # break out; naive raw reflection is only exploitable if not already
    # sanitized.
    js_string = False
    for m in _re.finditer(r"<script[^>]*>([\s\S]*?)</script>", body,
                           flags=_re.IGNORECASE):
        if payload in m.group(1):
            js_string = True
            break

    # Inside an HTML attribute value.
    attribute = bool(_re.search(
        rf'\s\w+\s*=\s*["\'][^"\']*{_re.escape(payload)}[^"\']*["\']',
        body,
    ))

    # JSON-only reflection: response looked like JSON and the payload only
    # appears inside a JSON string (indicated by preceding "). Weak signal —
    # if the response's declared CT was application/json this is very likely
    # not exploitable in a browser context.
    json_only = False
    try:
        # If body is a valid JSON document that contains the payload, treat
        # reflection as JSON-only unless there's also a raw HTML tag around.
        _json.loads(body)
        if raw and "<html" not in body.lower() and "<body" not in body.lower():
            json_only = True
    except Exception:
        pass

    reflected = raw or html_encoded

    likely_exploitable = False
    if raw and not (inside_textarea or inside_comment or json_only):
        likely_exploitable = True
    if html_encoded and attribute and not raw:
        # Encoded reflection inside an attribute — still risky via
        # broken-out event handlers if the value is unquoted.
        likely_exploitable = True

    return {
        "reflected": reflected, "raw": raw, "html_encoded": html_encoded,
        "js_string": js_string, "attribute": attribute,
        "textarea": inside_textarea, "json_only": json_only,
        "likely_exploitable": likely_exploitable,
    }


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

                    ctx = _classify_reflection(body, payload)
                    evidence_list.append({
                        "payload": payload,
                        "status_code": status_code,
                        "response_body": body,
                        "reflection_detected": ctx["reflected"],
                        "reflection_context": ctx,
                        "likely_exploitable": ctx["likely_exploitable"],
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
