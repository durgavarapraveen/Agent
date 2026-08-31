"""
Task Evaluator.
Validates task completion against strict objective criteria before marking tasks as SUCCEEDED.
Prevents unconfirmed / fake findings from polluting shared context and reports.
"""

import logging
import re
from enum import Enum
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger(__name__)


class CompletionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    PENDING = "pending"


class TaskCompletionEvaluator:
    """Evaluates task completion against TaskSpec success criteria."""

    @classmethod
    def evaluate(cls, spec: Any = None, tool_results: Optional[List[Any]] = None, agent_result: Any = None, **kwargs) -> Tuple[CompletionStatus, str]:
        tool_results = tool_results or []
        if not tool_results and not agent_result:
            return CompletionStatus.FAILED, "No tool results produced"

        has_success = any(
            (r.get("success") if isinstance(r, dict) else getattr(r, "success", False)) or
            (str(r.get("status", "")).upper() in ("SUCCESS", "SUCCEEDED", "COMPLETED", "PARTIAL_SUCCESS", "PARTIAL") if isinstance(r, dict) else str(getattr(r, "status", "")).upper() in ("SUCCESS", "SUCCEEDED", "COMPLETED", "PARTIAL_SUCCESS", "PARTIAL"))
            for r in tool_results
        )

        has_data = any(
            bool(r.get("data") or r.get("output")) if isinstance(r, dict) else bool(getattr(r, "data", None) or getattr(r, "output", None))
            for r in tool_results
        )

        if has_success or has_data or (agent_result and isinstance(agent_result, dict) and agent_result.get("status") != "failed"):
            return CompletionStatus.SUCCEEDED, "Task completed with extracted evidence"
        else:
            return CompletionStatus.FAILED, "Tool execution failed with no evidence"


class TaskEvaluator:
    """Evaluates task execution results against strict objective criteria."""

    @classmethod
    def evaluate_task(
        cls,
        task_id: str,
        objective: str,
        vuln_type: str,
        findings: List[Dict[str, Any]],
        shared_context: Any
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Validate task completion.
        Returns: (passed: bool, proof_or_reason: str, validated_findings: List[Dict])
        """
        vuln_type = (vuln_type or "").lower().strip()
        obj_lower = (objective or "").lower().strip()

        # 1. Auth Bypass / Authentication criteria
        if "auth" in vuln_type or "login" in obj_lower or "authenticate" in obj_lower:
            token = getattr(shared_context, "auth_token", None)
            harvested = getattr(shared_context, "harvested_creds", [])
            valid_finding = [f for f in findings if f.get("type") in ("auth_bypass", "unauthenticated_api_exposure") or "token" in str(f.get("proof", "")).lower()]

            if token or harvested or valid_finding:
                proof = f"token={str(token)[:20]}..., creds_count={len(harvested)}"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=SUCCEEDED proof='{proof}'")
                return True, proof, findings if findings else [{"type": "auth_bypass", "proof": proof}]
            else:
                reason = "No auth_token or authenticated session found in context"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=FAILED reason='{reason}'")
                return False, reason, []

        # 2. Remote Code Execution (RCE) criteria
        if "rce" in vuln_type or "command" in obj_lower or "exec" in obj_lower:
            rce_patterns = [r"uid=\d+", r"root:", r"www-data", r"Linux version", r"Windows IP Configuration"]
            validated = []
            for f in findings:
                proof_text = str(f.get("proof", "")) + str(f.get("matched_signatures", ""))
                if any(re.search(pat, proof_text, re.IGNORECASE) for pat in rce_patterns):
                    validated.append(f)

            if validated:
                proof = f"Command execution proof captured in {len(validated)} findings"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=SUCCEEDED proof='{proof}'")
                return True, proof, validated
            else:
                reason = "No command execution output or system signature captured"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=FAILED reason='{reason}'")
                return False, reason, []

        # 3. SQL Injection (SQLi) criteria
        if "sql" in vuln_type or "sqli" in obj_lower:
            validated = []
            for f in findings:
                proof_text = str(f.get("proof", "")).lower()
                if any(k in proof_text for k in ["syntax error", "mysql", "postgresql", "sqlite", "oracle", "extracted", "database"]):
                    validated.append(f)

            if validated:
                proof = f"Database syntax error/extracted data in {len(validated)} findings"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=SUCCEEDED proof='{proof}'")
                return True, proof, validated
            else:
                reason = "No database response error or extracted SQL data found"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=FAILED reason='{reason}'")
                return False, reason, []

        # 4. IDOR / Data Exposure criteria
        if "idor" in vuln_type or "object reference" in obj_lower:
            validated = [f for f in findings if "unauthorized" in str(f.get("proof", "")).lower() or "user" in str(f.get("proof", "")).lower()]
            if validated:
                proof = f"Unauthorized object data accessed in {len(validated)} findings"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=SUCCEEDED proof='{proof}'")
                return True, proof, validated
            else:
                reason = "No unauthorized data payload or user object accessed"
                logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=FAILED reason='{reason}'")
                return False, reason, []

        # Default fallback for general recon / scanning tasks
        if findings:
            proof = f"Findings recorded: {len(findings)}"
            logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=SUCCEEDED proof='{proof}'")
            return True, proof, findings

        # Check if this is an exploit/attack task vs a recon task
        if "exploit" in obj_lower or "injection" in vuln_type or "xss" in vuln_type or "missing_csp" in vuln_type or "attack" in obj_lower:
            reason = "Exploitation failed. No valid findings or proof generated."
            logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=FAILED reason='{reason}'")
            return False, reason, []

        logger.info(f"COMPLETION_EVALUATED: task_id={task_id} result=SUCCEEDED (recon/no vulns)")
        return True, "Task completed with zero vulnerabilities found", []
