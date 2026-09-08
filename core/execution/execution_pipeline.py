from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.domain.experiment import SecurityExperiment, ExperimentState
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase
from core.evidence.evidence import Evidence
from core.evidence.validator import EvidenceValidator, ValidationResult
from core.findings.finding import Finding, FindingState
from core.findings.finding_state_machine import FindingStateMachine
from core.findings.finding_store import FindingStore
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.tools.tool_portfolio import ToolPortfolio

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    SETUP = "setup"
    EXECUTE = "execute"
    COLLECT = "collect"
    VALIDATE = "validate"
    RECORD = "record"


@dataclass
class PipelineResult:
    experiment_id: str
    success: bool
    stage_reached: PipelineStage
    execution_result: Optional[ExecutionResult] = None
    evidence: Optional[Evidence] = None
    validation: Optional[ValidationResult] = None
    finding: Optional[Finding] = None
    coverage_delta: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class ExecutionPipelineV2:

    def __init__(
        self,
        executor_registry: Dict[str, ExecutorBase],
        tool_portfolio: ToolPortfolio,
        coverage_matrix: CoverageMatrix,
        finding_store: FindingStore,
        evidence_validator: Optional[EvidenceValidator] = None,
    ) -> None:
        self.executors = executor_registry
        self.portfolio = tool_portfolio
        self.matrix = coverage_matrix
        self.finding_store = finding_store
        self.validator = evidence_validator or EvidenceValidator()
        self.finding_sm = FindingStateMachine()

    def execute(self, experiment: SecurityExperiment) -> PipelineResult:
        result = PipelineResult(experiment_id=experiment.experiment_id, success=False, stage_reached=PipelineStage.SETUP)

        # SETUP
        setup_ok, setup_err = self._setup(experiment)
        if not setup_ok:
            result.error = setup_err
            return result

        # EXECUTE
        result.stage_reached = PipelineStage.EXECUTE
        exec_result = self._execute(experiment)
        result.execution_result = exec_result
        if exec_result.status in (ExecutionStatus.SCHEMA_ERROR, ExecutionStatus.AUTHORIZATION_ERROR):
            result.error = exec_result.error_message
            self._update_coverage(experiment, CoverageState.BLOCKED)
            result.coverage_delta = {"state": "blocked"}
            return result

        if exec_result.status == ExecutionStatus.FAILURE and exec_result.error_code:
            result.error = exec_result.error_message
            self._update_coverage(experiment, CoverageState.BLOCKED)
            result.coverage_delta = {"state": "blocked"}
            return result

        # COLLECT
        result.stage_reached = PipelineStage.COLLECT
        evidence = self._collect(experiment, exec_result)
        result.evidence = evidence

        # VALIDATE
        result.stage_reached = PipelineStage.VALIDATE
        validation = self._validate(experiment, evidence)
        result.validation = validation

        # RECORD
        result.stage_reached = PipelineStage.RECORD
        finding = self._record(experiment, evidence, validation)
        result.finding = finding
        result.success = True
        result.coverage_delta = {"state": finding.state if finding else "tested"}
        return result

    def _setup(self, experiment: SecurityExperiment) -> tuple:
        if not experiment.capability:
            return False, "No capability specified"
        if not experiment.endpoint_id:
            return False, "No endpoint specified"
        return True, None

    @staticmethod
    def _authorize_target(experiment: SecurityExperiment) -> Tuple[bool, Optional[str]]:
        """Enforce scope authorization for THIS specific experiment before firing.

        Called from `_execute` before every executor invocation. Historically,
        `ExecutorBase.validate_target()` was declared but never invoked anywhere
        in `core/` — all ~85 offensive executors ran without a per-request scope
        check. This is the single choke point that closes that gap.

        Prefers the unified `ScopeAuthority` façade (which fans out to every
        wired back-end). Falls back to the legacy `TargetScopeValidator` if the
        façade isn't wired yet, so nothing regresses on partial deployments.
        """
        # Extract a URL/host from wherever the experiment carries it.
        params = experiment.input_parameters or {}
        candidate = (
            params.get("url")
            or params.get("target")
            or params.get("endpoint")
            or params.get("host")
            or experiment.endpoint_id
            or ""
        )
        if not candidate:
            return False, "No target URL/host on experiment — refusing to execute"

        # Preferred path: unified façade.
        try:
            from core.security.scope_facade import get_scope_authority
            auth = get_scope_authority()
            status = auth.enforcement_status()
            wired_backends = sum(1 for k, v in status.items()
                                  if k != "auto_scope_size" and v)
            if wired_backends > 0:
                try:
                    ok = auth.is_authorized(candidate)
                except Exception as e:
                    logger.error("ScopeAuthority raised: %s", e)
                    return False, f"Scope authority error: {e}"
                if not ok:
                    return False, f"Target out of authorized scope: {candidate}"
                return True, None
        except Exception:
            pass  # fall through to legacy

        try:
            from core.security.authorization import TargetScopeValidator
        except Exception:
            return False, "TargetScopeValidator import failed — refusing to execute"

        try:
            validator = TargetScopeValidator.get()
            ok = bool(validator.validate(candidate))
        except Exception as e:
            logger.error("Scope validation raised: %s", e)
            return False, f"Scope validation error: {e}"

        if not ok:
            return False, f"Target out of authorized scope: {candidate}"
        return True, None

    def _execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        # ── Per-request authorization gate ────────────────────────────────
        authorized, authz_err = self._authorize_target(experiment)
        if not authorized:
            logger.warning("Executor refused: %s", authz_err)
            return ExecutionResult(
                status=ExecutionStatus.AUTHORIZATION_ERROR,
                error_code="OUT_OF_SCOPE",
                error_message=authz_err,
            )

        executor = self.executors.get(experiment.capability)
        if executor is None:
            tools = self.portfolio.get_tools(experiment.capability)
            for tool_name in tools:
                executor = self.executors.get(tool_name)
                if executor:
                    break

        if executor is None:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                error_code="NO_EXECUTOR",
                error_message=f"No executor for capability '{experiment.capability}'",
            )

        # If the executor overrides validate_target with a real (non-no-op) check,
        # call it too so subclass-specific policy still applies. Base class returns
        # (True, None) unconditionally; that no-op is now safely composed with the
        # scope gate above.
        try:
            endpoint_dict = {
                "url": (experiment.input_parameters or {}).get("url") or experiment.endpoint_id,
                "id": experiment.endpoint_id,
                **(experiment.input_parameters or {}),
            }
            identity_dict = (experiment.input_parameters or {}).get("identity", {}) or {}
            ok, why = executor.validate_target(endpoint_dict, identity_dict)
            if not ok:
                return ExecutionResult(
                    status=ExecutionStatus.AUTHORIZATION_ERROR,
                    error_code="EXECUTOR_REJECT",
                    error_message=why or "Executor validate_target refused",
                )
        except Exception as e:
            logger.debug("Executor validate_target raised (treated as pass): %s", e)

        try:
            return executor.execute(experiment)
        except Exception as exc:
            logger.error("Executor exception: %s", exc)
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                error_code="EXECUTION_ERROR",
                error_message=str(exc),
            )

    def _collect(self, experiment: SecurityExperiment, exec_result: ExecutionResult) -> Evidence:
        return Evidence(
            tool_name=experiment.capability,
            command=f"execute:{experiment.capability}:{experiment.endpoint_id}",
            stdout=str(exec_result.evidence),
            stderr=exec_result.error_message or "",
        )

    def _validate(self, experiment: SecurityExperiment, evidence: Evidence) -> ValidationResult:
        from core.evidence.oracle import ErrorSignatureOracle
        oracle = ErrorSignatureOracle()
        signal = experiment.expected_signals[0] if experiment.expected_signals else "vulnerability"
        return self.validator.validate(evidence, oracle, signal)

    def _record(self, experiment: SecurityExperiment, evidence: Evidence, validation: ValidationResult) -> Optional[Finding]:
        if validation.valid:
            state = FindingState.CONFIRMED
            cov_state = CoverageState.CONFIRMED
        else:
            state = FindingState.REJECTED
            cov_state = CoverageState.REJECTED

        self._update_coverage(experiment, cov_state, evidence.evidence_id)

        # Only create findings for confirmed vulnerabilities — rejected experiments
        # are coverage matrix entries, not actual findings
        if not validation.valid:
            return None

        finding = Finding(
            title=f"{experiment.capability} on {experiment.endpoint_id}",
            description=f"Test {experiment.capability} against {experiment.endpoint_id}",
            severity="MEDIUM",
            affected_endpoint=experiment.endpoint_id,
            state=state.value,
            evidence_ids=[evidence.evidence_id],
        )
        self.finding_store.store(finding)
        return finding

    def _update_coverage(self, experiment: SecurityExperiment, state: CoverageState, evidence_id: Optional[str] = None) -> None:
        self.matrix.update_state(experiment.endpoint_id, experiment.capability, state, evidence_id)
