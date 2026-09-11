from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class AuditSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AuditFinding:
    component: str
    check: str
    severity: AuditSeverity
    passed: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "check": self.check,
            "severity": self.severity.value,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class AuditReport:
    findings: List[AuditFinding] = field(default_factory=list)
    passed: bool = True

    def add(self, f: AuditFinding) -> None:
        self.findings.append(f)
        if not f.passed and f.severity in (AuditSeverity.WARNING, AuditSeverity.CRITICAL):
            self.passed = False

    @property
    def critical_failures(self) -> List[AuditFinding]:
        return [f for f in self.findings if not f.passed and f.severity == AuditSeverity.CRITICAL]

    @property
    def warnings(self) -> List[AuditFinding]:
        return [f for f in self.findings if not f.passed and f.severity == AuditSeverity.WARNING]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "total_checks": len(self.findings),
            "passed_checks": sum(1 for f in self.findings if f.passed),
            "failed_checks": sum(1 for f in self.findings if not f.passed),
            "critical_failures": len(self.critical_failures),
            "findings": [f.to_dict() for f in self.findings],
        }


def _check_policy_engine() -> List[AuditFinding]:
    findings = []
    try:
        from core.security.policy_engine import get_policy_engine
        engine = get_policy_engine()
        findings.append(AuditFinding(
            "PolicyEngine", "singleton_available",
            AuditSeverity.CRITICAL, True, "PolicyEngine singleton exists"))

        decision = engine.authorize_network("http://127.0.0.1/admin", method="GET")
        if decision.allowed:
            findings.append(AuditFinding(
                "PolicyEngine", "localhost_denied",
                AuditSeverity.CRITICAL, False,
                "PolicyEngine allowed request to localhost"))
        else:
            findings.append(AuditFinding(
                "PolicyEngine", "localhost_denied",
                AuditSeverity.CRITICAL, True,
                "PolicyEngine correctly denies localhost"))

        decision = engine.authorize_subprocess("rm", args=["-rf", "/"])
        if decision.allowed:
            findings.append(AuditFinding(
                "PolicyEngine", "destructive_cmd_denied",
                AuditSeverity.CRITICAL, False,
                "PolicyEngine allowed destructive command"))
        else:
            findings.append(AuditFinding(
                "PolicyEngine", "destructive_cmd_denied",
                AuditSeverity.CRITICAL, True,
                "PolicyEngine correctly denies destructive commands"))

    except ImportError:
        findings.append(AuditFinding(
            "PolicyEngine", "singleton_available",
            AuditSeverity.CRITICAL, False, "PolicyEngine not importable"))
    except Exception as e:
        findings.append(AuditFinding(
            "PolicyEngine", "singleton_available",
            AuditSeverity.CRITICAL, False, f"PolicyEngine error: {e}"))
    return findings


def _check_network_broker() -> List[AuditFinding]:
    findings = []
    try:
        from core.network.network_broker import get_network_broker
        broker = get_network_broker()
        findings.append(AuditFinding(
            "NetworkBroker", "singleton_available",
            AuditSeverity.CRITICAL, True, "NetworkBroker singleton exists"))

        decision = broker.check_url("http://169.254.169.254/latest/meta-data/")
        if decision.allowed:
            findings.append(AuditFinding(
                "NetworkBroker", "cloud_metadata_denied",
                AuditSeverity.CRITICAL, False,
                "NetworkBroker allowed cloud metadata endpoint"))
        else:
            findings.append(AuditFinding(
                "NetworkBroker", "cloud_metadata_denied",
                AuditSeverity.CRITICAL, True,
                "NetworkBroker correctly denies cloud metadata"))

        decision = broker.check_url("http://[::1]/admin")
        if decision.allowed:
            findings.append(AuditFinding(
                "NetworkBroker", "ipv6_loopback_denied",
                AuditSeverity.CRITICAL, False,
                "NetworkBroker allowed IPv6 loopback"))
        else:
            findings.append(AuditFinding(
                "NetworkBroker", "ipv6_loopback_denied",
                AuditSeverity.CRITICAL, True,
                "NetworkBroker correctly denies IPv6 loopback"))

    except ImportError:
        findings.append(AuditFinding(
            "NetworkBroker", "singleton_available",
            AuditSeverity.WARNING, False, "NetworkBroker not importable"))
    except Exception as e:
        findings.append(AuditFinding(
            "NetworkBroker", "singleton_available",
            AuditSeverity.WARNING, False, f"NetworkBroker error: {e}"))
    return findings


def _check_sandbox() -> List[AuditFinding]:
    findings = []
    try:
        from core.execution.sandbox import get_execution_controller
        ctrl = get_execution_controller()
        findings.append(AuditFinding(
            "ExecutionController", "singleton_available",
            AuditSeverity.CRITICAL, True, "ExecutionController singleton exists"))

        lint_result = ctrl.lint_code("import os; os.system('rm -rf /')")
        if lint_result is None:
            findings.append(AuditFinding(
                "ExecutionController", "destructive_lint",
                AuditSeverity.WARNING, False,
                "lint_code did not flag destructive pattern"))
        else:
            findings.append(AuditFinding(
                "ExecutionController", "destructive_lint",
                AuditSeverity.WARNING, True,
                f"lint_code flagged destructive pattern: {lint_result}"))

    except ImportError:
        findings.append(AuditFinding(
            "ExecutionController", "singleton_available",
            AuditSeverity.WARNING, False, "ExecutionController not importable"))
    except Exception as e:
        findings.append(AuditFinding(
            "ExecutionController", "singleton_available",
            AuditSeverity.WARNING, False, f"ExecutionController error: {e}"))
    return findings


def _check_tool_validator() -> List[AuditFinding]:
    findings = []
    try:
        from core.security.tool_validator import validate_authored_code
        result = validate_authored_code("exec(input())", name="test_exec")
        if result.blocked:
            findings.append(AuditFinding(
                "ToolValidator", "exec_blocked",
                AuditSeverity.CRITICAL, True,
                "exec() correctly blocked"))
        else:
            findings.append(AuditFinding(
                "ToolValidator", "exec_blocked",
                AuditSeverity.CRITICAL, False,
                "exec() was NOT blocked"))

        result = validate_authored_code("import subprocess; subprocess.run(['ls'])",
                                        name="test_subprocess")
        if result.blocked:
            findings.append(AuditFinding(
                "ToolValidator", "subprocess_blocked",
                AuditSeverity.CRITICAL, True,
                "subprocess correctly blocked"))
        else:
            findings.append(AuditFinding(
                "ToolValidator", "subprocess_blocked",
                AuditSeverity.CRITICAL, False,
                "subprocess was NOT blocked"))

        result = validate_authored_code("import httpx\nresult = httpx.get(url)",
                                        name="test_http")
        if result.valid:
            findings.append(AuditFinding(
                "ToolValidator", "http_allowed",
                AuditSeverity.INFO, True,
                "HTTP-only tool correctly allowed"))
        else:
            findings.append(AuditFinding(
                "ToolValidator", "http_allowed",
                AuditSeverity.WARNING, False,
                f"HTTP-only tool incorrectly blocked: {result.blocked_reason}"))

    except ImportError:
        findings.append(AuditFinding(
            "ToolValidator", "available",
            AuditSeverity.WARNING, False, "ToolValidator not importable"))
    except Exception as e:
        findings.append(AuditFinding(
            "ToolValidator", "available",
            AuditSeverity.WARNING, False, f"ToolValidator error: {e}"))
    return findings


def _check_secret_vault() -> List[AuditFinding]:
    findings = []
    try:
        from core.security.secret_vault import SecretVault
        vault = SecretVault.get()
        findings.append(AuditFinding(
            "SecretVault", "singleton_available",
            AuditSeverity.CRITICAL, True, "SecretVault singleton exists"))

        test_secret = "Bearer test_audit_token_12345678"
        ref = vault.store(test_secret, category="bearer_token", retention=1.0)
        if "<SECRET_REF:" in ref:
            findings.append(AuditFinding(
                "SecretVault", "store_returns_ref",
                AuditSeverity.CRITICAL, True,
                "store() returns reference, not raw secret"))
        else:
            findings.append(AuditFinding(
                "SecretVault", "store_returns_ref",
                AuditSeverity.CRITICAL, False,
                "store() did not return a reference"))

        raw = vault.retrieve(ref)
        if raw == test_secret:
            findings.append(AuditFinding(
                "SecretVault", "retrieve_works",
                AuditSeverity.INFO, True,
                "retrieve() returns original secret"))
        else:
            findings.append(AuditFinding(
                "SecretVault", "retrieve_works",
                AuditSeverity.WARNING, False,
                "retrieve() did not return original"))

        redacted = vault.redact(f"Authorization: {test_secret}")
        if test_secret not in redacted and "<SECRET_REF:" in redacted:
            findings.append(AuditFinding(
                "SecretVault", "redact_removes_secrets",
                AuditSeverity.CRITICAL, True,
                "redact() removes raw secrets from text"))
        else:
            findings.append(AuditFinding(
                "SecretVault", "redact_removes_secrets",
                AuditSeverity.CRITICAL, False,
                "redact() did NOT remove raw secret"))

    except ImportError:
        findings.append(AuditFinding(
            "SecretVault", "singleton_available",
            AuditSeverity.WARNING, False, "SecretVault not importable"))
    except Exception as e:
        findings.append(AuditFinding(
            "SecretVault", "singleton_available",
            AuditSeverity.WARNING, False, f"SecretVault error: {e}"))
    return findings


def _check_docker_socket() -> List[AuditFinding]:
    findings = []
    try:
        from core.security.docker_socket_guard import check_socket_mount
        result = check_socket_mount()
        findings.append(AuditFinding(
            "DockerSocket", "not_mounted",
            AuditSeverity.CRITICAL, result.safe,
            result.reason))
        if not result.safe and result.docker_host_value:
            findings.append(AuditFinding(
                "DockerSocket", "env_not_set",
                AuditSeverity.CRITICAL, False,
                f"DOCKER_HOST references socket: {result.docker_host_value}"))
        elif result.safe:
            findings.append(AuditFinding(
                "DockerSocket", "env_not_set",
                AuditSeverity.INFO, True,
                "DOCKER_HOST does not reference docker socket"))
    except ImportError:
        findings.append(AuditFinding(
            "DockerSocket", "not_mounted",
            AuditSeverity.WARNING, False,
            "docker_socket_guard module not importable"))
    return findings


def run_audit() -> AuditReport:
    report = AuditReport()
    for check_fn in (_check_policy_engine, _check_network_broker,
                     _check_sandbox, _check_tool_validator,
                     _check_secret_vault, _check_docker_socket):
        try:
            for f in check_fn():
                report.add(f)
        except Exception as e:
            report.add(AuditFinding(
                check_fn.__name__, "execution",
                AuditSeverity.WARNING, False, f"check failed: {e}"))

    n_pass = sum(1 for f in report.findings if f.passed)
    n_fail = sum(1 for f in report.findings if not f.passed)
    logger.info("[FailOpenAudit] %d passed, %d failed, overall=%s",
                n_pass, n_fail, "PASS" if report.passed else "FAIL")
    return report
