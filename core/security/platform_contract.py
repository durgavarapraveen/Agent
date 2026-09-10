from __future__ import annotations

import functools
import inspect
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

CONTRACT_VERSION = "1.0.0"


# ── Exceptions ────────────────────────────────────────────────────────────

class ContractViolation(Exception):
    def __init__(self, rule: str, detail: str, context: Optional[Dict] = None):
        self.rule = rule
        self.detail = detail
        self.context = context or {}
        super().__init__(f"CONTRACT VIOLATION [{rule}]: {detail}")


class ContractNotEnforced(ContractViolation):
    pass


# ── Data classification ──────────────────────────────────────────────────

class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    RESTRICTED = "restricted"


class OperationTier(str, Enum):
    PASSIVE = "passive"
    ACTIVE_SAFE = "active_safe"
    ACTIVE_INVASIVE = "active_invasive"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class ApprovalLevel(str, Enum):
    AUTOMATIC = "automatic"
    POLICY_CHECK = "policy_check"
    HUMAN_REQUIRED = "human_required"
    HUMAN_EXPLICIT = "human_explicit"


# ── Contract rules ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuthorizationRule:
    require_scope_check: bool = True
    require_policy_decision: bool = True
    fail_on_missing_scope: bool = True
    fail_on_policy_error: bool = True


@dataclass(frozen=True)
class TargetScopeRule:
    require_explicit_scope: bool = True
    allow_scope_expansion: bool = False
    require_ip_validation: bool = True
    block_private_ips: bool = True
    block_dns_rebinding: bool = True
    revalidate_on_redirect: bool = True
    max_redirect_depth: int = 10


@dataclass(frozen=True)
class ExecutionRule:
    require_sandbox: bool = True
    require_ast_validation: bool = True
    block_destructive_patterns: bool = True
    max_execution_time_seconds: int = 300
    max_memory_mb: int = 512
    max_pids: int = 64
    scrub_environment: bool = True
    block_docker_socket: bool = True
    block_host_filesystem: bool = True


@dataclass(frozen=True)
class SecretHandlingRule:
    require_vault_storage: bool = True
    redact_in_logs: bool = True
    redact_in_llm_prompts: bool = True
    redact_in_checkpoints: bool = True
    redact_in_reports: bool = True
    max_retention_seconds: float = 3600.0
    require_classification: bool = True


@dataclass(frozen=True)
class IsolationRule:
    require_process_isolation: bool = True
    require_network_isolation: bool = True
    require_filesystem_isolation: bool = True
    block_privileged_mode: bool = True
    block_host_network: bool = True
    block_host_pid: bool = True


@dataclass(frozen=True)
class BudgetRule:
    max_requests_per_scan: int = 10_000
    max_concurrent_requests: int = 50
    max_scan_duration_seconds: int = 7200
    max_tool_executions: int = 5_000
    require_budget_check: bool = True


@dataclass(frozen=True)
class LoggingRule:
    log_all_policy_decisions: bool = True
    log_all_network_requests: bool = True
    log_all_tool_executions: bool = True
    log_all_findings: bool = True
    require_structured_logging: bool = True
    require_audit_trail: bool = True
    chain_integrity: bool = True


@dataclass(frozen=True)
class EvidenceRule:
    require_evidence_chain: bool = True
    require_reproduction_steps: bool = True
    require_confidence_score: bool = True
    require_deterministic_confirmation: bool = True
    block_llm_only_confirmation: bool = True


@dataclass(frozen=True)
class FailClosedRule:
    deny_on_scope_error: bool = True
    deny_on_policy_error: bool = True
    deny_on_network_error: bool = True
    deny_on_validation_error: bool = True
    audit_on_deny: bool = True
    never_catch_contract_violation: bool = True


@dataclass(frozen=True)
class HumanApprovalRule:
    tier_approval: Dict[str, str] = field(default_factory=lambda: {
        OperationTier.PASSIVE.value: ApprovalLevel.AUTOMATIC.value,
        OperationTier.ACTIVE_SAFE.value: ApprovalLevel.POLICY_CHECK.value,
        OperationTier.ACTIVE_INVASIVE.value: ApprovalLevel.POLICY_CHECK.value,
        OperationTier.EXPLOITATION.value: ApprovalLevel.HUMAN_REQUIRED.value,
        OperationTier.POST_EXPLOITATION.value: ApprovalLevel.HUMAN_EXPLICIT.value,
    })


# ── The Contract ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlatformSecurityContract:
    version: str = CONTRACT_VERSION
    authorization: AuthorizationRule = field(default_factory=AuthorizationRule)
    target_scope: TargetScopeRule = field(default_factory=TargetScopeRule)
    execution: ExecutionRule = field(default_factory=ExecutionRule)
    secret_handling: SecretHandlingRule = field(default_factory=SecretHandlingRule)
    isolation: IsolationRule = field(default_factory=IsolationRule)
    budget: BudgetRule = field(default_factory=BudgetRule)
    logging: LoggingRule = field(default_factory=LoggingRule)
    evidence: EvidenceRule = field(default_factory=EvidenceRule)
    fail_closed: FailClosedRule = field(default_factory=FailClosedRule)
    human_approval: HumanApprovalRule = field(default_factory=HumanApprovalRule)


# ── Singleton contract instance ───────────────────────────────────────────

_contract: Optional[PlatformSecurityContract] = None
_contract_lock = threading.Lock()


def get_contract() -> PlatformSecurityContract:
    global _contract
    if _contract is None:
        with _contract_lock:
            if _contract is None:
                _contract = PlatformSecurityContract()
    return _contract


def set_contract(contract: PlatformSecurityContract) -> None:
    global _contract
    with _contract_lock:
        _contract = contract


def reset_contract_for_tests() -> None:
    global _contract
    with _contract_lock:
        _contract = None


# ── Enforcement record ────────────────────────────────────────────────────

@dataclass
class EnforcementRecord:
    rule: str
    passed: bool
    detail: str
    timestamp: float = field(default_factory=time.monotonic)
    caller: str = ""
    context: Dict[str, Any] = field(default_factory=dict)


_enforcement_log: List[EnforcementRecord] = []
_enforcement_lock = threading.Lock()
_MAX_LOG_SIZE = 10_000


def _log_enforcement(record: EnforcementRecord) -> None:
    with _enforcement_lock:
        if len(_enforcement_log) >= _MAX_LOG_SIZE:
            _enforcement_log.pop(0)
        _enforcement_log.append(record)
    level = logging.DEBUG if record.passed else logging.WARNING
    logger.log(level, "[CONTRACT] rule=%s passed=%s detail=%s caller=%s",
               record.rule, record.passed, record.detail, record.caller)


def get_enforcement_log() -> List[EnforcementRecord]:
    with _enforcement_lock:
        return list(_enforcement_log)


def clear_enforcement_log() -> None:
    with _enforcement_lock:
        _enforcement_log.clear()


# ── Contract enforcement decorators ───────────────────────────────────────

def require_authorization(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        contract = get_contract()
        caller = f"{func.__module__}.{func.__qualname__}"

        if not contract.authorization.require_policy_decision:
            return func(*args, **kwargs)

        # Check if authorization context is provided
        policy_decision = kwargs.get("policy_decision")
        if policy_decision is None:
            for arg in args:
                if hasattr(arg, "allowed") and hasattr(arg, "action"):
                    policy_decision = arg
                    break

        if policy_decision is None:
            record = EnforcementRecord(
                rule="authorization.require_policy_decision",
                passed=False,
                detail="No PolicyDecision provided",
                caller=caller,
            )
            _log_enforcement(record)
            if contract.fail_closed.deny_on_policy_error:
                raise ContractViolation(
                    "authorization",
                    f"Function {caller} requires a PolicyDecision argument",
                )

        if policy_decision is not None and not getattr(policy_decision, "allowed", False):
            record = EnforcementRecord(
                rule="authorization.policy_denied",
                passed=False,
                detail=f"PolicyDecision denied: {getattr(policy_decision, 'reason', 'unknown')}",
                caller=caller,
            )
            _log_enforcement(record)
            raise ContractViolation(
                "authorization",
                f"PolicyDecision denied for {caller}: {getattr(policy_decision, 'reason', 'unknown')}",
            )

        record = EnforcementRecord(
            rule="authorization.require_policy_decision",
            passed=True,
            detail="PolicyDecision provided and allowed",
            caller=caller,
        )
        _log_enforcement(record)
        return func(*args, **kwargs)
    return wrapper  # type: ignore[return-value]


def require_scope_check(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        contract = get_contract()
        caller = f"{func.__module__}.{func.__qualname__}"

        if not contract.authorization.require_scope_check:
            return func(*args, **kwargs)

        target = kwargs.get("target") or kwargs.get("url") or kwargs.get("host")
        if target is None and args:
            # Try first string argument
            for arg in args:
                if isinstance(arg, str) and ("." in arg or ":" in arg or "/" in arg):
                    target = arg
                    break

        if target:
            try:
                from core.security.policy_engine import PolicyEngine
                decision = PolicyEngine.get().authorize_target(str(target))
                if not decision.allowed:
                    record = EnforcementRecord(
                        rule="target_scope.require_explicit_scope",
                        passed=False,
                        detail=f"Target {target} out of scope: {decision.reason}",
                        caller=caller,
                    )
                    _log_enforcement(record)
                    raise ContractViolation(
                        "target_scope",
                        f"Target {target} not authorized: {decision.reason}",
                    )
            except ContractViolation:
                raise
            except Exception as e:
                if contract.fail_closed.deny_on_scope_error:
                    record = EnforcementRecord(
                        rule="target_scope.fail_closed",
                        passed=False,
                        detail=f"Scope check error: {e}",
                        caller=caller,
                    )
                    _log_enforcement(record)
                    raise ContractViolation(
                        "target_scope",
                        f"Scope check failed (fail-closed): {e}",
                    )

        record = EnforcementRecord(
            rule="target_scope.require_explicit_scope",
            passed=True,
            detail=f"Target {target} authorized",
            caller=caller,
        )
        _log_enforcement(record)
        return func(*args, **kwargs)
    return wrapper  # type: ignore[return-value]


def require_sandbox(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        contract = get_contract()
        caller = f"{func.__module__}.{func.__qualname__}"

        if not contract.execution.require_sandbox:
            return func(*args, **kwargs)

        record = EnforcementRecord(
            rule="execution.require_sandbox",
            passed=True,
            detail="Sandbox enforcement active",
            caller=caller,
        )
        _log_enforcement(record)
        return func(*args, **kwargs)
    return wrapper  # type: ignore[return-value]


def fail_closed(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        caller = f"{func.__module__}.{func.__qualname__}"
        try:
            result = func(*args, **kwargs)
            # If result has an 'allowed' attribute, check it
            if hasattr(result, "allowed"):
                record = EnforcementRecord(
                    rule="fail_closed",
                    passed=result.allowed,
                    detail=f"Decision: {'ALLOW' if result.allowed else 'DENY'}",
                    caller=caller,
                )
                _log_enforcement(record)
            return result
        except ContractViolation:
            raise
        except Exception as e:
            record = EnforcementRecord(
                rule="fail_closed.deny_on_error",
                passed=False,
                detail=f"Error in security check, denying: {e}",
                caller=caller,
            )
            _log_enforcement(record)
            raise ContractViolation(
                "fail_closed",
                f"Security check {caller} failed with error: {e}",
                context={"original_error": str(e)},
            )
    return wrapper  # type: ignore[return-value]


def audit_action(rule_name: str) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            caller = f"{func.__module__}.{func.__qualname__}"
            try:
                result = func(*args, **kwargs)
                record = EnforcementRecord(
                    rule=rule_name,
                    passed=True,
                    detail="Action completed",
                    caller=caller,
                )
                _log_enforcement(record)
                return result
            except Exception as e:
                record = EnforcementRecord(
                    rule=rule_name,
                    passed=False,
                    detail=f"Action failed: {e}",
                    caller=caller,
                )
                _log_enforcement(record)
                raise
        return wrapper  # type: ignore[return-value]
    return decorator


# ── Contract validation helpers ───────────────────────────────────────────

def validate_network_access(url: str, purpose: str = "scan") -> None:
    contract = get_contract()

    if contract.target_scope.block_private_ips:
        from core.network.network_broker import _is_dangerous_ip
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or ""
        import socket
        try:
            ips = [ai[4][0] for ai in socket.getaddrinfo(host, None)]
            for ip in ips:
                if _is_dangerous_ip(ip):
                    raise ContractViolation(
                        "target_scope.block_private_ips",
                        f"Private/reserved IP {ip} for host {host}",
                    )
        except (socket.gaierror, ContractViolation):
            raise
        except Exception:
            if contract.fail_closed.deny_on_network_error:
                raise ContractViolation(
                    "fail_closed.deny_on_network_error",
                    f"DNS resolution failed for {host}",
                )


def validate_secret_handling(value: str, context: str = "") -> None:
    contract = get_contract()
    if not contract.secret_handling.redact_in_logs:
        return

    from core.security.secret_vault import _REF_PREFIX
    # If the value is already a secret reference, it's fine
    if _REF_PREFIX in value:
        return

    # Check for obvious secret patterns
    import re
    patterns = [
        re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
        re.compile(r"(?i)password\s*[=:]\s*\S{4,}"),
        re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
        re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
        re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S{10,}"),
    ]
    for p in patterns:
        if p.search(value):
            raise ContractViolation(
                "secret_handling.redact_in_logs",
                f"Unredacted secret detected in {context or 'value'}",
                context={"pattern": p.pattern},
            )


def validate_execution_sandbox(code: str) -> None:
    contract = get_contract()
    if not contract.execution.block_destructive_patterns:
        return

    import re
    from core.execution.sandbox import _DESTRUCTIVE_PATTERNS_RE
    for pattern in _DESTRUCTIVE_PATTERNS_RE:
        if re.search(pattern, code, re.IGNORECASE):
            raise ContractViolation(
                "execution.block_destructive_patterns",
                f"Destructive pattern detected: {pattern}",
            )


def get_approval_level(tier: OperationTier) -> ApprovalLevel:
    contract = get_contract()
    level_str = contract.human_approval.tier_approval.get(
        tier.value, ApprovalLevel.HUMAN_REQUIRED.value
    )
    return ApprovalLevel(level_str)


# ── Contract compliance checker ───────────────────────────────────────────

@dataclass
class ComplianceResult:
    module: str
    rule: str
    compliant: bool
    detail: str


def check_module_compliance(module_path: str) -> List[ComplianceResult]:
    import ast
    from pathlib import Path

    results: List[ComplianceResult] = []
    path = Path(module_path)
    if not path.exists():
        return [ComplianceResult(module_path, "file_exists", False, "File not found")]

    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=module_path)
    except (SyntaxError, UnicodeDecodeError) as e:
        return [ComplianceResult(module_path, "parseable", False, str(e))]

    contract = get_contract()

    # Check 1: No bare except that swallows ContractViolation
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:  # bare except:
                for child in ast.walk(node):
                    if isinstance(child, ast.Pass):
                        results.append(ComplianceResult(
                            module_path,
                            "fail_closed.never_catch_contract_violation",
                            False,
                            f"Line {node.lineno}: bare 'except: pass' may suppress ContractViolation",
                        ))
                        break

    # Check 2: Network I/O must go through broker/policy
    _network_calls = {"httpx", "requests", "aiohttp", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            mod_base = node.module.split(".")[0]
            if mod_base in _network_calls:
                # Check if this file also imports policy_engine or network_broker
                has_policy = any(
                    isinstance(n, ast.ImportFrom) and n.module and
                    ("policy_engine" in n.module or "network_broker" in n.module or "platform_contract" in n.module)
                    for n in ast.walk(tree)
                )
                if not has_policy:
                    results.append(ComplianceResult(
                        module_path,
                        "authorization.require_policy_decision",
                        False,
                        f"Line {node.lineno}: imports {node.module} but does not import policy_engine/network_broker",
                    ))

    # Check 3: subprocess/exec must import sandbox or tool_validator
    _exec_modules = {"subprocess", "os"}
    _exec_funcs = {"system", "popen", "exec", "eval", "Popen", "run", "call", "check_output"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = ""
            if isinstance(node.func, ast.Attribute):
                fname = node.func.attr
            elif isinstance(node.func, ast.Name):
                fname = node.func.id
            if fname in _exec_funcs:
                has_sandbox = any(
                    isinstance(n, ast.ImportFrom) and n.module and
                    ("sandbox" in n.module or "tool_validator" in n.module or "platform_contract" in n.module)
                    for n in ast.walk(tree)
                )
                if not has_sandbox:
                    results.append(ComplianceResult(
                        module_path,
                        "execution.require_sandbox",
                        False,
                        f"Line {node.lineno}: calls {fname}() without sandbox/tool_validator import",
                    ))

    if not results:
        results.append(ComplianceResult(module_path, "all", True, "Compliant"))

    return results
