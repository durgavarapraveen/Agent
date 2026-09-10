"""P0.4 — Secure LLM-authored tool validation pipeline.

Replaces the pattern: LLM generates code -> LLM critic -> exec()

New pipeline:
    LLM generation
     |
    AST/static validation     (this module)
     |
    capability analysis        (this module)
     |
    policy validation          (PolicyEngine)
     |
    isolated execution         (ExecutionController from P0.3)
     |
    runtime policy enforcement
     |
    ToolRegistry

The LLM critic is advisory only — it cannot authorize anything.
"""
from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Capability model ─────────────────────────────────────────────────────

class ToolCapability(str, Enum):
    NETWORK_HTTP = "network_http"
    NETWORK_SOCKET = "network_socket"
    NETWORK_DNS = "network_dns"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    SUBPROCESS = "subprocess"
    DYNAMIC_EXEC = "dynamic_exec"
    ENVIRONMENT_ACCESS = "environment_access"
    IMPORT_EXTERNAL = "import_external"
    CRYPTO = "crypto"
    SERIALIZATION = "serialization"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuthoredToolDefinition:
    """Security-annotated metadata for an LLM-authored tool."""
    name: str
    description: str = ""
    capabilities: FrozenSet[ToolCapability] = frozenset()
    network_access: bool = False
    filesystem_access: bool = False
    subprocess_access: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    timeout: int = 30
    request_budget: int = 100
    max_code_bytes: int = 8000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "capabilities": sorted(c.value for c in self.capabilities),
            "network_access": self.network_access,
            "filesystem_access": self.filesystem_access,
            "subprocess_access": self.subprocess_access,
            "risk_level": self.risk_level.value,
            "timeout": self.timeout,
            "request_budget": self.request_budget,
        }


# ── Validation result ────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    valid: bool
    capabilities: Set[ToolCapability] = field(default_factory=set)
    risk_level: RiskLevel = RiskLevel.LOW
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    ast_errors: List[str] = field(default_factory=list)
    blocked: bool = False
    blocked_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "capabilities": sorted(c.value for c in self.capabilities),
            "risk_level": self.risk_level.value,
            "issues": self.issues,
            "warnings": self.warnings,
            "blocked": self.blocked,
            "blocked_reason": self.blocked_reason,
        }


# ── AST capability detector ─────────────────────────────────────────────

# Maps module/attribute access to capabilities
_IMPORT_CAPABILITIES: Dict[str, ToolCapability] = {
    "httpx": ToolCapability.NETWORK_HTTP,
    "requests": ToolCapability.NETWORK_HTTP,
    "aiohttp": ToolCapability.NETWORK_HTTP,
    "urllib": ToolCapability.NETWORK_HTTP,
    "urllib3": ToolCapability.NETWORK_HTTP,
    "http.client": ToolCapability.NETWORK_HTTP,
    "socket": ToolCapability.NETWORK_SOCKET,
    "dns": ToolCapability.NETWORK_DNS,
    "dns.resolver": ToolCapability.NETWORK_DNS,
    "subprocess": ToolCapability.SUBPROCESS,
    "os": ToolCapability.ENVIRONMENT_ACCESS,
    "sys": ToolCapability.ENVIRONMENT_ACCESS,
    "pathlib": ToolCapability.FILESYSTEM_READ,
    "shutil": ToolCapability.FILESYSTEM_WRITE,
    "pickle": ToolCapability.SERIALIZATION,
    "marshal": ToolCapability.SERIALIZATION,
    "yaml": ToolCapability.SERIALIZATION,
    "cryptography": ToolCapability.CRYPTO,
    "hashlib": ToolCapability.CRYPTO,
    "hmac": ToolCapability.CRYPTO,
}

# Function/attribute access patterns that indicate capabilities
_CALL_CAPABILITIES: Dict[str, ToolCapability] = {
    "open": ToolCapability.FILESYSTEM_READ,
    "exec": ToolCapability.DYNAMIC_EXEC,
    "eval": ToolCapability.DYNAMIC_EXEC,
    "compile": ToolCapability.DYNAMIC_EXEC,
    "__import__": ToolCapability.IMPORT_EXTERNAL,
    "importlib": ToolCapability.IMPORT_EXTERNAL,
    "getattr": ToolCapability.DYNAMIC_EXEC,
}

# Attributes that indicate specific capabilities
_ATTR_CAPABILITIES: Dict[Tuple[str, str], ToolCapability] = {
    ("os", "system"): ToolCapability.SUBPROCESS,
    ("os", "popen"): ToolCapability.SUBPROCESS,
    ("os", "exec"): ToolCapability.SUBPROCESS,
    ("os", "execvp"): ToolCapability.SUBPROCESS,
    ("os", "spawn"): ToolCapability.SUBPROCESS,
    ("os", "environ"): ToolCapability.ENVIRONMENT_ACCESS,
    ("os", "getenv"): ToolCapability.ENVIRONMENT_ACCESS,
    ("os", "remove"): ToolCapability.FILESYSTEM_WRITE,
    ("os", "unlink"): ToolCapability.FILESYSTEM_WRITE,
    ("os", "rmdir"): ToolCapability.FILESYSTEM_WRITE,
    ("os", "rename"): ToolCapability.FILESYSTEM_WRITE,
    ("os", "makedirs"): ToolCapability.FILESYSTEM_WRITE,
    ("os", "mkdir"): ToolCapability.FILESYSTEM_WRITE,
    ("subprocess", "run"): ToolCapability.SUBPROCESS,
    ("subprocess", "call"): ToolCapability.SUBPROCESS,
    ("subprocess", "Popen"): ToolCapability.SUBPROCESS,
    ("subprocess", "check_output"): ToolCapability.SUBPROCESS,
    ("shutil", "rmtree"): ToolCapability.FILESYSTEM_WRITE,
    ("shutil", "copy"): ToolCapability.FILESYSTEM_WRITE,
    ("shutil", "move"): ToolCapability.FILESYSTEM_WRITE,
}

# Absolutely blocked patterns — no authored tool may use these
_BLOCKED_PATTERNS = [
    (r"\brm\s+-rf\b", "destructive shell command"),
    (r"\bmkfs\b", "filesystem format"),
    (r"\bdd\s+if=", "raw disk write"),
    (r"\b:\(\)\s*\{", "fork bomb"),
    (r"\bshutdown\b", "system shutdown"),
    (r"\breboot\b", "system reboot"),
    (r"crypt|ransom|encrypt_all", "encryption/ransom"),
    (r">\s*/dev/sd", "raw device write"),
    (r"/etc/passwd\s*>", "passwd overwrite"),
]


class _CapabilityVisitor(ast.NodeVisitor):
    """Walk AST to detect capabilities used by the code."""

    def __init__(self):
        self.capabilities: Set[ToolCapability] = set()
        self.imports: Set[str] = set()
        self.issues: List[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name.split(".")[0]
            self.imports.add(mod)
            if mod in _IMPORT_CAPABILITIES:
                self.capabilities.add(_IMPORT_CAPABILITIES[mod])
            full = alias.name
            if full in _IMPORT_CAPABILITIES:
                self.capabilities.add(_IMPORT_CAPABILITIES[full])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            mod = node.module.split(".")[0]
            self.imports.add(mod)
            if mod in _IMPORT_CAPABILITIES:
                self.capabilities.add(_IMPORT_CAPABILITIES[mod])
            if node.module in _IMPORT_CAPABILITIES:
                self.capabilities.add(_IMPORT_CAPABILITIES[node.module])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Direct function calls: exec(), eval(), open(), etc.
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in _CALL_CAPABILITIES:
                self.capabilities.add(_CALL_CAPABILITIES[name])
                if name in ("exec", "eval", "compile"):
                    self.issues.append(f"dynamic execution via {name}()")

        # Attribute calls: os.system(), subprocess.run(), etc.
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
                key = (mod, attr)
                if key in _ATTR_CAPABILITIES:
                    self.capabilities.add(_ATTR_CAPABILITIES[key])

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.value, ast.Name):
            key = (node.value.id, node.attr)
            if key in _ATTR_CAPABILITIES:
                self.capabilities.add(_ATTR_CAPABILITIES[key])
        self.generic_visit(node)


# ── Risk assessment ──────────────────────────────────────────────────────

def _assess_risk(capabilities: Set[ToolCapability]) -> RiskLevel:
    """Determine risk level from detected capabilities."""
    if ToolCapability.DYNAMIC_EXEC in capabilities:
        return RiskLevel.CRITICAL
    if ToolCapability.SUBPROCESS in capabilities:
        return RiskLevel.CRITICAL
    if ToolCapability.FILESYSTEM_WRITE in capabilities:
        return RiskLevel.HIGH
    if ToolCapability.SERIALIZATION in capabilities:
        return RiskLevel.HIGH
    if ToolCapability.NETWORK_SOCKET in capabilities:
        return RiskLevel.MEDIUM
    if ToolCapability.ENVIRONMENT_ACCESS in capabilities:
        return RiskLevel.MEDIUM
    if ToolCapability.NETWORK_HTTP in capabilities:
        return RiskLevel.LOW
    return RiskLevel.LOW


# ── Blocked capabilities ─────────────────────────────────────────────────

_ALWAYS_BLOCKED: FrozenSet[ToolCapability] = frozenset({
    ToolCapability.DYNAMIC_EXEC,
    ToolCapability.SUBPROCESS,
    ToolCapability.FILESYSTEM_WRITE,
    ToolCapability.IMPORT_EXTERNAL,
})


# ── Main validation pipeline ────────────────────────────────────────────

def validate_authored_code(code: str, name: str = "",
                           allowed_capabilities: Optional[Set[ToolCapability]] = None,
                           ) -> ValidationResult:
    """Full validation pipeline for LLM-authored tool code.

    Steps:
      1. Size check
      2. Blocked pattern scan (regex)
      3. AST parse
      4. Capability detection via AST walk
      5. Risk assessment
      6. Capability policy check
      7. PolicyEngine authorization

    Returns ValidationResult with capabilities, risk, issues.
    """
    result = ValidationResult(valid=False)

    # 1. Size check
    if len(code.encode("utf-8", "ignore")) > 50_000:
        result.blocked = True
        result.blocked_reason = "code exceeds 50KB limit"
        return result

    if not code.strip():
        result.blocked = True
        result.blocked_reason = "empty code"
        return result

    # 2. Blocked pattern scan
    for pattern, desc in _BLOCKED_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            result.blocked = True
            result.blocked_reason = f"blocked pattern: {desc}"
            result.issues.append(f"destructive pattern detected: {desc}")
            return result

    # 3. AST parse
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        result.ast_errors.append(f"syntax error: {e}")
        result.blocked = True
        result.blocked_reason = f"syntax error at line {e.lineno}: {e.msg}"
        return result

    # 4. Capability detection
    visitor = _CapabilityVisitor()
    visitor.visit(tree)
    result.capabilities = visitor.capabilities
    result.issues.extend(visitor.issues)

    # 5. Risk assessment
    result.risk_level = _assess_risk(result.capabilities)

    # 6. Capability policy — block always-dangerous capabilities
    if allowed_capabilities is None:
        allowed_capabilities = {
            ToolCapability.NETWORK_HTTP,
            ToolCapability.NETWORK_DNS,
            ToolCapability.CRYPTO,
        }

    blocked_caps = result.capabilities & _ALWAYS_BLOCKED
    if blocked_caps:
        result.blocked = True
        result.blocked_reason = (
            f"blocked capabilities: {', '.join(c.value for c in blocked_caps)}"
        )
        return result

    unauthorized = result.capabilities - allowed_capabilities - _ALWAYS_BLOCKED
    if unauthorized:
        result.warnings.append(
            f"capabilities not in allowlist: {', '.join(c.value for c in unauthorized)}"
        )

    # 7. PolicyEngine authorization
    try:
        from core.security.policy_engine import get_policy_engine
        engine = get_policy_engine()
        decision = engine.authorize_subprocess(
            "python", args=[f"<authored_tool:{name}>"],
        )
        if not decision.allowed:
            result.blocked = True
            result.blocked_reason = f"policy denied: {decision.reason}"
            return result
    except ImportError:
        result.blocked = True
        result.blocked_reason = "PolicyEngine unavailable (fail-closed per platform contract)"
        return result
    except Exception as e:
        result.blocked = True
        result.blocked_reason = f"policy check error: {e}"
        return result

    result.valid = True
    return result


def build_tool_definition(name: str, description: str, code: str,
                          validation: ValidationResult,
                          timeout: int = 30,
                          request_budget: int = 100) -> AuthoredToolDefinition:
    """Build an AuthoredToolDefinition from validation results."""
    return AuthoredToolDefinition(
        name=name,
        description=description,
        capabilities=frozenset(validation.capabilities),
        network_access=any(
            c in validation.capabilities
            for c in (ToolCapability.NETWORK_HTTP, ToolCapability.NETWORK_SOCKET,
                      ToolCapability.NETWORK_DNS)
        ),
        filesystem_access=any(
            c in validation.capabilities
            for c in (ToolCapability.FILESYSTEM_READ, ToolCapability.FILESYSTEM_WRITE)
        ),
        subprocess_access=ToolCapability.SUBPROCESS in validation.capabilities,
        risk_level=validation.risk_level,
        timeout=timeout,
        request_budget=request_budget,
        max_code_bytes=len(code.encode("utf-8", "ignore")),
    )
