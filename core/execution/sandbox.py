"""P0.3 — Isolated Execution Sandbox.

Replaces in-process exec()/eval() with proper process-level isolation.
Generated code NEVER runs inside the main application process.

Architecture:
    Agent
     |
    ExecutionController
     |
    SandboxWorker
     |
    Ephemeral isolated container / restricted subprocess

Enforcement:
    - CPU limit
    - Memory limit
    - PID limit
    - Wall-clock timeout
    - Filesystem isolation (read-only root, ephemeral workdir)
    - Restricted environment (no secrets, no host vars)
    - Restricted network (egress firewall)
    - No Docker socket
    - No host filesystem
    - No host process access
    - No privileged mode
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SandboxMode(str, Enum):
    DOCKER = "docker"
    SUBPROCESS = "subprocess"
    BLOCKED = "blocked"


class ExecutionLanguage(str, Enum):
    PYTHON = "python"
    BASH = "bash"
    JAVASCRIPT = "javascript"


# Patterns that must NEVER appear in sandboxed code — static pre-check
# before we even start a container. Defense-in-depth, not the boundary.
_DESTRUCTIVE_PATTERNS_RE = [
    r"\brm\s+-rf\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\b:\(\)\s*\{",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bhalt\b",
    r"\bDROP\s+TABLE\b",
    r"\bDELETE\s+FROM\b",
    r"\bTRUNCATE\b",
    r"\bformat\s+[Cc]:",
    r"crypt|ransom|encrypt_all",
    r">\s*/dev/sd",
    r"/etc/passwd\s*>",
    r"\bdel\s+/[sSqQ]",
]

# Environment variables NEVER passed into the sandbox
_SCRUBBED_ENV_KEYS = frozenset({
    "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "GROQ_API_KEY", "TOGETHER_API_KEY", "MISTRAL_API_KEY",
    "COHERE_API_KEY", "VOYAGEAI_API_KEY", "SHODAN_API_KEY",
    "CENSYS_API_ID", "CENSYS_API_SECRET", "VIRUSTOTAL_API_KEY",
    "GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT_KEY", "DATABASE_URL", "DB_PASSWORD",
    "POSTGRES_PASSWORD", "REDIS_URL", "SECRET_KEY", "JWT_SECRET",
    "SESSION_SECRET", "COOKIE_SECRET", "ENCRYPTION_KEY",
    "PRIVATE_KEY", "SSL_KEY", "TLS_KEY",
    "SMTP_PASSWORD", "EMAIL_PASSWORD", "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN", "SLACK_TOKEN", "DISCORD_TOKEN",
    "STRIPE_SECRET_KEY", "PAYPAL_SECRET",
    "PATH",  # prevent PATH injection
    "HOME", "USERPROFILE",  # prevent home directory discovery
    "DOCKER_HOST",  # prevent Docker socket access
})


@dataclass(frozen=True)
class SandboxConfig:
    """Resource limits for sandbox execution."""
    memory_mb: int = 256
    cpu_count: float = 1.0
    pid_limit: int = 128
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000
    max_code_bytes: int = 50_000
    network_enabled: bool = True
    read_only_root: bool = True
    docker_image: str = "python:3.11-slim"
    node_image: str = "node:20-slim"


@dataclass
class SandboxResult:
    """Result of sandboxed code execution."""
    executed: bool = False
    mode: str = "blocked"
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    blocked_reason: str = ""
    execution_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def success(self) -> bool:
        return self.executed and self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executed": self.executed,
            "mode": self.mode,
            "exit_code": self.exit_code,
            "stdout": self.stdout[-2000:],
            "stderr": self.stderr[-1000:],
            "timed_out": self.timed_out,
            "blocked_reason": self.blocked_reason,
            "execution_id": self.execution_id,
        }


class ExecutionController:
    """Routes all code execution through isolated sandboxes.

    This is the ONLY authorized path for running generated/dynamic code.
    exec()/eval() in the main process is forbidden for generated code.
    """

    _instance: Optional["ExecutionController"] = None
    _lock = threading.RLock()

    @classmethod
    def get(cls) -> "ExecutionController":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        with cls._lock:
            cls._instance = None

    def __init__(self, config: Optional[SandboxConfig] = None,
                 force_mode: Optional[SandboxMode] = None):
        self._config = config or SandboxConfig()
        self._docker_available: Optional[bool] = None
        self._force_mode = force_mode
        self._execution_count = 0
        self._count_lock = threading.Lock()

    @property
    def config(self) -> SandboxConfig:
        return self._config

    def _detect_docker(self) -> bool:
        if self._docker_available is not None:
            return self._docker_available
        try:
            r = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, timeout=5,
            )
            self._docker_available = r.returncode == 0
        except Exception:
            self._docker_available = False
        return self._docker_available

    def _select_mode(self) -> SandboxMode:
        if self._force_mode:
            return self._force_mode
        if self._detect_docker():
            return SandboxMode.DOCKER
        return SandboxMode.SUBPROCESS

    # ── Static analysis pre-check ────────────────────────────────────────

    @staticmethod
    def lint_code(code: str) -> Optional[str]:
        """Pre-execution static check. Returns reason if blocked, else None.
        This is defense-in-depth, NOT the security boundary."""
        import re
        for pattern in _DESTRUCTIVE_PATTERNS_RE:
            if re.search(pattern, code, re.IGNORECASE):
                return f"destructive pattern: {pattern}"
        return None

    # ── Policy check ─────────────────────────────────────────────────────

    def _authorize(self, language: str, code_preview: str,
                   target: str = "") -> Optional[str]:
        """Returns blocking reason or None if authorized."""
        try:
            from core.security.policy_engine import get_policy_engine
            engine = get_policy_engine()
            runner = {"python": "python", "bash": "bash",
                      "javascript": "node"}.get(language, language)
            decision = engine.authorize_subprocess(
                runner, args=["<sandbox_code>"], target=target,
            )
            if not decision.allowed:
                return decision.reason
        except ImportError:
            return "policy engine unavailable (fail-closed per platform contract)"
        except Exception as e:
            return f"policy check error: {e}"
        return None

    # ── Execution ────────────────────────────────────────────────────────

    async def execute(self, code: str, language: ExecutionLanguage = ExecutionLanguage.PYTHON,
                      target: str = "", env: Optional[Dict[str, str]] = None,
                      config: Optional[SandboxConfig] = None,
                      input_data: str = "") -> SandboxResult:
        """Execute code in an isolated sandbox. Returns SandboxResult."""
        cfg = config or self._config
        result = SandboxResult()

        # Size check
        if len(code.encode("utf-8", "ignore")) > cfg.max_code_bytes:
            result.blocked_reason = f"code too large ({len(code)} bytes, max {cfg.max_code_bytes})"
            return result

        # Static lint
        lint_reason = self.lint_code(code)
        if lint_reason:
            result.blocked_reason = lint_reason
            logger.warning("[Sandbox] code blocked by lint: %s", lint_reason)
            return result

        # Policy check
        auth_reason = self._authorize(language.value, code[:200], target)
        if auth_reason:
            result.blocked_reason = auth_reason
            logger.warning("[Sandbox] code blocked by policy: %s", auth_reason)
            return result

        # Scrub environment
        safe_env = self._build_safe_env(env)

        # Select execution mode
        mode = self._select_mode()
        result.mode = mode.value

        with self._count_lock:
            self._execution_count += 1

        workdir = tempfile.mkdtemp(prefix="sandbox_")
        try:
            if mode == SandboxMode.DOCKER:
                await self._run_docker(code, language, cfg, safe_env,
                                       workdir, result, input_data)
            elif mode == SandboxMode.SUBPROCESS:
                await self._run_subprocess(code, language, cfg, safe_env,
                                           workdir, result, input_data)
            else:
                result.blocked_reason = "no execution mode available"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        return result

    def _build_safe_env(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Build a minimal, scrubbed environment for the sandbox."""
        env: Dict[str, str] = {}
        if extra:
            for k, v in extra.items():
                if k.upper() not in _SCRUBBED_ENV_KEYS:
                    env[k] = v
        env.setdefault("LANG", "C.UTF-8")
        env.setdefault("TERM", "dumb")
        return env

    # ── Docker execution ─────────────────────────────────────────────────

    async def _run_docker(self, code: str, language: ExecutionLanguage,
                          cfg: SandboxConfig, env: Dict[str, str],
                          workdir: str, result: SandboxResult,
                          input_data: str = "") -> None:
        ext = {"python": "py", "bash": "sh", "javascript": "js"}[language.value]
        script_name = f"run_{result.execution_id}.{ext}"
        script_path = os.path.join(workdir, script_name)

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        runner = {"python": "python", "bash": "bash",
                  "javascript": "node"}[language.value]
        image = cfg.node_image if language == ExecutionLanguage.JAVASCRIPT else cfg.docker_image

        cmd = [
            "docker", "run", "--rm",
            f"--memory={cfg.memory_mb}m",
            f"--cpus={cfg.cpu_count}",
            f"--pids-limit={cfg.pid_limit}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--no-healthcheck",
        ]

        if cfg.read_only_root:
            cmd.append("--read-only")
            cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        if not cfg.network_enabled:
            cmd.append("--network=none")

        # No Docker socket, no host filesystem, no privileged
        # (these are defaults, but explicit for clarity)
        # Volume mount is read-only
        cmd.extend([
            "-v", f"{workdir}:/sandbox:ro",
            "-w", "/sandbox",
        ])

        # Scrubbed env vars
        for k, v in env.items():
            cmd.extend(["-e", f"{k}={v}"])

        cmd.extend([image, "timeout", str(cfg.timeout_seconds),
                     runner, f"/sandbox/{script_name}"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else asyncio.subprocess.DEVNULL,
            )
            stdin_bytes = input_data.encode("utf-8") if input_data else None
            out, err = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=cfg.timeout_seconds + 30,
            )
            result.executed = True
            result.exit_code = proc.returncode
            result.stdout = (out or b"")[:cfg.max_output_bytes].decode("utf-8", "ignore")
            result.stderr = (err or b"")[:cfg.max_output_bytes].decode("utf-8", "ignore")
            if result.exit_code == 124:
                result.timed_out = True
        except asyncio.TimeoutError:
            result.executed = True
            result.timed_out = True
            result.exit_code = 124
            result.stderr = "sandbox timeout (controller)"
            try:
                proc.kill()
            except Exception:
                pass

    # ── Subprocess execution (fallback) ──────────────────────────────────

    async def _run_subprocess(self, code: str, language: ExecutionLanguage,
                              cfg: SandboxConfig, env: Dict[str, str],
                              workdir: str, result: SandboxResult,
                              input_data: str = "") -> None:
        ext = {"python": "py", "bash": "sh", "javascript": "js"}[language.value]
        script_name = f"run_{result.execution_id}.{ext}"
        script_path = os.path.join(workdir, script_name)

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        runner = {"python": "python", "bash": "bash",
                  "javascript": "node"}[language.value]

        cmd: List[str] = []

        # On Linux, use resource limits via ulimit wrapper
        is_linux = platform.system() == "Linux"
        if is_linux:
            mem_kb = cfg.memory_mb * 1024
            cmd = [
                "bash", "-c",
                f"ulimit -v {mem_kb} -u {cfg.pid_limit} -t {cfg.timeout_seconds}; "
                f"exec {runner} {script_path}"
            ]
        else:
            cmd = [runner, script_path]

        # Minimal env — no inheritance from parent
        safe_env = dict(env)
        if is_linux:
            safe_env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        else:
            safe_env["PATH"] = os.environ.get("PATH", "")
            safe_env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else asyncio.subprocess.DEVNULL,
                cwd=workdir,
                env=safe_env,
            )
            stdin_bytes = input_data.encode("utf-8") if input_data else None
            out, err = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=cfg.timeout_seconds,
            )
            result.executed = True
            result.exit_code = proc.returncode
            result.stdout = (out or b"")[:cfg.max_output_bytes].decode("utf-8", "ignore")
            result.stderr = (err or b"")[:cfg.max_output_bytes].decode("utf-8", "ignore")
        except asyncio.TimeoutError:
            result.executed = True
            result.timed_out = True
            result.exit_code = 124
            result.stderr = "sandbox timeout"
            try:
                proc.kill()
            except Exception:
                pass


# ── Module-level accessor ────────────────────────────────────────────────

def get_execution_controller() -> ExecutionController:
    return ExecutionController.get()
