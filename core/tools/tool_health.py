"""
P1-7: formal ToolHealthManager.

Tool health is validated BEFORE scanning: binary present, dependencies
ok, minimal execution test passes. Broken tools go into COOLDOWN and
the router picks replacements immediately instead of wasting an LLM
round attempting a known-broken invocation.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class HealthState(str, Enum):
    UNKNOWN = "UNKNOWN"
    READY = "READY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    COOLDOWN = "COOLDOWN"


@dataclass
class ToolHealth:
    tool: str
    version: Optional[str] = None
    binary_exists: bool = False
    dependencies_ok: bool = False
    execution_test: bool = False
    container: str = ""
    last_failure: str = ""
    cooldown_until: Optional[datetime] = None
    replacement_tools: List[str] = field(default_factory=list)
    state: HealthState = HealthState.UNKNOWN

    def is_available(self) -> bool:
        if self.state in (HealthState.UNAVAILABLE,):
            return False
        if self.state == HealthState.COOLDOWN:
            return bool(self.cooldown_until and datetime.now() >= self.cooldown_until)
        return self.state in (HealthState.READY, HealthState.DEGRADED, HealthState.UNKNOWN)

    def as_dict(self) -> Dict:
        return {
            "tool": self.tool, "version": self.version,
            "binary_exists": self.binary_exists,
            "dependencies_ok": self.dependencies_ok,
            "execution_test": self.execution_test,
            "container": self.container,
            "last_failure": self.last_failure,
            "cooldown_until": self.cooldown_until.isoformat() if self.cooldown_until else None,
            "replacement_tools": list(self.replacement_tools),
            "state": self.state.value,
        }


# Baseline replacement chains for tools with well-known drop-ins.
DEFAULT_REPLACEMENTS: Dict[str, List[str]] = {
    "dirsearch": ["ffuf", "feroxbuster", "gobuster"],
    "gobuster": ["ffuf", "feroxbuster"],
    "ffuf": ["feroxbuster", "gobuster"],
    "feroxbuster": ["ffuf", "gobuster"],
    "masscan": ["nmap"],
    "nmap": ["masscan"],
    "amass": ["subfinder", "assetfinder"],
    "subfinder": ["assetfinder", "amass"],
    "nikto": ["nuclei"],
}


class ToolHealthManager:
    def __init__(self):
        self._states: Dict[str, ToolHealth] = {}
        self._lock = Lock()

    def probe(self, tool: str, container: str = "",
              version_arg: str = "--version") -> ToolHealth:
        """Cheap probe: binary exists + a quick `--version` run.

        Deeper dependency checks are tool-specific and can be plugged in
        by callers via `mark_dependency_failed`.
        """
        health = self._states.get(tool) or ToolHealth(tool=tool, container=container)
        health.binary_exists = bool(shutil.which(tool))
        if not health.binary_exists:
            health.state = HealthState.UNAVAILABLE
            health.last_failure = "binary not found in PATH"
            health.replacement_tools = DEFAULT_REPLACEMENTS.get(tool, [])
            with self._lock:
                self._states[tool] = health
            return health
        try:
            r = subprocess.run(
                [tool, version_arg],
                capture_output=True, text=True, timeout=10,
            )
            health.version = (r.stdout or r.stderr or "").strip().splitlines()[0][:120]
            health.execution_test = r.returncode in (0, 1)  # some tools return 1 for --version
            health.dependencies_ok = True
            health.state = HealthState.READY if health.execution_test else HealthState.DEGRADED
        except FileNotFoundError:
            health.state = HealthState.UNAVAILABLE
            health.last_failure = "binary vanished between check and exec"
        except subprocess.TimeoutExpired:
            health.state = HealthState.DEGRADED
            health.last_failure = "version probe timed out"
        except Exception as e:
            health.state = HealthState.DEGRADED
            health.last_failure = f"version probe error: {e}"
        health.replacement_tools = DEFAULT_REPLACEMENTS.get(tool, [])
        with self._lock:
            self._states[tool] = health
        return health

    def mark_failure(self, tool: str, reason: str, cooldown_seconds: int = 300) -> None:
        with self._lock:
            h = self._states.get(tool) or ToolHealth(tool=tool)
            h.last_failure = reason[:200]
            h.state = HealthState.COOLDOWN
            h.cooldown_until = datetime.now() + timedelta(seconds=cooldown_seconds)
            h.replacement_tools = DEFAULT_REPLACEMENTS.get(tool, h.replacement_tools)
            self._states[tool] = h
        logger.warning(f"TOOL_HEALTH_COOLDOWN tool={tool} reason={reason[:120]} "
                       f"until={h.cooldown_until.isoformat()}")

    def mark_dependency_failed(self, tool: str, reason: str) -> None:
        with self._lock:
            h = self._states.get(tool) or ToolHealth(tool=tool)
            h.dependencies_ok = False
            h.last_failure = reason[:200]
            h.state = HealthState.UNAVAILABLE
            h.replacement_tools = DEFAULT_REPLACEMENTS.get(tool, h.replacement_tools)
            self._states[tool] = h

    def status_of(self, tool: str) -> Optional[ToolHealth]:
        with self._lock:
            return self._states.get(tool)

    def pick_replacement(self, tool: str) -> Optional[str]:
        """First available replacement for a broken tool."""
        for alt in DEFAULT_REPLACEMENTS.get(tool, []):
            h = self._states.get(alt) or self.probe(alt)
            if h.is_available():
                return alt
        return None

    def snapshot(self) -> Dict[str, Dict]:
        with self._lock:
            return {t: h.as_dict() for t, h in self._states.items()}


_SINGLETON: Optional[ToolHealthManager] = None


def get_health_manager() -> ToolHealthManager:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ToolHealthManager()
    return _SINGLETON
