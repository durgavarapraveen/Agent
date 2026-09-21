from __future__ import annotations

import os
from pathlib import Path

_TRUE = ("1", "true", "yes", "on")

# UI-settable, persisted flag file (read by both the API process and each scan
# subprocess, so it needs no env plumbing). Relative to project root.
_MSF_FILE = Path(".antigravity") / "enable_msf"


def allow_shell_operators() -> bool:
    return os.getenv("ALLOW_SHELL_OPERATORS", "").strip().lower() in _TRUE


def allow_ambient_auth() -> bool:
    return os.getenv("ALLOW_AMBIENT_AUTH", "").strip().lower() in _TRUE


def redact_llm_context() -> bool:
    return os.getenv("REDACT_LLM_CONTEXT", "1").strip().lower() in _TRUE


def enable_metasploit() -> bool:
    """Off by default. Enables the msf auxiliary-scanner tool (read-only,
    allow-listed modules only) for authorized targets. Env var wins; falls
    back to the UI-set persisted flag file so a scan subprocess honors the
    Settings toggle without extra env plumbing."""
    env = os.getenv("NEO_ENABLE_MSF", "").strip().lower()
    if env:
        return env in _TRUE
    try:
        return _MSF_FILE.read_text(encoding="utf-8").strip().lower() in _TRUE
    except Exception:
        return False


def metasploit_enabled() -> bool:
    """UI read: reflect the effective state (env or persisted file)."""
    return enable_metasploit()


def set_metasploit_enabled(on: bool) -> bool:
    """UI write: persist the toggle. Also mirrors into this process's env so
    the change takes effect for scans started before the file is re-read."""
    _MSF_FILE.parent.mkdir(parents=True, exist_ok=True)
    _MSF_FILE.write_text("1" if on else "0", encoding="utf-8")
    os.environ["NEO_ENABLE_MSF"] = "1" if on else "0"
    return on
