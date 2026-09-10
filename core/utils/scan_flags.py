from __future__ import annotations

import os

_TRUE = ("1", "true", "yes", "on")


def allow_shell_operators() -> bool:
    return os.getenv("ALLOW_SHELL_OPERATORS", "").strip().lower() in _TRUE


def allow_ambient_auth() -> bool:
    return os.getenv("ALLOW_AMBIENT_AUTH", "").strip().lower() in _TRUE


def redact_llm_context() -> bool:
    return os.getenv("REDACT_LLM_CONTEXT", "1").strip().lower() in _TRUE
