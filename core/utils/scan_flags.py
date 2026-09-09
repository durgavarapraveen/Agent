"""Per-scan runtime policy flags, decided at scan start.

The operator (not the LLM, and not observed content) chooses these when
launching a scan. They are propagated to the scan subprocess via environment
variables so every module can read them without threading config through
constructors.
"""
from __future__ import annotations

import os

_TRUE = ("1", "true", "yes", "on")


def allow_shell_operators() -> bool:
    """Whether tool arguments may contain shell metacharacters (| ; & ` $ ( )).

    Default False (safe): such arguments are rejected, because the Kali tool
    layer executes with ``shell=True`` and raw operators would allow command
    injection from an LLM-crafted argument.

    When the operator opts in at scan start (``ALLOW_SHELL_OPERATORS=1``), the
    router still does NOT run them as shell control — it shell-quotes each token
    so the characters pass through as literal data (needed for payloads like
    ``--data="a=1&b=2"`` that legitimately contain ``&``). It never enables raw
    shell pipelines.
    """
    return os.getenv("ALLOW_SHELL_OPERATORS", "").strip().lower() in _TRUE


def allow_ambient_auth() -> bool:
    """Whether a captured/active bearer token may be auto-injected into requests
    that do NOT explicitly declare a session (P0.2).

    Default False (safe): a request with no declared ``session_id`` is treated as
    ANONYMOUS and receives no Authorization header, so a JWT captured mid-scan
    can never silently authenticate a later anonymous or access-control test.
    Explicitly named sessions always use their own token regardless of this flag.

    When the operator opts in at scan start (``ALLOW_AMBIENT_AUTH=1``) the legacy
    convenience returns: an undeclared request reuses the active same-host token
    (useful for a fully-authenticated scan of a single identity).
    """
    return os.getenv("ALLOW_AMBIENT_AUTH", "").strip().lower() in _TRUE


def redact_llm_context() -> bool:
    """Whether credentials/PII are masked before entering the LLM context (P2.8).

    Default True (privacy- and cost-preserving): response bodies, prompts and
    tool results are scrubbed of tokens, passwords, emails, card/SSN, keys, etc.
    The agent authenticates via explicit session tokens (P0.2), so redaction does
    not impair exploitation. Set ``REDACT_LLM_CONTEXT=0`` to disable.
    """
    return os.getenv("REDACT_LLM_CONTEXT", "1").strip().lower() in _TRUE
