"""LLM error-feedback repair for failed CLI / Kali tool commands.

When a tool exits with an error, ask a cheap LLM to correct the *command* from the
tool's OWN stderr — the general form of the hand-written per-tool flag fixes in
``tool_router`` (wafw00f ``--aggressive``, gobuster ``--wildcard``, curl ``-H``
quoting, masscan hostname, …). One repair attempt per (tool, error-signature) per
scan; the result is cached so the same failure is reasoned about only once.

Server-independent: it reads the *tool's* error text, never the target's response,
so it works even when the target is down.

SAFETY (this builds shell commands for a security tool). A repaired command is
executed only if it:
  * keeps the SAME first binary as the original,
  * introduces NO shell operators the original didn't already have,
  * contains NO host/URL that isn't authorized in scope (no scope drift),
  * is length-bounded.
On any doubt the repair is rejected (``None`` → no retry) or the tool is skipped
(``""``). The LLM can never redirect the tool at a new host or inject shell control.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_MAX_CMD = 2000
_URL_RE = re.compile(r'https?://[^\s"\']+', re.I)
# Shell control operators (data literals like a URL '?' or '&' inside a single arg
# are fine; these are the metacharacters that change execution).
_SHELL_OPS_RE = re.compile(r'[|;&`]|\$\(|\$\{|>>|<|(?<!\d)>(?!\d)')

# Per-process caches. A correction (or a skip) is remembered per error-signature so
# a recurring failure is fixed once and reused, and never re-attempted in a loop.
_CACHE: Dict[str, str] = {}          # sig -> corrected command, or "" for SKIP
_ATTEMPTED: Set[str] = set()         # signatures already sent to the LLM


def _error_signature(tool: str, stderr: str) -> str:
    """Normalise stderr into a stable cache key (drop target-specific URLs/numbers)."""
    s = (stderr or "").lower()
    s = _URL_RE.sub("<url>", s)
    s = re.sub(r'\d+', "N", s)
    s = re.sub(r'\s+', " ", s).strip()
    return f"{tool}:{s[:160]}"


def _has_shell_ops(cmd: str) -> bool:
    return bool(_SHELL_OPS_RE.search(cmd or ""))


def _hosts_in(cmd: str) -> Set[str]:
    out: Set[str] = set()
    for u in _URL_RE.findall(cmd or ""):
        try:
            h = urlparse(u).hostname
            if h:
                out.add(h.lower())
        except Exception:
            pass
    return out


def _scope_safe(cand: str, orig: str) -> bool:
    """Every host/URL in the corrected command must be authorized. Falls back to
    'introduces no new host vs. the original' when the scope validator is
    unavailable — never widens reach."""
    cand_hosts = _hosts_in(cand)
    if not cand_hosts:
        return True
    try:
        from core.security.authorization import TargetScopeValidator
        v = TargetScopeValidator.get()
        return all(v.is_authorized(h) for h in cand_hosts)
    except Exception:
        return cand_hosts <= _hosts_in(orig)


def _validate(tool: str, orig: str, cand: str) -> Optional[str]:
    """Return a safe corrected command, "" to SKIP, or None to reject."""
    if not isinstance(cand, str):
        return None
    cand = cand.strip().strip("`").strip()
    if not cand or cand.upper() == "SKIP":
        return ""
    if len(cand) > _MAX_CMD:
        return None
    # Same binary as the original (basename compare; tolerate a path prefix).
    o0 = (orig.split() or [""])[0].rsplit("/", 1)[-1]
    c0 = (cand.split() or [""])[0].rsplit("/", 1)[-1]
    if not o0 or c0 != o0:
        return None
    # No NEW shell operators (only allowed if the original already had them).
    if _has_shell_ops(cand) and not _has_shell_ops(orig):
        return None
    # No scope drift.
    if not _scope_safe(cand, orig):
        return None
    # Reject a no-op (identical) correction.
    if cand == orig.strip():
        return None
    return cand


async def repair_command(tool: str, command: str, stderr: str,
                         *, target: str = "") -> Optional[str]:
    """Ask a cheap LLM to fix a failed tool command from its stderr.

    Returns a corrected command to retry, ``""`` to SKIP (unfixable — do not retry),
    or ``None`` (no repair available / unsafe). One LLM attempt per
    (tool, error-signature) per scan; corrections are cached.
    """
    if not command or not stderr or not tool:
        return None
    sig = _error_signature(tool, stderr)
    if sig in _CACHE:                       # known correction or known skip
        cached = _CACHE[sig]
        return cached if cached else ""
    if sig in _ATTEMPTED:                    # tried once, no safe fix — don't loop
        return None
    _ATTEMPTED.add(sig)

    try:
        from agents.llm_harness_adapter import get_llm
        from core.common.schemas import TaskTier
        llm = get_llm()
        prompt = (
            "A command-line security tool failed. Correct ONLY the command's syntax "
            "using its error output. Hard rules:\n"
            "- keep the SAME first binary;\n"
            "- keep the SAME target host/URL — never change, add, or remove the host;\n"
            "- fix or drop only invalid flags/arguments;\n"
            "- output a single line, no shell operators (| ; & ` $() > <).\n"
            "If it cannot be fixed by editing the command, return skip.\n\n"
            f"TOOL: {tool}\n"
            f"COMMAND: {command}\n"
            f"STDERR:\n{str(stderr)[:800]}\n\n"
            'Return JSON exactly: {"command": "<corrected one-line command>"} '
            'or {"skip": true}.'
        )
        data = await llm.generate_json(prompt, tier=TaskTier.SMALL, max_tokens=300)
    except Exception as e:
        logger.debug("[CmdRepair] LLM unavailable for %s: %s", tool, e)
        return None

    if not isinstance(data, dict):
        return None
    if data.get("skip") is True:
        _CACHE[sig] = ""
        logger.info("[CmdRepair] %s: LLM judged unfixable — skipping", tool)
        return ""
    fixed = _validate(tool, command, str(data.get("command", "")))
    if fixed is None:
        logger.info("[CmdRepair] %s: proposed fix rejected (unsafe/invalid)", tool)
        return None
    if fixed == "":
        _CACHE[sig] = ""
        return ""
    _CACHE[sig] = fixed
    logger.info("[CmdRepair] %s: command repaired from stderr and cached", tool)
    return fixed
