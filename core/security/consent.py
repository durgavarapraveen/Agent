"""
Per-Exploit Consent Gate

Before ANY exploitation is attempted, the operator is shown a briefing —
what the system will do, how it will do it, and which vulnerability/payloads
it will use — and must explicitly approve. On "no" the exploit is skipped.

Design notes:
  - Prompts are serialized with an asyncio.Lock so parallel exploit agents do
    not interleave their questions.
  - input() runs in a thread executor so it never blocks the event loop.
  - Non-interactive stdin (EOF) defaults to DENY (fail safe).
  - AUTO_APPROVE_EXPLOITS=1 (or set_auto_approve(True)) approves automatically
    for unattended runs; every decision is still logged.
  - set_prompt() injects a custom prompt fn for tests / alternative UIs.
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ExploitConsentManager:
    def __init__(self):
        self._lock = asyncio.Lock()
        self.decisions: List[Dict] = []
        self.auto_approve = os.getenv("AUTO_APPROVE_EXPLOITS", "").lower() in ("1", "true", "yes")
        self._prompt: Optional[Callable[[str], str]] = None

    # ── configuration ──

    def set_prompt(self, fn: Callable[[str], str]):
        """Inject a custom prompt: takes the briefing text, returns the raw answer."""
        self._prompt = fn

    def set_auto_approve(self, value: bool):
        self.auto_approve = bool(value)

    # ── briefing ──

    def render_briefing(self, b: Dict) -> str:
        payloads = b.get("sample_payloads") or []
        params = b.get("params") or []
        param_str = ", ".join(
            (p.get("name", str(p)) if isinstance(p, dict) else str(p)) for p in params
        ) or "auto-detected by the agent"
        lines = [
            "\n" + "=" * 68,
            "EXPLOIT CONSENT REQUIRED — this is an active test, approve to proceed",
            "=" * 68,
            f"Agent        : {b.get('agent_id','?')}",
            f"Target       : {b.get('target','?')}",
            f"Vulnerability: {str(b.get('vuln_type','?')).upper()}",
            f"Objective    : {b.get('objective','?')}",
            "",
            "WHAT it will do:",
            f"  Attempt to confirm and demonstrate the {str(b.get('vuln_type','?')).upper()} "
            f"vulnerability at tier {b.get('tier','POC')} (proof-of-concept, read-only).",
            "HOW it will do it:",
            f"  {b.get('method') or 'Send crafted probe requests and analyze responses.'}",
            f"  Injection point(s): {param_str}",
            "WHICH payloads / signatures:",
        ]
        if payloads:
            for p in payloads[:5]:
                lines.append(f"    - {p}")
        else:
            lines.append("    - agent-selected payloads for this vulnerability class")
        lines.append("=" * 68)
        return "\n".join(lines)

    # ── decision ──

    async def confirm(self, briefing: Dict) -> bool:
        text = self.render_briefing(briefing)

        async with self._lock:
            if self.auto_approve:
                logger.info(f"[Consent] AUTO-APPROVED ({briefing.get('vuln_type')}) "
                            f"via AUTO_APPROVE_EXPLOITS")
                approved = True
            else:
                answer = await self._ask(text)
                approved = answer in ("Y", "YES")

        decision = {
            "agent_id": briefing.get("agent_id"),
            "vuln_type": briefing.get("vuln_type"),
            "objective": briefing.get("objective"),
            "target": briefing.get("target"),
            "approved": approved,
            "auto": self.auto_approve,
            "timestamp": datetime.now().isoformat(),
        }
        self.decisions.append(decision)
        logger.info(f"[Consent] {'APPROVED' if approved else 'DECLINED'}: "
                    f"{briefing.get('vuln_type')} @ {briefing.get('target')}")
        return approved

    async def _ask(self, text: str) -> str:
        print(text)
        loop = asyncio.get_event_loop()

        def _read() -> str:
            try:
                if self._prompt:
                    return (self._prompt(text) or "").strip().upper()
                return input("Proceed with THIS exploit? [yes/no]: ").strip().upper()
            except (EOFError, KeyboardInterrupt):
                return "NO"

        try:
            resp = await loop.run_in_executor(None, _read)
        except Exception:       # noqa: BLE001
            resp = "NO"
        return "YES" if resp in ("Y", "YES") else "NO"

    def summary(self) -> Dict:
        approved = [d for d in self.decisions if d["approved"]]
        return {
            "total": len(self.decisions),
            "approved": len(approved),
            "declined": len(self.decisions) - len(approved),
            "decisions": self.decisions,
        }


# Module-level singleton shared by all exploit agents.
_CONSENT = ExploitConsentManager()


def get_consent() -> ExploitConsentManager:
    return _CONSENT
