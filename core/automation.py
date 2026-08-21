"""
Automation Rules (Phase 4, Module 4)

A small event-driven rules engine over SharedContext:
  - Auto-escalate when RCE / shell is found
  - Auto-chain vulnerabilities
  - Auto-report after exploitation
  - Scheduled scanning (daily/weekly) config
  - Remediation tracking

Rules are evaluated against the context and return recommended actions. The
engine itself performs no destructive work; the brain decides which recommended
actions to carry out via existing managers.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    name: str
    action: str                     # symbolic action the brain can dispatch
    condition: Callable[["object"], bool]
    description: str = ""
    once: bool = True               # fire at most once per engagement
    fired: bool = False

    def to_dict(self) -> Dict:
        return {"name": self.name, "action": self.action,
                "description": self.description, "fired": self.fired}


@dataclass
class RemediationItem:
    vuln_id: str
    title: str
    severity: str
    status: str = "open"            # open | in_progress | remediated | accepted
    owner: str = ""
    note: str = ""
    updated: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return self.__dict__.copy()


class AutomationEngine:
    """Evaluates automation rules and tracks remediation."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.rules: List[Rule] = self._default_rules()
        self.remediation: Dict[str, RemediationItem] = {}
        self.triggered_log: List[Dict] = []

    # ── rule set ──

    def _default_rules(self) -> List[Rule]:
        def has_rce(ctx):
            return ctx.has_shell_access() if hasattr(ctx, "has_shell_access") else any(
                v.get("type", "").lower() in ("rce", "file_upload", "ssti", "command_injection")
                for v in ctx.vulnerabilities)

        def multi_vuln(ctx):
            return len(ctx.vulnerabilities) >= 2

        def exploited(ctx):
            return any(e.get("success") for e in ctx.exploit_results)

        return [
            Rule("auto_escalate_on_rce", "run_post_exploitation", has_rce,
                 "RCE/shell foothold detected -> run privilege escalation"),
            Rule("auto_chain_vulns", "build_attack_chains", multi_vuln,
                 "Multiple vulns present -> build & score attack chains"),
            Rule("auto_report_after_exploit", "generate_report", exploited,
                 "At least one successful exploit -> generate enterprise report"),
        ]

    # ── evaluation ──

    def evaluate(self) -> List[Dict]:
        """Return the list of actions whose conditions are newly satisfied."""
        actions = []
        for r in self.rules:
            if r.once and r.fired:
                continue
            try:
                ok = bool(r.condition(self.ctx))
            except Exception as e:      # noqa: BLE001
                logger.debug(f"[Automation] rule '{r.name}' error: {e}")
                ok = False
            if ok:
                r.fired = True
                entry = {"rule": r.name, "action": r.action,
                         "description": r.description,
                         "at": datetime.now().isoformat()}
                self.triggered_log.append(entry)
                actions.append(entry)
                logger.info(f"[Automation] Rule fired: {r.name} -> {r.action}")
        return actions

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    # ── scheduled scanning ──

    @staticmethod
    def schedule_config(target: str, cadence: str = "weekly",
                        hour: int = 3, minute: int = 17) -> Dict:
        """Produce a cron-style schedule spec for recurring scans."""
        cadence = cadence.lower()
        cron = {
            "daily":  f"{minute} {hour} * * *",
            "weekly": f"{minute} {hour} * * 1",     # Mondays
            "monthly": f"{minute} {hour} 1 * *",
        }.get(cadence, f"{minute} {hour} * * 1")
        return {
            "target": target, "cadence": cadence, "cron": cron,
            "command": f"python main.py --target {target} --tier POC",
            "note": "Install via OS scheduler / CI cron; each run appends a new report.",
        }

    # ── remediation tracking ──

    def sync_remediation(self):
        """Create/refresh a remediation item for each known vulnerability."""
        for v in self.ctx.vulnerabilities:
            vid = str(v.get("id", v.get("title", "")))
            if not vid:
                continue
            if vid not in self.remediation:
                self.remediation[vid] = RemediationItem(
                    vuln_id=vid, title=str(v.get("title", v.get("type", "?"))),
                    severity=str(v.get("severity", "MEDIUM")).upper())

    def set_remediation_status(self, vuln_id: str, status: str,
                               owner: str = "", note: str = "") -> bool:
        item = self.remediation.get(vuln_id)
        if not item:
            return False
        item.status = status
        item.owner = owner or item.owner
        item.note = note or item.note
        item.updated = datetime.now().isoformat()
        return True

    def remediation_report(self) -> Dict:
        self.sync_remediation()
        items = [i.to_dict() for i in self.remediation.values()]
        by_status: Dict[str, int] = {}
        for i in items:
            by_status[i["status"]] = by_status.get(i["status"], 0) + 1
        return {"items": items, "summary": by_status,
                "open": by_status.get("open", 0), "total": len(items)}

    def to_dict(self) -> Dict:
        return {
            "rules": [r.to_dict() for r in self.rules],
            "triggered": self.triggered_log,
            "remediation": self.remediation_report(),
        }
