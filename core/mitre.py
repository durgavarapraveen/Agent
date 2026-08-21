"""
MITRE ATT&CK Integration (Phase 3, Module 4)

Maps discovered vulnerabilities and post-exploitation actions to MITRE ATT&CK
techniques, and surfaces detection methods + evasion considerations for each.
Uses a local technique table (no network dependency).
"""

import logging
from typing import Dict, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# technique_id -> {name, tactic, detection, evasion}
ATTACK_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
              "detection": "WAF logs, anomalous request patterns, IDS signatures",
              "evasion": "Encoding/obfuscation, low-and-slow request pacing"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
              "detection": "Process creation logs, shell spawns from web user",
              "evasion": "Living-off-the-land binaries, encoded commands"},
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence",
              "detection": "File integrity monitoring on webroot, new *.php/.jsp files",
              "evasion": "Blend filename with app, small handler, timestomping"},
    "T1053.003": {"name": "Scheduled Task/Job: Cron", "tactic": "Persistence",
              "detection": "Auditd on /etc/cron*, unexpected cron entries",
              "evasion": "Hidden dotfile names, comment as system job"},
    "T1543.002": {"name": "Create/Modify System Process: systemd", "tactic": "Persistence",
              "detection": "New/modified .service units, systemctl audit",
              "evasion": "Benign service naming, disable then re-enable timing"},
    "T1098.004": {"name": "Account Manipulation: SSH authorized_keys", "tactic": "Persistence",
              "detection": "FIM on authorized_keys, new key fingerprints",
              "evasion": "Match key comment to existing users"},
    "T1548.001": {"name": "Abuse Elevation Control: setuid/setgid", "tactic": "Privilege Escalation",
              "detection": "SUID inventory diff, GTFOBins process trees",
              "evasion": "Use expected admin binaries"},
    "T1548.003": {"name": "Abuse Elevation Control: sudo", "tactic": "Privilege Escalation",
              "detection": "sudo logs (/var/log/auth.log), unusual sudo targets",
              "evasion": "Use already-permitted NOPASSWD entries"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
              "detection": "Kernel crash logs, unexpected root processes",
              "evasion": "Kernel-version-matched exploit, clean up droppers"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
              "detection": "Access to /etc/shadow, LSASS/memory reads",
              "evasion": "Read via legitimate admin tooling"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "detection": "New auth sessions, cross-host logon patterns",
              "evasion": "Reuse valid creds, normal business hours"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement",
              "detection": "auth.log SSH accepts, new source IPs",
              "evasion": "Key reuse from trusted hosts"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access",
              "detection": "Access to config files, history files, env dumps",
              "evasion": "Read-only access, avoid mass grep signatures"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "detection": "Port-scan IDS signatures, connection fan-out",
              "evasion": "Slow scan, limit port ranges"},
}

# vuln_type / action -> technique_ids
VULN_TECHNIQUE_MAP = {
    "sqli": ["T1190", "T1003"],
    "xss": ["T1190"],
    "rce": ["T1190", "T1059"],
    "command_injection": ["T1059"],
    "lfi": ["T1190", "T1552"],
    "file_upload": ["T1190", "T1505.003"],
    "ssti": ["T1190", "T1059"],
    "ssrf": ["T1190", "T1046"],
    "idor": ["T1190"],
    "auth_bypass": ["T1190"],
    "credentials": ["T1552", "T1003"],
    # post-exploitation actions
    "kernel_exploit": ["T1068"],
    "suid_abuse": ["T1548.001"],
    "sudo_misconfig": ["T1548.003"],
    "cred_harvest": ["T1003", "T1552"],
    "lateral_move": ["T1021", "T1021.004"],
    "persistence": ["T1053.003", "T1543.002", "T1098.004", "T1505.003"],
    "recon": ["T1046"],
}


@dataclass
class TechniqueMapping:
    technique_id: str
    name: str
    tactic: str
    detection: str = ""
    evasion: str = ""
    source: str = ""     # what triggered the mapping (vuln id / action)

    def to_dict(self) -> Dict:
        return {"technique_id": self.technique_id, "name": self.name,
                "tactic": self.tactic, "detection": self.detection,
                "evasion": self.evasion, "source": self.source}


class MitreMapper:
    """Maps vulns/actions to ATT&CK techniques with detection + evasion notes."""

    def __init__(self):
        self.mappings: List[TechniqueMapping] = []

    def _lookup(self, tid: str, source: str) -> TechniqueMapping:
        meta = ATTACK_TECHNIQUES.get(tid, {"name": tid, "tactic": "Unknown"})
        return TechniqueMapping(
            technique_id=tid, name=meta.get("name", tid),
            tactic=meta.get("tactic", "Unknown"),
            detection=meta.get("detection", ""), evasion=meta.get("evasion", ""),
            source=source,
        )

    def map_key(self, key: str, source: str = "") -> List[TechniqueMapping]:
        """Map a single vuln_type/action key to techniques."""
        out = []
        for tid in VULN_TECHNIQUE_MAP.get((key or "").lower(), []):
            out.append(self._lookup(tid, source or key))
        return out

    def map_context(self, ctx) -> List[TechniqueMapping]:
        """Map everything discovered so far in SharedContext to ATT&CK."""
        seen = {}

        def add(mappings):
            for m in mappings:
                seen.setdefault(m.technique_id, m)

        for v in getattr(ctx, "vulnerabilities", []) or []:
            add(self.map_key(v.get("type", ""), v.get("id", v.get("title", ""))))
        for f in getattr(ctx, "privesc_findings", []) or []:
            add(self.map_key(f.get("technique", ""), f.get("host", "privesc")))
        if getattr(ctx, "harvested_creds", None):
            add(self.map_key("cred_harvest", "harvest"))
        if getattr(ctx, "lateral_plan", None):
            add(self.map_key("lateral_move", "lateral"))
        for p in getattr(ctx, "persistence_plan", []) or []:
            add(self.map_key("persistence", p.get("mechanism", "persistence")))

        self.mappings = list(seen.values())
        # Persist onto context
        if hasattr(ctx, "add_mitre_mappings"):
            ctx.add_mitre_mappings([m.to_dict() for m in self.mappings])
        logger.info(f"[MITRE] Mapped {len(self.mappings)} ATT&CK techniques")
        return self.mappings

    def navigator_layer(self) -> Dict:
        """Export a minimal ATT&CK Navigator layer for reporting."""
        return {
            "name": "Autonomous Pentest Coverage",
            "versions": {"layer": "4.5", "attack": "14"},
            "domain": "enterprise-attack",
            "techniques": [
                {"techniqueID": m.technique_id, "score": 1, "comment": m.source}
                for m in self.mappings
            ],
        }

    def by_tactic(self) -> Dict[str, List[Dict]]:
        out: Dict[str, List[Dict]] = {}
        for m in self.mappings:
            out.setdefault(m.tactic, []).append(m.to_dict())
        return out
