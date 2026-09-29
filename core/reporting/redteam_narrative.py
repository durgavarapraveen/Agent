"""Red-team narrative & purple-team debrief — REPORTING-time documentation.

This is a REPORTING/documentation layer (no offensive execution): it turns the
confirmed findings + attack chains into the artifacts a red-team/purple-team
engagement needs —

  * ATT&CK technique tagging per finding (tactic + technique id/name);
  * objective tracking (operator-declared crown-jewel goals → achieved?/evidence);
  * a human kill-chain narrative ordered by ATT&CK tactic;
  * a purple-team detection-gap checklist (techniques exercised → what a SOC
    SHOULD alert on, so the blue team can verify coverage);
  * a timestamped deconfliction summary of the actions taken.

All read-only over ctx state. Nothing here launches C2, evades detection, sends
phishing, or moves laterally — those stay human-operated, out of the tool.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# vuln class (upper) -> (tactic, technique_id, technique_name). Best-effort map of
# the classes this scanner produces onto MITRE ATT&CK Enterprise.
_ATTACK_MAP: Dict[str, Tuple[str, str, str]] = {
    "SQLI": ("Collection", "T1213", "Data from Information Repositories"),
    "NOSQLI": ("Collection", "T1213", "Data from Information Repositories"),
    "RCE": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "COMMAND_INJECTION": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "SSTI": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "DESERIALIZATION": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "RFI": ("Execution", "T1105", "Ingress Tool Transfer"),
    "FILE_UPLOAD": ("Persistence", "T1505.003", "Web Shell"),
    "LFI": ("Discovery", "T1083", "File and Directory Discovery"),
    "PATH_TRAVERSAL": ("Discovery", "T1083", "File and Directory Discovery"),
    "XXE": ("Collection", "T1213", "Data from Information Repositories"),
    "SSRF": ("Discovery", "T1046", "Network Service Discovery"),
    "OPEN_REDIRECT": ("Initial Access", "T1566.002", "Spearphishing Link"),
    "XSS": ("Execution", "T1059.007", "JavaScript"),
    "CSTI": ("Execution", "T1059.007", "JavaScript"),
    "IDOR": ("Collection", "T1213", "Data from Information Repositories"),
    "BOLA": ("Collection", "T1213", "Data from Information Repositories"),
    "BROKEN_ACCESS_CONTROL": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    "AUTH_BYPASS": ("Defense Evasion", "T1548", "Abuse Elevation Control Mechanism"),
    "JWT": ("Credential Access", "T1552", "Unsecured Credentials"),
    "SESSION": ("Credential Access", "T1539", "Steal Web Session Cookie"),
    "CSRF": ("Execution", "T1204", "User Execution"),
    "MASS_ASSIGNMENT": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    "CORS": ("Collection", "T1213", "Data from Information Repositories"),
    "OAUTH_ABUSE": ("Credential Access", "T1528", "Steal Application Access Token"),
    "SUBDOMAIN_TAKEOVER": ("Resource Development", "T1584.001", "Compromise Infrastructure: Domains"),
    "GRPC_MISSING_AUTHZ": ("Discovery", "T1046", "Network Service Discovery"),
    "GRAPHQL_INJECTION": ("Collection", "T1213", "Data from Information Repositories"),
    "API_SHADOW_ENDPOINT": ("Discovery", "T1595.003", "Active Scanning: Wordlist Scanning"),
    "WEB_CACHE_DECEPTION": ("Collection", "T1213", "Data from Information Repositories"),
    "CDN_ORIGIN_EXPOSURE": ("Reconnaissance", "T1590", "Gather Victim Network Information"),
    "SECRET_EXPOSURE": ("Credential Access", "T1552", "Unsecured Credentials"),
    "RATE_LIMIT": ("Credential Access", "T1110", "Brute Force"),
    "CREDENTIAL_BRUTE_FORCE": ("Credential Access", "T1110", "Brute Force"),
    "SUBDOMAIN_ENUM": ("Reconnaissance", "T1595", "Active Scanning"),
}
# Rough kill-chain ordering of tactics for narrative sequencing.
_TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access",
                 "Execution", "Persistence", "Privilege Escalation",
                 "Defense Evasion", "Credential Access", "Discovery",
                 "Lateral Movement", "Collection", "Exfiltration", "Impact"]
# Techniques a mature SOC USUALLY alerts on (loud) vs usually misses (quiet).
# Used only to seed the purple-team checklist — not a claim about this target.
_USUALLY_DETECTED = {"T1110", "T1595.003", "T1046", "T1595"}

# Objective keyword → the vuln classes whose CONFIRMED presence achieves it.
_OBJECTIVE_RULES: List[Tuple[Tuple[str, ...], Tuple[str, ...], str]] = [
    (("domain admin", "admin", "privilege", "privesc", "elevate"),
     ("BROKEN_ACCESS_CONTROL", "AUTH_BYPASS", "MASS_ASSIGNMENT", "RCE"),
     "administrative / privilege-escalation access"),
    (("database", "db", "crown", "pii", "data", "records"),
     ("SQLI", "NOSQLI", "IDOR", "BOLA", "XXE", "GRAPHQL_INJECTION", "WEB_CACHE_DECEPTION"),
     "sensitive-data / database access"),
    (("rce", "shell", "code execution", "command"),
     ("RCE", "COMMAND_INJECTION", "DESERIALIZATION", "SSTI", "FILE_UPLOAD"),
     "remote code execution / foothold"),
    (("takeover", "account", "session", "impersonat"),
     ("IDOR", "AUTH_BYPASS", "JWT", "SESSION", "OAUTH_ABUSE"),
     "account takeover"),
    (("internal", "ssrf", "network", "pivot"),
     ("SSRF", "CDN_ORIGIN_EXPOSURE"),
     "internal-network reach"),
]


def _confirmed(v: Dict) -> bool:
    return str(v.get("status") or "").upper() == "CONFIRMED" or bool(v.get("confirmed"))


def _cls(v: Dict) -> str:
    return (v.get("type") or v.get("vuln_type") or v.get("attack_type") or "").upper().replace(" ", "_").replace("-", "_")


def _technique(vuln_class: str) -> Tuple[str, str, str]:
    return _ATTACK_MAP.get(vuln_class, ("Discovery", "T1595", "Active Scanning"))


def tag_attack_techniques(vulns: List[Dict]) -> int:
    """Annotate each finding in place with its ATT&CK tactic/technique. Returns
    the number tagged. Idempotent."""
    n = 0
    for v in vulns or []:
        if not isinstance(v, dict) or v.get("attack_technique_id"):
            continue
        tac, tid, tname = _technique(_cls(v))
        v["attack_tactic"] = tac
        v["attack_technique_id"] = tid
        v["attack_technique"] = tname
        n += 1
    return n


def _declared_objectives(ctx) -> List[str]:
    objs = getattr(ctx, "redteam_objectives", None)
    if isinstance(objs, list) and objs:
        return [str(o) for o in objs]
    env = os.getenv("REDTEAM_OBJECTIVES", "").strip()
    return [o.strip() for o in env.split(",") if o.strip()]


def _track_objectives(ctx, vulns: List[Dict]) -> List[Dict[str, Any]]:
    confirmed = [v for v in vulns if _confirmed(v)]
    classes = {_cls(v) for v in confirmed}
    out: List[Dict[str, Any]] = []

    declared = _declared_objectives(ctx)
    if declared:
        for name in declared:
            low = name.lower()
            achieved, why = False, ""
            for kws, needed, label in _OBJECTIVE_RULES:
                if any(k in low for k in kws):
                    hit = classes & set(needed)
                    if hit:
                        achieved, why = True, f"{label} via {', '.join(sorted(hit))}"
                    break
            out.append({"objective": name, "achieved": achieved,
                        "evidence": why or "no confirmed finding satisfies this objective"})
        return out

    # No operator objectives declared → derive impact objectives from what was
    # actually achieved (so the narrative still has goals to report against).
    for kws, needed, label in _OBJECTIVE_RULES:
        hit = classes & set(needed)
        if hit:
            out.append({"objective": f"(derived) {label}", "achieved": True,
                        "evidence": f"confirmed via {', '.join(sorted(hit))}"})
    return out


def _kill_chain(vulns: List[Dict]) -> List[Dict[str, Any]]:
    """Order confirmed findings by ATT&CK tactic into a readable narrative."""
    confirmed = [v for v in vulns if _confirmed(v)]
    steps: List[Dict[str, Any]] = []
    for v in confirmed:
        tac, tid, tname = _technique(_cls(v))
        steps.append({
            "tactic": tac, "technique_id": tid, "technique": tname,
            "finding": (v.get("title") or _cls(v)),
            "location": v.get("location") or v.get("target") or v.get("url") or "",
            "severity": (v.get("severity") or "").upper(),
            "_order": _TACTIC_ORDER.index(tac) if tac in _TACTIC_ORDER else 99,
        })
    steps.sort(key=lambda s: (s["_order"], s["technique_id"]))
    for s in steps:
        s.pop("_order", None)
    return steps


def _detection_gaps(vulns: List[Dict]) -> List[Dict[str, Any]]:
    """Purple-team checklist: techniques exercised → whether a SOC usually
    detects them. 'usually_detected: false' = verify your telemetry covers it.
    This is a debrief prompt, not a measurement of this target's blue team."""
    seen: Dict[str, Dict[str, Any]] = {}
    for v in vulns:
        if not _confirmed(v):
            continue
        tac, tid, tname = _technique(_cls(v))
        if tid not in seen:
            seen[tid] = {"technique_id": tid, "technique": tname, "tactic": tac,
                         "usually_detected": tid in _USUALLY_DETECTED,
                         "example_finding": (v.get("title") or _cls(v))}
    # Quiet techniques first — those are the gaps worth the debrief.
    return sorted(seen.values(), key=lambda x: (x["usually_detected"], x["tactic"]))


def _deconfliction(ctx) -> Dict[str, Any]:
    """Timestamped action summary for white-cell deconfliction, from captured
    attack traffic. Counts + window only (no bodies)."""
    reqs = getattr(ctx, "captured_requests", None) or []
    hosts: Dict[str, int] = {}
    ts: List[float] = []
    for r in reqs:
        if not isinstance(r, dict):
            continue
        u = r.get("url") or ""
        h = urlparse(u).netloc or ""
        if h:
            hosts[h] = hosts.get(h, 0) + 1
        for k in ("timestamp", "ts", "time"):
            val = r.get(k)
            if isinstance(val, (int, float)):
                ts.append(float(val))
                break
    out = {"total_actions": len(reqs), "hosts": hosts}
    if ts:
        out["first_action"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(ts)))
        out["last_action"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(ts)))
    # Human-in-the-loop decisions on critical tasks (approve/deny audit trail).
    hitl = getattr(ctx, "hitl_decisions", None)
    if isinstance(hitl, list) and hitl:
        out["critical_task_approvals"] = hitl[:50]
    return out


def build_redteam_narrative(ctx) -> Dict[str, Any]:
    """Assemble the red-team/purple-team artifact from ctx state and attach it to
    ctx.redteam_narrative. Read-only; never raises."""
    try:
        vulns = list(getattr(ctx, "vulnerabilities", None) or [])
        tagged = tag_attack_techniques(vulns)
        narrative = {
            "objectives": _track_objectives(ctx, vulns),
            "kill_chain": _kill_chain(vulns),
            "detection_gaps": _detection_gaps(vulns),
            "deconfliction": _deconfliction(ctx),
            "techniques_tagged": tagged,
        }
    except Exception as e:
        logger.warning("[RedTeamNarrative] build failed (non-fatal): %s", e)
        return {}
    try:
        setattr(ctx, "redteam_narrative", narrative)
        if hasattr(ctx, "update"):
            ctx.update("redteam_narrative", narrative)
    except Exception:
        pass
    achieved = sum(1 for o in narrative["objectives"] if o.get("achieved"))
    logger.info("[RedTeamNarrative] %d objective(s) achieved, %d kill-chain step(s), "
                "%d detection-gap technique(s)", achieved,
                len(narrative["kill_chain"]), len(narrative["detection_gaps"]))
    return narrative
