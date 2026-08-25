"""
SharedContext - Shared memory store for all agents.
Central brain writes everything here.
Agents get ONLY what's relevant to their task (brain decides).
"""

import json
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
import re

logger = logging.getLogger(__name__)


class SharedContext:
    """Thread-safe shared memory. Single source of truth."""

    def __init__(self, target: str, scope: Dict = None):
        self.target = target
        self.scope = scope or {}
        self.created_at = datetime.now().isoformat()
        self._lock = threading.Lock()

        # ── Recon data ──
        self.subdomains: List[str] = []
        self.ips: List[str] = []
        self.ports: Dict[str, List[Dict]] = {}       # host → [{port, service, version}]
        self.technologies: Dict[str, List[str]] = {}  # host → [techs]
        self.endpoints: List[Dict] = []               # [{url, method, params, status}]
        self.parameters: Dict[str, List[str]] = {}    # endpoint → [param names]
        self.directories: List[Dict] = []             # [{path, status, size}]
        self.headers: Dict[str, Dict] = {}            # host → {header: value}
        self.js_files: List[Dict] = []                # [{url, endpoints_found, secrets}]
        self.secrets: List[Dict] = []                 # [{type, value, source}]
        self.ssl_info: Dict = {}
        self.whois: str = ""
        self.dns_records: List[Dict] = []

        # ── Vulnerability data ──
        self.vulnerabilities: List[Dict] = []   # [{id, type, location, severity, details}]
        self.attack_chains: List[Dict] = []     # [{chain_id, steps, impact}]

        # ── Captured HTTP traffic (for replay in exploits) ──
        self.captured_requests: List[Dict] = []  # [{method,url,headers,post_data,status,...}]
        self.crawled_pages: List[str] = []

        # ── Exploitation data ──
        self.exploit_plan: Optional[Dict] = None
        self.exploit_results: List[Dict] = []   # [{vuln_id, payload, success, proof}]

        # ── Phase 3: Post-exploitation data ──
        self.shell_access: List[Dict] = []       # [{host, user, method, source_vuln}]
        self.privesc_findings: List[Dict] = []    # [{host, technique, detail, path, severity}]
        self.harvested_creds: List[Dict] = []     # [{type, username, secret, source, host}]
        self.lateral_plan: Optional[Dict] = None  # {pivots, internal_hosts, steps}
        self.persistence_plan: List[Dict] = []    # [{mechanism, artifact, installed, tier}]
        self.mitre_mappings: List[Dict] = []       # [{technique_id, name, tactic, source}]

        # ── Agent tracking ──
        self.agents_spawned: List[Dict] = []    # [{id, objective, status, result_summary}]
        self.brain_log: List[Dict] = []         # [{timestamp, thought, action}]

        # ── Raw tool outputs ──
        self._raw_outputs: Dict[str, str] = {}  # agent_id → raw output (for debugging)

    # ── Write methods (thread-safe) ──

    def add_subdomains(self, subs: List[str], source: str = ""):
        with self._lock:
            added = 0
            for s in subs:
                if s and s not in self.subdomains:
                    self.subdomains.append(s)
                    added += 1
            if added > 0:
                logger.info(f"SHARED_CONTEXT_UPDATE: key=subdomains, count={len(self.subdomains)} (+{added} from {source})")

    def add_ips(self, ips: List[str], source: str = ""):
        with self._lock:
            added = 0
            for ip in ips:
                if ip and ip not in self.ips:
                    self.ips.append(ip)
                    added += 1
            if added > 0:
                logger.info(f"SHARED_CONTEXT_UPDATE: key=ips, count={len(self.ips)} (+{added} from {source})")

    def add_ports(self, host: str, ports: List, source: str = ""):
        """Add ports - handles both ints and dicts."""
        with self._lock:
            existing = self.ports.get(host, [])
            existing_nums = {p.get("port") if isinstance(p, dict) else p for p in existing}
            
            for p in ports:
                if isinstance(p, int):
                    port_dict = {"port": p, "service": "unknown", "version": ""}
                    if p == 22:
                        port_dict["service"] = "ssh"
                    elif p == 80:
                        port_dict["service"] = "http"
                    elif p == 443:
                        port_dict["service"] = "https"
                elif isinstance(p, dict):
                    port_dict = p
                else:
                    port_dict = {"port": str(p), "service": "unknown", "version": ""}
                
                port_num = port_dict.get("port")
                if port_num and port_num not in existing_nums:
                    existing.append(port_dict)
                    existing_nums.add(port_num)
            
            self.ports[host] = existing
            logger.info(f"SHARED_CONTEXT_UPDATE: key=ports[{host}], count={len(existing)} from {source}")

    def add_endpoints(self, endpoints: List[Dict], source: str = ""):
        with self._lock:
            existing_urls = {e.get("url") for e in self.endpoints}
            added = 0
            for ep in endpoints:
                url_str = ep.get("url") if isinstance(ep, dict) else str(ep)
                if url_str and url_str not in existing_urls:
                    self.endpoints.append(ep if isinstance(ep, dict) else {"url": url_str})
                    existing_urls.add(url_str)
                    added += 1
            if added > 0:
                logger.info(f"SHARED_CONTEXT_UPDATE: key=endpoints, count={len(self.endpoints)} (+{added} from {source})")

    def add_directories(self, dirs: List[Dict], source: str = ""):
        with self._lock:
            existing_paths = {d.get("path") for d in self.directories}
            for d in dirs:
                if d.get("path") and d["path"] not in existing_paths:
                    self.directories.append(d)
                    existing_paths.add(d["path"])

    def add_technologies(self, host: str, techs: List):
         existing = set(self.technologies.get(host, []))
         for tech in techs:
             if isinstance(tech, dict):
                 tech_str = tech.get("name", str(tech))
             else:
                 tech_str = str(tech).strip()
             if tech_str:
                 existing.add(tech_str)
         self.technologies[host] = sorted(existing)
         logger.info(f"SHARED_CONTEXT_UPDATE: key=technologies[{host}], count={len(self.technologies[host])}")

    def add_vulnerability(self, vuln: Dict) -> bool:
        from core.dedup_tracker import DeduplicationTracker
        with self._lock:
            vuln_type = str(vuln.get("type") or vuln.get("vuln_type") or "").lower().strip()
            proof = str(vuln.get("proof") or vuln.get("details") or "").strip()
            payload = str(vuln.get("payload") or "").strip()
            tool_name = str(vuln.get("tool") or "unknown").strip()

            if not proof:
                logger.info(f"VULN_REJECTED: type={vuln_type or 'unknown'} reason='No proof string or details captured'")
                return False

            if "rce" in vuln_type or "command" in vuln_type:
                rce_patterns = [r"uid=\d+", r"root:", r"www-data", r"Linux version", r"Windows IP", r"system"]
                if not any(re.search(pat, proof, re.IGNORECASE) for pat in rce_patterns):
                    logger.info(f"VULN_REJECTED: type={vuln_type} reason='No command output captured'")
                    return False

            elif "sqli" in vuln_type or "sql" in vuln_type:
                if not payload:
                    logger.info(f"VULN_REJECTED: type={vuln_type} reason='No SQL injection payload recorded'")
                    return False
                sqli_indicators = ["error", "syntax", "sqlite", "mysql", "postgresql", "oracle", "extracted", "tables_found", "table", "version"]
                if not any(ind in proof.lower() for ind in sqli_indicators):
                    logger.info(f"VULN_REJECTED: type={vuln_type} reason='No database error message or extracted data in proof'")
                    return False

            elif "auth_bypass" in vuln_type:
                if "200" not in proof and "unauthorized" not in proof.lower() and "token" not in proof.lower() and "data" not in proof.lower():
                    logger.info(f"VULN_REJECTED: type={vuln_type} reason='No unauthorized access or HTTP 200 proof'")
                    return False

            # Check deduplication BEFORE adding
            dedup = DeduplicationTracker()
            if dedup.is_duplicate(tool=tool_name, finding_type=vuln_type, data=payload or proof or vuln.get("title", "")):
                logger.info(f"VULN_DEDUPLICATED: type={vuln_type} title='{vuln.get('title', '')}' (already recorded)")
                return False

            dedup.register_finding(tool=tool_name, finding_type=vuln_type, data=payload or proof or vuln.get("title", ""))

            vuln.setdefault("id", f"VULN-{len(self.vulnerabilities)+1:03d}")
            vuln.setdefault("timestamp", datetime.now().isoformat())
            self.vulnerabilities.append(vuln)
            logger.info(f"SHARED_CONTEXT_UPDATE: key=vulnerabilities, count={len(self.vulnerabilities)}")
            logger.info(f"  New vuln: [{vuln.get('severity','?')}] {vuln.get('title', vuln.get('type', '?'))}")
            return True

    def add_exploit_result(self, result: Dict):
        with self._lock:
            result.setdefault("timestamp", datetime.now().isoformat())
            self.exploit_results.append(result)

    def add_captured_requests(self, requests: List[Dict], pages: List[str] = None):
        """Store intercepted HTTP requests (deduped) for replay in exploits."""
        with self._lock:
            seen = {(r.get("method"), r.get("url"), (r.get("post_data") or "")[:200])
                    for r in self.captured_requests}
            for req in requests:
                key = (req.get("method"), req.get("url"),
                       (req.get("post_data") or "")[:200])
                if req.get("url") and key not in seen:
                    self.captured_requests.append(req)
                    seen.add(key)
            for pg in (pages or []):
                if pg and pg not in self.crawled_pages:
                    self.crawled_pages.append(pg)
            logger.info(f"Captured requests: +{len(requests)}, "
                        f"total={len(self.captured_requests)}")

    # ── Phase 3: Post-exploitation writes ──

    def add_shell_access(self, shell: Dict):
        with self._lock:
            shell.setdefault("timestamp", datetime.now().isoformat())
            self.shell_access.append(shell)
            logger.info(f"  Shell access: {shell.get('user','?')}@{shell.get('host','?')} "
                        f"via {shell.get('method','?')}")

    def has_shell_access(self) -> bool:
        """True if any RCE/shell foothold exists (gate for post-exploitation)."""
        if self.shell_access:
            return True
        return any(
            (v.get("type", "").lower() in ("rce", "file_upload", "ssti", "command_injection"))
            for v in self.vulnerabilities
        )

    def add_privesc_finding(self, finding: Dict):
        with self._lock:
            self.privesc_findings.append(finding)
            logger.info(f"  Privesc: [{finding.get('severity','?')}] {finding.get('technique','?')}")

    def add_credentials(self, creds: List[Dict], source: str = ""):
        with self._lock:
            existing = {(c.get("username"), c.get("secret")) for c in self.harvested_creds}
            for c in creds:
                key = (c.get("username"), c.get("secret"))
                if key not in existing and any(key):
                    c.setdefault("source", source)
                    self.harvested_creds.append(c)
                    existing.add(key)

    def add_persistence(self, mech: Dict):
        with self._lock:
            mech.setdefault("timestamp", datetime.now().isoformat())
            self.persistence_plan.append(mech)

    def add_mitre_mappings(self, mappings: List[Dict]):
        with self._lock:
            existing = {m.get("technique_id") for m in self.mitre_mappings}
            for m in mappings:
                if m.get("technique_id") and m["technique_id"] not in existing:
                    self.mitre_mappings.append(m)
                    existing.add(m["technique_id"])

    def log_agent(self, agent_id: str, objective: str, status: str, result_summary: str = ""):
        with self._lock:
            self.agents_spawned.append({
                "id": agent_id,
                "objective": objective,
                "status": status,
                "result_summary": result_summary,
                "timestamp": datetime.now().isoformat(),
            })

    def log_brain(self, thought: str, action: str = ""):
        with self._lock:
            self.brain_log.append({
                "timestamp": datetime.now().isoformat(),
                "thought": thought,
                "action": action,
            })

    def store_raw(self, agent_id: str, output: str):
        with self._lock:
            self._raw_outputs[agent_id] = output[:10000]

    # ── Read methods (for brain — full picture) ──

    def get_full_summary(self, max_chars: int = 6000) -> str:
        """Full context summary for Central Brain decisions"""
        parts = [f"TARGET: {self.target}"]

        if self.subdomains:
            parts.append(f"SUBDOMAINS ({len(self.subdomains)}): {', '.join(self.subdomains[:20])}")
        if self.ips:
            parts.append(f"IPs: {', '.join(self.ips[:10])}")
        if self.ports:
            for host, plist in self.ports.items():
                port_str = ", ".join(f"{p['port']}/{p.get('service','?')}" for p in plist[:15])
                parts.append(f"PORTS [{host}]: {port_str}")
        if self.technologies:
            for host, techs in self.technologies.items():
                parts.append(f"TECH [{host}]: {', '.join(techs[:10])}")
        if self.endpoints:
            parts.append(f"ENDPOINTS ({len(self.endpoints)}): {json.dumps(self.endpoints[:15], default=str)}")
        if self.directories:
            dir_str = ", ".join(f"{d['path']}({d.get('status','')})" for d in self.directories[:20])
            parts.append(f"DIRECTORIES ({len(self.directories)}): {dir_str}")
        if self.headers:
            parts.append(f"HEADERS: {json.dumps(self.headers, default=str)[:500]}")
        if self.secrets:
            parts.append(f"SECRETS ({len(self.secrets)}): {json.dumps(self.secrets[:5], default=str)}")
        if self.ssl_info:
            parts.append(f"SSL: {json.dumps(self.ssl_info, default=str)[:300]}")
        if self.js_files:
            parts.append(f"JS FILES: {len(self.js_files)} analyzed")
        if self.vulnerabilities:
            vuln_str = "\n".join(
                f"  [{v.get('severity','?')}] {v.get('title','?')} @ {v.get('location','?')}"
                for v in self.vulnerabilities[:20]
            )
            parts.append(f"VULNERABILITIES ({len(self.vulnerabilities)}):\n{vuln_str}")
        if self.attack_chains:
            parts.append(f"ATTACK CHAINS: {json.dumps(self.attack_chains[:5], default=str)}")
        if self.exploit_results:
            parts.append(f"EXPLOIT RESULTS: {len(self.exploit_results)} executed")

        # Agent history (compact)
        if self.agents_spawned:
            agent_str = ", ".join(f"{a['id']}({a['status']})" for a in self.agents_spawned[-10:])
            parts.append(f"AGENTS: {agent_str}")

        summary = "\n".join(parts)
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n... (truncated)"
        return summary

    # ── Selective context for agents (brain picks what's relevant) ──

    def get_context_for_agent(self, objective: str, relevant_keys: List[str]) -> str:
        """
        Brain calls this to build ONLY relevant context for an agent.
        relevant_keys: which data sections to include.
        Example: ["target", "subdomains", "ports"] for a port scanner.
        """
        parts = [f"TARGET: {self.target}", f"OBJECTIVE: {objective}"]

        key_map = {
            "target": lambda: f"TARGET: {self.target}",
            "scope": lambda: f"SCOPE: {json.dumps(self.scope, default=str)[:500]}",
            "subdomains": lambda: f"SUBDOMAINS: {json.dumps(self.subdomains[:30])}",
            "ips": lambda: f"IPs: {json.dumps(self.ips[:20])}",
            "ports": lambda: f"PORTS: {json.dumps(self.ports, default=str)[:1500]}",
            "technologies": lambda: f"TECH: {json.dumps(self.technologies, default=str)[:800]}",
            "endpoints": lambda: f"ENDPOINTS: {json.dumps(self.endpoints[:30], default=str)}",
            "captured_requests": lambda: (
                "CAPTURED REQUESTS (real intercepted traffic — replay/fuzz these):\n"
                + json.dumps([
                    {"method": r.get("method"), "url": r.get("url"),
                     "type": r.get("resource_type"),
                     "post_data": (r.get("post_data") or "")[:300],
                     "status": r.get("status")}
                    for r in self.captured_requests[:40]], default=str)),
            "parameters": lambda: f"PARAMETERS: {json.dumps(self.parameters, default=str)[:800]}",
            "directories": lambda: f"DIRECTORIES: {json.dumps(self.directories[:30], default=str)}",
            "headers": lambda: f"HEADERS: {json.dumps(self.headers, default=str)[:800]}",
            "js_files": lambda: f"JS FILES: {json.dumps(self.js_files[:10], default=str)}",
            "secrets": lambda: f"SECRETS: {json.dumps(self.secrets[:10], default=str)}",
            "ssl_info": lambda: f"SSL: {json.dumps(self.ssl_info, default=str)[:500]}",
            "vulnerabilities": lambda: f"VULNS: {json.dumps(self.vulnerabilities[:20], default=str)}",
            "attack_chains": lambda: f"CHAINS: {json.dumps(self.attack_chains[:5], default=str)}",
            "exploit_results": lambda: f"EXPLOITS: {json.dumps(self.exploit_results[:10], default=str)}",
        }

        for key in relevant_keys:
            if key in key_map:
                val = key_map[key]()
                if val:
                    parts.append(val)

        return "\n".join(parts)

    # ── Export ──

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scope": self.scope,
            "subdomains": self.subdomains,
            "ips": self.ips,
            "ports": self.ports,
            "technologies": self.technologies,
            "endpoints": self.endpoints,
            "captured_requests": self.captured_requests,
            "crawled_pages": self.crawled_pages,
            "parameters": self.parameters,
            "directories": self.directories,
            "headers": self.headers,
            "js_files": self.js_files,
            "secrets": self.secrets,
            "ssl_info": self.ssl_info,
            "vulnerabilities": self.vulnerabilities,
            "attack_chains": self.attack_chains,
            "exploit_plan": self.exploit_plan,
            "exploit_results": self.exploit_results,
            "shell_access": self.shell_access,
            "privesc_findings": self.privesc_findings,
            "harvested_creds": self.harvested_creds,
            "lateral_plan": self.lateral_plan,
            "persistence_plan": self.persistence_plan,
            "mitre_mappings": self.mitre_mappings,
            "agents_spawned": self.agents_spawned,
            "brain_log": self.brain_log,
        }

    def save(self, path: str):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, default=str, ensure_ascii=False)