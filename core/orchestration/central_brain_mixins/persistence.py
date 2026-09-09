"""PersistenceMixin — Postgres writers moved out of CentralBrain.

Persists recon findings, captured requests, vulnerabilities, exploit results,
and post-exploit findings via `core.database.pg_store` repositories.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class PersistenceMixin:
    async def _persist_recon_findings(self):
        """Save recon discoveries to knowledge store."""
        try:
            logger.info("Persisting recon findings...")
            
            # ── Debug: Log what's actually in the context ──
            logger.debug(f"subdomains: {getattr(self.ctx, 'subdomains', [])}")
            logger.debug(f"ips: {getattr(self.ctx, 'ips', [])}")
            
            ports = getattr(self.ctx, 'ports', [])
            if isinstance(ports, dict):
                logger.debug(f"ports keys: {ports.keys()}")
            else:
                logger.debug(f"ports is list, len: {len(ports)}")
            
            # ── Subdomains ──
            if hasattr(self.ctx, 'subdomains') and self.ctx.subdomains:
                from core.security.authorization import TargetScopeValidator
                _sv = TargetScopeValidator.get()
                for subdomain in self.ctx.subdomains:
                    self.persistent_knowledge_store.add_asset(
                        self.target_id, "subdomain", subdomain,
                        metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                    )
                    # Authorize the IPs each in-scope subdomain resolves to, so a
                    # follow-up scan of that IP is not blocked as out-of-scope.
                    try:
                        _sv.note_resolution(subdomain)
                    except Exception:
                        pass
                logger.info(f"  ✓ Persisted {len(self.ctx.subdomains)} subdomains")
            
            # ── IPs ──
            if hasattr(self.ctx, 'ips') and self.ctx.ips:
                from core.security.authorization import TargetScopeValidator
                scope_validator = TargetScopeValidator.get()
                for ip in self.ctx.ips:
                    scope_validator.add_target(ip)
                    self.persistent_knowledge_store.add_asset(
                        self.target_id, "ip", ip,
                        metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                    )
                logger.info(f"  ✓ Persisted {len(self.ctx.ips)} IPs (added to authorized scope)")
            
            # ── Ports - FIXED ──
            if hasattr(self.ctx, 'ports') and self.ctx.ports:
                ports = self.ctx.ports
                if isinstance(ports, dict):
                    for host, port_list in ports.items():
                        host_asset_id = self.persistent_knowledge_store.add_asset(
                            self.target_id, "host", host,
                            metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                        )
                        for port_item in port_list:
                            if isinstance(port_item, dict):
                                port_num = port_item.get("port", "unknown")
                                service = port_item.get("service", "unknown")
                                version = port_item.get("version", "")
                            else:
                                port_num = str(port_item)
                                service = "unknown"
                                version = ""
                            self.persistent_knowledge_store.add_technology(
                                host_asset_id, 
                                f"{service}:{port_num}", 
                                version,
                                source="port_scan"
                            )
                    logger.info(f"  ✓ Persisted ports for {len(ports)} hosts")
                else:
                    # In V2, it's just a list
                    host_asset_id = self.persistent_knowledge_store.add_asset(
                        self.target_id, "host", self.ctx.target,
                        metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                    )
                    for port_item in ports:
                        if isinstance(port_item, dict):
                            port_num = port_item.get("port", "unknown")
                            service = port_item.get("service", "unknown")
                            version = port_item.get("version", "")
                        else:
                            port_num = str(port_item)
                            service = "unknown"
                            version = ""
                        self.persistent_knowledge_store.add_technology(
                            host_asset_id, 
                            f"{service}:{port_num}", 
                            version,
                            source="port_scan"
                        )
                    logger.info(f"  ✓ Persisted {len(ports)} ports for target")
            
            # ── Technologies ──
            if hasattr(self.ctx, 'technologies') and self.ctx.technologies:
                for host, techs in self.ctx.technologies.items():
                    if isinstance(techs, bool) or techs is None:
                        techs = [host] if isinstance(host, str) else []
                    elif isinstance(techs, str):
                        techs = [techs]
                    elif not isinstance(techs, list):
                        continue
                    host_asset_id = self.persistent_knowledge_store.add_asset(
                        self.target_id, "host", host
                    )
                    for tech in techs:
                        if isinstance(tech, dict):
                            name = tech.get("name", "")
                            version = tech.get("version", "")
                        elif isinstance(tech, str):
                            name = str(tech)
                            version = ""
                        else:
                            continue
                        if name:
                            self.persistent_knowledge_store.add_technology(
                                host_asset_id, name, version,
                                source="web_fingerprint"
                            )
                logger.info(f"  ✓ Persisted technologies for {len(self.ctx.technologies)} hosts")
            
            # ── Endpoints ──
            # P3: read endpoint RECORDS via the canonical getter. Iterating
            # ``self.ctx.endpoints`` directly yields the dict's canonical-id KEYS
            # (e.g. "GET:https://h/x"), which were being persisted as paths.
            _eps = (self.ctx.get_endpoints() if hasattr(self.ctx, 'get_endpoints')
                    else list(getattr(self.ctx, 'endpoints', []) or []))
            if _eps:
                for endpoint in _eps:
                    if isinstance(endpoint, dict):
                        path = endpoint.get("url", "")
                        method = endpoint.get("method", "GET")
                        status = endpoint.get("status", 0)
                        params = endpoint.get("params", [])
                    elif isinstance(endpoint, str):
                        path = endpoint
                        method = "GET"
                        status = 0
                        params = []
                    else:
                        continue
                    
                    if path:
                        self.persistent_knowledge_store.add_endpoint(
                            target_id=self.target_id,
                            path=path,
                            http_method=method,
                            status_code=status,
                            metadata=json.dumps({
                                "params": params,
                                "discovered_at": datetime.now().isoformat()
                            })
                        )
                logger.info(f"  ✓ Persisted {len(_eps)} endpoints")
            
            # ── Missing Security Headers → Vulnerability Findings ──
            profile = getattr(self.ctx, 'target_profile', None) or {}
            if isinstance(profile, dict):
                sec_headers = profile.get("security_headers", {})
            else:
                sec_headers = getattr(profile, 'security_headers', {}) or {}
            important_headers = {
                "X-Frame-Options": ("Missing X-Frame-Options header", "Clickjacking protection not enabled — site can be framed by malicious pages"),
                "Content-Security-Policy": ("Missing Content-Security-Policy header", "No CSP policy — increased XSS risk"),
                "Strict-Transport-Security": ("Missing HSTS header", "HSTS not enforced — vulnerable to SSL stripping"),
                "X-Content-Type-Options": ("Missing X-Content-Type-Options header", "MIME sniffing protection not enabled"),
            }
            present_lower = {k.lower() for k in (sec_headers or {})}
            header_findings = 0
            for hdr, (title, detail) in important_headers.items():
                if hdr.lower() not in present_lower:
                    vuln = {
                        "type": "MISSING_HEADER",
                        "title": title,
                        "severity": "LOW",
                        "target": self.ctx.target,
                        "location": self.ctx.target,
                        "proof": f"HTTP response missing {hdr} header",
                        "details": detail,
                        "tool": "profiler",
                    }
                    if hasattr(self.ctx, 'add_vulnerability'):
                        self.ctx.add_vulnerability(vuln)
                        header_findings += 1
            if header_findings:
                logger.info(f"  ✓ Added {header_findings} missing security header findings")

            # ── Summary ──
            logger.info(f"Persisted: {len(getattr(self.ctx, 'subdomains', []))} subdomains, "
                        f"{len(getattr(self.ctx, 'ips', []))} IPs, "
                        f"{len(getattr(self.ctx, 'ports', {}))} hosts with ports, "
                        f"{len(getattr(self.ctx, 'endpoints', []))} endpoints")

            # ── V2: Feed recon into canonical AttackSurfaceState ──
            self._feed_recon_to_attack_surface_state()

        except Exception as e:
            logger.error(f"Failed to persist recon findings: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    async def _persist_captured_requests(self):
        """Save captured HTTP requests to disk for replay."""
        try:
            if not self.ctx.captured_requests:
                logger.debug("No captured requests to persist")
                return

            logger.info("Persisting captured HTTP requests...")
            self.report_dir.mkdir(parents=True, exist_ok=True)
            request_file = self.report_dir / f"captured_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(request_file, 'w') as f:
                json.dump({
                    "target": self.ctx.target,
                    "captured_at": datetime.now().isoformat(),
                    "pages": self.ctx.crawled_pages,
                    "requests": self.ctx.captured_requests,
                }, f, indent=2)
            logger.info(f"Saved {len(self.ctx.captured_requests)} requests to {request_file}")
        except Exception as e:
            logger.error(f"Failed to persist captured requests: {e}")

    async def _llm_probe_finding_sweep(self):
        """LLM safety-net: review exploit-intent probes the deterministic oracle
        did not classify, and materialize any missed vulnerabilities before
        persistence. Ensures ambiguous-but-real findings still reach the DB.
        """
        obs = getattr(self.ctx, "probe_observations", None) or []
        if not obs:
            return
        llm = getattr(self, "llm", None)
        if llm is None or not hasattr(llm, "generate_json"):
            return

        # Token savers:
        #  1) never re-review a probe already sent to the LLM (per-scan cursor);
        #  2) drop clearly-blocked/absent responses (401/403/404/405/429/400) —
        #     those are non-findings, so they never need an LLM call;
        #  3) collapse repeated attempts to the same (method, path, status).
        seen = getattr(self.ctx, "_probe_sweep_seen", None)
        if seen is None:
            seen = set()
            setattr(self.ctx, "_probe_sweep_seen", seen)
        known = {(v.get("location") or v.get("target") or "").split("?")[0].lower()
                 for v in self.ctx.vulnerabilities}
        _blocked = {400, 401, 403, 404, 405, 429}
        pending, batch_sigs = [], []
        for o in obs:
            url = o.get("url", "")
            path = url.split("?")[0].lower()
            status = int(o.get("status") or 0)
            sig = f"{o.get('method')}|{path}|{status}"
            if sig in seen or path in known or status in _blocked or status == 0:
                continue
            seen.add(sig)
            pending.append(o)
            if len(pending) >= 40:
                break
        if not pending:
            return
        import json as _json
        prompt = (
            "You are triaging HTTP exploit probes from a pentest of an authorized "
            "target. For EACH probe decide if the response proves a real, reportable "
            "web vulnerability (auth bypass, IDOR/BOLA, injection, XSS, SSRF, access "
            "control, info disclosure, etc.). Ignore failed/blocked probes and pure "
            "recon. Return STRICT JSON: {\"findings\":[{\"index\":<int>,\"title\":str,"
            "\"type\":str,\"severity\":\"CRITICAL|HIGH|MEDIUM|LOW\",\"cwe\":str,"
            "\"rationale\":str}]}. Only include probes that are genuinely vulnerable.\n\n"
            "PROBES:\n" + _json.dumps(
                [{"index": i, "method": o.get("method"), "url": o.get("url"),
                  "status": o.get("status"), "hypothesis": o.get("hypothesis"),
                  "body_snippet": o.get("body_snippet", "")[:300]}
                 for i, o in enumerate(pending)], default=str)[:12000]
        )
        try:
            resp = await llm.generate_json(prompt, max_tokens=1500)
        except Exception as e:
            logger.warning(f"[ProbeSweep] LLM review skipped: {e}")
            return
        findings = (resp or {}).get("findings", []) if isinstance(resp, dict) else []
        added = 0
        for f in findings:
            try:
                idx = int(f.get("index", -1))
                if not (0 <= idx < len(pending)):
                    continue
                o = pending[idx]
                self.ctx.add_vulnerability({
                    "type": (f.get("type") or "LLM_TRIAGE").upper().replace(" ", "_"),
                    "title": f.get("title") or f"Probe finding: {o.get('url')}",
                    "severity": (f.get("severity") or "MEDIUM").upper(),
                    "target": o.get("url"), "location": o.get("url"),
                    "details": (f.get("rationale") or "") +
                               f" [probe: {o.get('method')} {o.get('url')} -> HTTP {o.get('status')}]",
                    "proof": f"{o.get('method')} {o.get('url')} -> HTTP {o.get('status')}",
                    "hypothesis": o.get("hypothesis", ""),
                    "cwe": f.get("cwe", ""), "tool": "custom_probe+llm_triage",
                    "confirmed": False, "status": "CANDIDATE",
                })
                added += 1
            except Exception:
                continue
        if added:
            logger.info(f"[ProbeSweep] LLM triage recovered {added} missed finding(s) from {len(pending)} probes")

    async def _persist_vulnerabilities(self):
        """Save vulnerability findings to knowledge store."""
        try:
            # LLM safety-net over unclassified probes before we persist.
            try:
                await self._llm_probe_finding_sweep()
            except Exception as e:
                logger.warning(f"[ProbeSweep] skipped: {e}")

            if not self.ctx.vulnerabilities:
                logger.debug("No vulnerabilities to persist")
                return

            logger.info("Persisting vulnerability findings...")
            for vuln in self.ctx.vulnerabilities:
                finding_id = self.persistent_knowledge_store.add_finding(
                    target_id=self.target_id,
                    title=vuln.get("title", "Unknown"),
                    description=vuln.get("details", ""),
                    severity=vuln.get("severity", "MEDIUM"),
                    category=vuln.get("type", ""),
                    cwe=vuln.get("cwe", ""),
                    cve=vuln.get("cve", ""),
                    affected_asset=vuln.get("location", ""),
                    evidence=json.dumps(vuln.get("proof", {})),
                    source_agent_id=vuln.get("source_agent", ""),
                )
                # Add evidence
                for evidence_item in vuln.get("evidence", []):
                    if isinstance(evidence_item, dict):
                        self.persistent_knowledge_store.add_evidence(
                            finding_id,
                            evidence_type=evidence_item.get("type", "screenshot"),
                            content=evidence_item.get("content", ""),
                            tool_name=evidence_item.get("tool", "")
                        )
            
            logger.info(f"Persisted {len(self.ctx.vulnerabilities)} vulnerabilities")
        except Exception as e:
            logger.error(f"Failed to persist vulnerabilities: {e}")

    async def _persist_exploit_results(self):
        """Save exploitation results to knowledge store."""
        try:
            if not self.ctx.exploit_results:
                logger.debug("No exploit results to persist")
                return
            
            logger.info("Persisting exploit results...")
            for result in self.ctx.exploit_results:
                self.persistent_knowledge_store.add_exploit_result(
                    target_id=self.target_id,
                    vuln_id=result.get("vuln_id", ""),
                    exploit_id=result.get("exploit_id", ""),
                    payload=result.get("payload", ""),
                    success=result.get("success", False),
                    proof=result.get("proof", ""),
                    severity=result.get("severity", "MEDIUM"),
                    executed_at=result.get("timestamp", datetime.now().isoformat()),
                )
            
            logger.info(f"Persisted {len(self.ctx.exploit_results)} exploitation results")

            # Record experience for learning
            for result in self.ctx.exploit_results:
                strategy = result.get("strategy", result.get("vuln_type", "unknown"))
                test_type = result.get("test_type", result.get("capability", "unknown"))
                if result.get("success"):
                    self.experience_learner.record_success(strategy, test_type, result)
                else:
                    self.experience_learner.record_failure(
                        strategy, test_type, result.get("error", "exploit_failed"))
            patterns = self.experience_learner.detect_patterns()
            if patterns:
                logger.info(f"[ExperienceLearner] Detected {len(patterns)} failure patterns")
                for p in patterns:
                    logger.info(f"  Pattern: {p}")

        except Exception as e:
            logger.error(f"Failed to persist exploit results: {e}")

    async def _persist_post_exploit_findings(self):
        """Save post-exploitation findings (privesc, lateral, persistence, MITRE)."""
        try:
            findings = []
            
            # Privesc findings
            for priv in self.ctx.privesc_findings:
                self.persistent_knowledge_store.add_post_exploit_finding(
                    target_id=self.target_id,
                    type="privesc",
                    host=priv.get("host", ""),
                    technique=priv.get("technique", ""),
                    detail=priv.get("detail", ""),
                    severity=priv.get("severity", "MEDIUM"),
                    metadata=json.dumps(priv)
                )
                findings.append(priv)
            
            # Lateral movement
            if self.ctx.lateral_plan:
                for pivot in self.ctx.lateral_plan.get("pivots", []):
                    self.persistent_knowledge_store.add_post_exploit_finding(
                        target_id=self.target_id,
                        type="lateral_movement",
                        host=pivot.get("source_host", ""),
                        technique=pivot.get("technique", ""),
                        detail=f"Move to {pivot.get('target_host', '')}",
                        metadata=json.dumps(pivot)
                    )
                    findings.append(pivot)
            
            # Persistence mechanisms
            for persist in self.ctx.persistence_plan:
                self.persistent_knowledge_store.add_post_exploit_finding(
                    target_id=self.target_id,
                    type="persistence",
                    technique=persist.get("mechanism", ""),
                    detail=persist.get("artifact", ""),
                    metadata=json.dumps(persist)
                )
                findings.append(persist)
            
            logger.info(f"Persisted {len(findings)} post-exploitation findings")
        except Exception as e:
            logger.error(f"Failed to persist post-exploit findings: {e}")


