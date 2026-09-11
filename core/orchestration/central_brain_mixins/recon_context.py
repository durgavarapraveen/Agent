from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


class ReconContextMixin:
    def _build_recon_context(self) -> dict:
        subs = list(getattr(self.ctx, "subdomains", []) or [])
        # Merge OSINT-discovered subdomains into the main list
        osint_subs = getattr(self.ctx, "discovered_subdomains", []) or []
        for s in osint_subs:
            name = s.name if hasattr(s, 'name') else str(s)
            if name and name not in subs:
                subs.append(name)
        # Merge discovered_domains too
        for s in (getattr(self.ctx, "discovered_domains", []) or []):
            name = str(s)
            if name and name not in subs:
                subs.append(name)

        sub_status = getattr(self.ctx, "subdomain_status", {}) or {}
        catalog = getattr(self.ctx, "endpoint_catalog", []) or []

        seen_hosts = set()
        subs_out = []
        for s in subs:
            host = s if isinstance(s, str) else (s.get("name") if isinstance(s, dict) else str(s))
            host_n = str(host).replace("https://", "").replace("http://", "").rstrip("/").lower()
            if host_n in seen_hosts:
                continue
            seen_hosts.add(host_n)
            st = sub_status.get(host_n, {})
            subs_out.append({
                "name": host_n,
                "live": bool(st.get("live")),
                "status": "live" if st.get("live") else ("dead" if st else "unknown"),
                "status_code": st.get("status_code", 0),
                "note": st.get("note", ""),
            })

        if not catalog:
            eps = getattr(self.ctx, "endpoints", {}) or {}
            ep_iter = eps.values() if isinstance(eps, dict) else eps
            for ep in ep_iter:
                url = getattr(ep, "url", None) or (ep.get("url") or ep.get("name") if isinstance(ep, dict) else None)
                if url:
                    catalog.append({"url": str(url), "path": str(url), "method": "GET",
                                    "host": "", "kind": "page"})

        caps = getattr(self.ctx, "captured_requests", []) or []
        caps_out = []
        for r in caps[:200]:
            caps_out.append({
                "url": getattr(r, "url", None) or (r.get("url") if isinstance(r, dict) else str(r)),
                "method": getattr(r, "method", None) or (r.get("method") if isinstance(r, dict) else "GET"),
                "resource_type": r.get("resource_type", "") if isinstance(r, dict) else "",
                "status": r.get("status", 0) if isinstance(r, dict) else 0,
                "is_preflight": r.get("is_preflight", False) if isinstance(r, dict) else False,
                "headers": r.get("headers", {}) if isinstance(r, dict) else {},
                "post_data": r.get("post_data", "") if isinstance(r, dict) else "",
            })

        tool_execs = getattr(self.ctx, "tool_executions", []) or []
        texecs_out = []
        for e in tool_execs[:200]:
            if isinstance(e, dict):
                texecs_out.append(e)

        return {
            "subdomains": subs_out,
            "endpoints": catalog,
            "technologies": getattr(self.ctx, "technologies", {}) or {},
            "captured_requests": caps_out,
            "tool_executions": texecs_out,
            "ports": getattr(self.ctx, "ports", []) or [],
            "ips": getattr(self.ctx, "ips", []) or [],
            "subdomain_summary": {
                "total": len(subs_out),
                "live": sum(1 for s in subs_out if s["live"]),
                "dead": sum(1 for s in subs_out if not s["live"]),
            },
            "osint": self._build_osint_context(),
            # Every other piece of recon intelligence, so nothing is lost.
            "ssl_info": getattr(self.ctx, "ssl_info", {}) or {},
            "headers": getattr(self.ctx, "headers", {}) or {},
            "directories": getattr(self.ctx, "directories", []) or [],
            "secrets": getattr(self.ctx, "secrets", []) or [],
            "crawled_pages": (getattr(self.ctx, "crawled_pages", []) or [])[:200],
            "dns_records": getattr(self.ctx, "dns_records", []) or [],
        }

    def _persist_recon_data(self):
        try:
            from core.database.pg_store import ReconRepo
            ReconRepo.save(self._scan_id, self.ctx.target, self._build_recon_context())
            logger.info("[Recon] Full recon intelligence persisted to database")
        except Exception as e:
            logger.warning(f"[Recon] recon_data persist failed (non-fatal): {e}")

    def _write_live_results(self):
        try:
            subs = getattr(self.ctx, "subdomains", []) or []
            eps = getattr(self.ctx, "endpoints", []) or []
            ports = getattr(self.ctx, "ports", []) or []
            sub_status = getattr(self.ctx, "subdomain_status", {}) or {}
            endpoint_catalog = getattr(self.ctx, "endpoint_catalog", []) or []
            ips = getattr(self.ctx, "ips", []) or []
            techs = getattr(self.ctx, "technologies", {}) or {}
            vulns = self.ctx.vulnerabilities or []
            exploits = self.ctx.exploit_results or []

            def _serialize(items):
                out = []
                for item in items:
                    if isinstance(item, dict):
                        out.append(item)
                    elif isinstance(item, str):
                        out.append({"name": item})
                    elif hasattr(item, "__dict__"):
                        out.append({k: v for k, v in item.__dict__.items() if not k.startswith("_")})
                    else:
                        out.append({"value": str(item)})
                return out

            captured = getattr(self.ctx, 'captured_requests', []) or []
            attack_chains = getattr(self.ctx, 'attack_chains', None) or {}

            recon_ctx = self._build_recon_context()
            recon_ctx["ports"] = _serialize(ports) if ports else recon_ctx.get("ports", [])
            recon_ctx["ips"] = _serialize(ips) if ips else recon_ctx.get("ips", [])
            if techs and isinstance(techs, dict):
                recon_ctx["technologies"] = techs
            results = {
                "recon": recon_ctx,
                "vulnerabilities": _serialize(vulns),
                "exploits": _serialize(exploits),
                "captured_requests": _serialize(captured[:100]),
                "attack_chains": attack_chains,
            }
            try:
                from core.database.pg_store import (LiveDataRepo, ReconRepo, VulnRepo,
                    ExploitResultRepo, AttackChainRepo, PostExploitRepo, ScanMetadataRepo)
                LiveDataRepo.upsert_results(self._scan_id, results)
                ReconRepo.save(self._scan_id, self.ctx.target, recon_ctx)
                if results.get("vulnerabilities"):
                    VulnRepo.bulk_insert(self._scan_id, results["vulnerabilities"])
                if results.get("exploits"):
                    ExploitResultRepo.bulk_insert(self._scan_id, results["exploits"])
                if attack_chains:
                    AttackChainRepo.bulk_upsert(self._scan_id, attack_chains if isinstance(attack_chains, list) else list(attack_chains.values()) if isinstance(attack_chains, dict) else [])
                privesc = getattr(self.ctx, 'privesc_findings', None)
                if privesc:
                    PostExploitRepo.bulk_upsert(self._scan_id, 'privesc', privesc)
                creds = getattr(self.ctx, 'harvested_creds', None)
                if creds:
                    PostExploitRepo.bulk_upsert(self._scan_id, 'credentials', creds)
                lateral = getattr(self.ctx, 'lateral_plan', None)
                if lateral:
                    PostExploitRepo.bulk_upsert(self._scan_id, 'lateral_movement', lateral if isinstance(lateral, list) else [lateral])
                persist_plan = getattr(self.ctx, 'persistence_plan', None)
                if persist_plan:
                    PostExploitRepo.bulk_upsert(self._scan_id, 'persistence', persist_plan if isinstance(persist_plan, list) else [persist_plan])
                mitre = getattr(self.ctx, 'mitre_mappings', None)
                if mitre:
                    ScanMetadataRepo.upsert(self._scan_id, 'mitre_mappings', mitre)
                agents = getattr(self.ctx, 'agents_spawned', None)
                if agents:
                    ScanMetadataRepo.upsert(self._scan_id, 'agents_spawned', agents)
            except Exception:
                pass
        except Exception:
            pass

