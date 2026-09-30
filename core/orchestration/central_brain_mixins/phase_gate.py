from __future__ import annotations

from typing import Any, Dict


class PhaseGateMixin:
    """Derive a compact execution context from persisted task state and evaluate
    phase-completion gates (recon / analyze / exploit). Extracted from
    CentralBrain; pure reads of self.task_manager and self.ctx.
    """

    def _get_db_execution_context(self) -> Dict[str, Any]:
        completed_tasks = []
        for task in self.task_manager.get_all_tasks():
            if task.status.value in ("COMPLETED", "FAILED", "RUNNING"):
                target = task.spec.inputs.get("target") or task.spec.inputs.get("url") or task.spec.inputs.get("domain") or self.target
                tools = task.spec.inputs.get("tools", [])
                summary_finding = ""
                if task.result and isinstance(task.result, dict):
                    summary_finding = str(task.result.get("results") or task.result.get("reason") or "")[:150]
                completed_tasks.append([
                    task.spec.capability.value,
                    target,
                    ",".join(tools) if tools else "default",
                    task.status.value,
                    summary_finding
                ])

        # Pull discovered assets from persistent knowledge store or shared context
        subdomains = list(getattr(self.ctx, "subdomains", []))
        ips = list(getattr(self.ctx, "ips", []))
        ports = dict(getattr(self.ctx, "ports", {}))
        technologies = dict(getattr(self.ctx, "technologies", {}))

        return {
            "completed_tasks": completed_tasks[-10:],
            "discovered_assets": {
                "subdomains": subdomains[:10],
                "ips": ips[:10],
                "open_ports": ports,
                "technologies": technologies
            }
        }

    def _is_recon_complete(self, db_context: Dict[str, Any]) -> bool:
        return self._evaluate_phase_gate("recon", db_context)

    def _evaluate_phase_gate(self, phase: str, db_context: Dict[str, Any]) -> bool:
        completed = db_context.get("completed_tasks", [])
        p_lower = phase.lower().strip()

        # 1. Reconnaissance Phase Gate (recon, osint, deep_recon)
        if p_lower in ("recon", "osint_reconnaissance", "deep_reconnaissance"):
            if not completed:
                return False
            recon_caps = {"dns_enumeration", "port_scanning", "technology_fingerprinting", "tls_analysis", "subdomain_enumeration", "endpoint_discovery"}
            executed_recon = {f"{item[0]}:{item[1]}" for item in completed if item[0] in recon_caps}
            subdomains = db_context.get("discovered_assets", {}).get("subdomains", [])
            targets = set([self.target] + subdomains[:5])
            required_port_scans = {f"port_scanning:{t}" for t in targets}
            if required_port_scans.issubset(executed_recon) or len(executed_recon) >= 3:
                return True
            return False

        # 2. Vulnerability Assessment Phase Gate (analyze)
        elif p_lower in ("analyze", "vulnerability_assessment"):
            vuln_caps = {"vulnerability_scanning", "http_analysis", "javascript_analysis"}
            executed_vulns = [item for item in completed if item[0] in vuln_caps]
            if getattr(self.ctx, "vulnerabilities", []) or len(executed_vulns) >= 2:
                return True
            return False

        # 3. Exploitation Phase Gate (exploit)
        elif p_lower in ("exploit", "exploitation"):
            vulns = getattr(self.ctx, "vulnerabilities", [])
            if not vulns:
                return True
            exploit_results = getattr(self.ctx, "exploit_results", [])
            if len(exploit_results) >= len(vulns) or len(exploit_results) >= 3:
                return True
            return False

        return False
