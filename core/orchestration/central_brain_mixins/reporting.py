from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict

from agents.llm_client import TaskTier
from core.compliance import ComplianceReporter
from core.exploitation.poc_generator import POCGenerator
from core.orchestration.automation import AutomationEngine
from core.reporting.coverage_report import CoverageReport
from core.security.consent import get_consent

logger = logging.getLogger(__name__)


class ReportingMixin:
    """Final report assembly, coverage report, and token usage.

    Extracted from CentralBrain; relies on shared attrs (self.ctx, self.llm,
    self.reporter, self.metrics, self.automation, self._scan_id, ...) supplied
    by the composing class.
    """

    def _generate_coverage_report(self) -> str:
        cat_map = {}
        for t in self.test_catalog_v2.list_all():
            cat_map[t.test_id] = t.attack_type
        report = CoverageReport(
            coverage_matrix=self.coverage_matrix,
            finding_store=self.finding_store_v2,
            knowledge_graph=self.knowledge_graph,
            test_category_map=cat_map,
        )
        return report.generate()

    def _build_understanding_report(self, understanding, plan) -> Dict[str, Any]:
        """Structured report of what the model understood + what the plan requires."""
        u = understanding
        rel = plan.relevant_families() if plan else []
        items = [it for it in (plan.ordered() if plan else []) if it.relevant]
        return {
            "domain": getattr(u, "business_domain", "generic"),
            "domain_confidence": round(float(getattr(u, "domain_confidence", 0.0) or 0.0), 2),
            "source": getattr(u, "source", ""),
            "business_rules": list(getattr(u, "business_rules", []) or [])[:20],
            "data_sensitivity": dict(getattr(u, "data_sensitivity", {}) or {}),
            "roles": list(getattr(u, "roles", []) or [])[:20],
            "entities": list(getattr(u, "entities", []) or [])[:20],
            "security_invariants": list(getattr(u, "security_invariants", []) or [])[:20],
            "trust_boundaries": list(getattr(u, "trust_boundaries", []) or [])[:20],
            "threat_model": plan.threat_model if plan else {},
            # "what is required": the prioritized test plan.
            "required_testing": [
                {"family": it.family.value, "priority": it.priority, "why": it.rationale}
                for it in items
            ],
            "relevant_families": [f.value for f in rel],
            "skipped_families": [f.value for f in (plan.skipped_families() if plan else [])],
        }

    async def _generate_report(self):
        # D-1: attach a concrete remediation plan (root cause, fix, optional code
        # patch, verification, references) to every confirmed/high finding BEFORE
        # the report is assembled and persisted, so each reported vuln ships with
        # an actionable fix — the brief's "then fix them". Runs after the critic
        # so only surviving findings are planned. Bounded LLM spend with a
        # deterministic per-class fallback; non-destructive (guidance only, never
        # applies a patch).
        try:
            from core.remediation import get_fix_planner
            _src = os.getenv("ANTIGRAVITY_SOURCE_SNIPPET", "") or ""
            await get_fix_planner(self.llm).enrich(
                list(getattr(self.ctx, "vulnerabilities", []) or []),
                ctx=self.ctx, source_snippet=_src)
        except Exception as _e:
            logger.warning(f"[FixPlanner] remediation enrichment skipped (non-fatal): {_e}")

        # Attack-chain intelligence: compose distinct exploitation paths from
        # the scan artefacts (SQLi→dump→crack→login→IDOR chains, etc.)
        try:
            from core.reporting.chain_intelligence import synthesize_chains
            await synthesize_chains(self._scan_id)
        except Exception as _e:
            logger.warning(f"[ChainIntel] synthesis failed (non-fatal): {_e}")

        # Benchmark scoring (opt-in) — generic across benchmarks/targets: build a
        # corpus (live challenge API → checklist over the attack surface → static)
        # and score findings per-challenge into benchmark_results + the blackboard.
        if os.getenv("NEO_BENCHMARK", "0").strip() == "1":
            try:
                from core.benchmark.runner import generate_corpus, score_corpus
                _tgt = getattr(self.ctx, "target", "") or "target"
                suite = os.getenv("NEO_BENCHMARK_SUITE", "") or (
                    _tgt.split("://")[-1].split("/")[0].split(":")[0] or "target")
                corpus = generate_corpus(getattr(self.ctx, "target", ""), suite,
                                         scan_id=self._scan_id, ctx=self.ctx)
                if corpus.challenges:
                    score_corpus(self._scan_id, corpus,
                                 list(self.ctx.vulnerabilities or []), ctx=self.ctx)
            except Exception as _e:
                logger.warning(f"[Benchmark] scoring failed (non-fatal): {_e}")

        """LLM generates final report.

        Token-savings: prefer the LLM's OWN phase-by-phase summaries recorded
        during the scan (scan_llm_memory) over dumping raw context. Uses the
        SMALL tier because this is prose summarisation, not reasoning — the
        LARGE reasoning-model tier tripled cost with no quality gain.
        """
        # 1. Reuse recorded per-phase summaries the scan-time LLM produced
        try:
            from core.database.pg_store import LLMMemoryRepo
            mem_rows = LLMMemoryRepo.get_by_scan(self._scan_id, kind="summary", limit=30)
        except Exception:
            mem_rows = []
        if mem_rows:
            memory_txt = "\n\n".join(f"### {m.get('phase','phase')}\n{(m.get('content') or '').strip()}"
                                       for m in mem_rows if (m.get("content") or "").strip())
        else:
            memory_txt = ""
        # 2. Compact fact snapshot — just counts + top vuln titles (no full details)
        v_list = self.ctx.vulnerabilities or []
        sev_counts: Dict[str, int] = {}
        for v in v_list:
            s = (v.get("severity") or "INFO").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        top_vulns = [v.get("title", "") for v in v_list
                     if (v.get("severity") or "").upper() in ("CRITICAL", "HIGH")][:15]
        fact_snapshot = {
            "target": self.ctx.target,
            "severity_counts": sev_counts,
            "top_high_critical": top_vulns,
            "attack_chains_count": len(self.ctx.attack_chains or []),
            "exploit_results_count": len(self.ctx.exploit_results or []),
            "harvested_creds_count": len(self.ctx.harvested_creds or []),
        }
        # 3. SMALL tier — this is summarisation, not reasoning
        exec_summary = await self.llm.generate_response(
            "Write a 3-paragraph professional executive summary for this pentest. "
            "Cover: overall risk posture, key finding categories, recommendations. "
            "Use the scan-time analyst notes as your primary source; the fact "
            "snapshot is only for citing exact counts.\n\n"
            f"SCAN-TIME ANALYST NOTES:\n{memory_txt or '(no phase summaries recorded)'}\n\n"
            f"FACT SNAPSHOT: {json.dumps(fact_snapshot, default=str)}\n\n"
            "Be concise (3 paragraphs max, ~250 words total).",
            tier=TaskTier.SMALL,
            max_tokens=800,
        )
        # generate_response() returns a NormalizedLLMResponse, but the JSON report
        # and self.reporter.generate() expect a plain string — passing the object
        # crashed the enterprise report with "'NormalizedLLMResponse' object has no
        # attribute 'replace'" (implemented.md §9.4). Extract .content.
        exec_summary = getattr(exec_summary, "content", exec_summary)
        if not isinstance(exec_summary, str):
            exec_summary = str(exec_summary or "")

        # ── Finding validation + compliance mapping (production-grade layer) ──
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        validated = self._validate_findings(ts)
        frameworks = self._active_frameworks()
        try:
            compliance_summary = ComplianceReporter(frameworks).build(
                self.ctx.vulnerabilities)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[report] compliance mapping failed: {e}")
            compliance_summary = {"active_frameworks": frameworks, "error": str(e)}

        # Build report
        report = {
            "metadata": {
                "title": f"Penetration Test Report - {self.ctx.target}",
                "target": self.ctx.target,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "agents_used": len(self.ctx.agents_spawned),
                "token_usage": self._get_token_usage(),
            },
            "executive_summary": exec_summary,
            "scope": self.ctx.scope,
            "context": self._build_recon_context(),
            "vulnerabilities": validated["reported"],
            "vulnerabilities_all": self.ctx.vulnerabilities,
            "needs_review": validated["needs_review"],
            "dedup": validated["dedup"],
            "compliance": compliance_summary,
            "attack_chains": self.ctx.attack_chains,
            "exploit_results": self.ctx.exploit_results,
            "post_exploitation": (
                self.post_exploit.to_dict() if self.post_exploit else {
                    "privesc_findings": self.ctx.privesc_findings,
                    "harvested_creds": self.ctx.harvested_creds,
                    "lateral_plan": self.ctx.lateral_plan,
                    "persistence_plan": self.ctx.persistence_plan,
                    "mitre_mappings": self.ctx.mitre_mappings,
                }
            ),
            "technical_data": {
                "subdomains": self.ctx.subdomains,
                "ips": self.ctx.ips,
                "ports": self.ctx.ports,
                "technologies": self.ctx.technologies,
                "endpoints": self.ctx.endpoints,
                "directories": self.ctx.directories,
                "headers": self.ctx.headers,
                "ssl_info": self.ctx.ssl_info,
                "secrets": self.ctx.secrets,
                "crawled_pages": self.ctx.crawled_pages,
                "captured_requests": self.ctx.captured_requests,
            },
            "automation": self.automation.to_dict(),
            "exploit_consent": get_consent().summary(),
            "remediation": self.automation.remediation_report(),
            "metrics": self.metrics.snapshot(),
            "scheduled_scan": AutomationEngine.schedule_config(self.ctx.target),
            "brain_log": self.ctx.brain_log,
            "agents": self.ctx.agents_spawned,
        }

        # P2: Coverage & Confidence section — blind spots (what was NOT tested),
        # unified coverage %, and capability-based attack-chain reasoning. Makes
        # the report state its own confidence instead of implying completeness.
        try:
            from core.coverage.unified_coverage import UnifiedCoverage
            cov = UnifiedCoverage.from_brain(self).summary()
        except Exception:
            cov = {}
        chains = []
        try:
            from core.exploitation.chain_reasoner import ChainReasoner
            vulns = list(getattr(self.ctx, "vulnerabilities", []) or [])
            if vulns:
                chains = [c.to_dict() for c in ChainReasoner().analyze(vulns)]
        except Exception:
            chains = []
        report["coverage_confidence"] = {
            "coverage": cov,
            "blind_spots": getattr(self.ctx, "blind_spots", {}) or {},
            "attack_chains_reasoned": chains,
            "note": "Findings reflect executed tests only; see blind_spots for untested surface.",
        }

        # Generate automated exploit POC reproduction scripts (Python, cURL, Markdown).
        # PoCs persist to Postgres (scan_artifacts) so the UI can render them; disk
        # writes only happen when REPORTS_ENABLED=1.
        try:
            # Ensure the shared_context knows its scan_id so POCGenerator can persist to DB
            try:
                self.ctx.scan_id = getattr(self, "_scan_id", None) or getattr(self.ctx, "scan_id", None)
            except Exception:
                pass
            from core.common.reports_config import reports_enabled as _re
            poc_files = POCGenerator.generate(self.ctx,
                                              output_dir=str(self.report_dir) if _re() else None)
            if poc_files:
                report["poc_artifacts"] = poc_files
                logger.info(f"POC reproduction scripts generated: {poc_files}")
        except Exception as pe:
            logger.warning(f"POC generation failed (non-fatal): {pe}")

        # Coverage ledger into the persisted report so finished scans keep the
        # "what was tested vs UNKNOWN" picture (§23/§24) for the UI.
        try:
            _oos = []
            try:
                from core.security.authorization import TargetScopeValidator
                _oos = TargetScopeValidator.get().discovered_out_of_scope()
            except Exception:
                pass
            report["coverage"] = {
                "ledger": getattr(self.ctx, "coverage_ledger", {}) or {},
                "surface": getattr(self.ctx, "surface_coverage", {}) or {},
                "discovered_out_of_scope": _oos,
                "dom_sinks": getattr(self.ctx, "dom_sinks", {}) or {},
                # Coverage-vs-plan: what the Test Plan scoped in and what it skipped
                # (skipped ≠ tested-clean — UNKNOWN≠CLEAN).
                "engagement_plan": getattr(self.ctx, "engagement_plan", {}) or {},
                "plan_skipped_families": getattr(self.ctx, "plan_skipped_families", []) or [],
            }
            # Threat model = Phase 1 deliverable.
            report["threat_model"] = getattr(self.ctx, "threat_model", {}) or {}
        except Exception:
            pass

        # Save  (ts computed above, shared with the validation/dedup scan_id)
        report_path = self.report_dir / f"pentest_{ts}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"Report saved: {report_path}")

        # Persist to PostgreSQL under the canonical run id (never the wall-clock
        # timestamp) so this run's rows are isolated from every other run.
        try:
            from core.database.pg_store import ScanRepo, VulnRepo
            run_id = self._scan_id
            ScanRepo.create(run_id, self.ctx.target, self.tier)
            ScanRepo.save_report(run_id, report)
            VulnRepo.bulk_insert(run_id, list(self.ctx.vulnerabilities))
        except Exception as pg_err:
            logger.warning(f"[report] PG persist failed (non-fatal): {pg_err}")

        # Enterprise HTML/PDF report + final dashboard
        try:
            self.reporter.active_frameworks = frameworks
            paths = self.reporter.generate(executive_summary=exec_summary,
                                           stem=f"pentest_{ts}")
            logger.info(f"Enterprise report: {paths.get('html')}"
                        + (f" | {paths['pdf']}" if paths.get("pdf") else ""))
            self.metrics.write_dashboard()
        except Exception as e:      # noqa: BLE001
            logger.error(f"Enterprise report generation failed: {e}")

        # Save shared context as backup
        ctx_path = self.report_dir / f"context_{ts}.json"
        self.ctx.save(str(ctx_path))
        logger.info(f"Context saved: {ctx_path}")

    def _get_token_usage(self) -> Dict[str, Any]:
        try:
            from agents.llm_harness_adapter import get_llm
            harness = get_llm()
            if harness and hasattr(harness, "budget"):
                stats = harness.budget.stats()
                total_input = sum(r.input_tokens for r in harness.budget.requests)
                total_output = sum(r.output_tokens for r in harness.budget.requests)
                stats["input_tokens"] = total_input
                stats["output_tokens"] = total_output
                return stats
        except Exception:
            pass
        return {}

