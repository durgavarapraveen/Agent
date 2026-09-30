from __future__ import annotations

import logging

from core.coverage.coverage_matrix import CoverageState
from core.domain.experiment import SecurityExperiment
from core.recovery.recovery_policy import RetryAction

logger = logging.getLogger(__name__)


class AdvancedEngineSyncMixin:
    """Sync recon/scanning/exploit artifacts into the advanced engines
    (ApplicationModel, MultiChannelDiscovery, SemanticInference,
    SpecialistTeam, coverage matrix). Extracted from CentralBrain; all
    dependencies are self attrs or method-local imports.
    """

    def _sync_recon_to_advanced_engines(self):
        """Synchronizes RECON artifacts to ApplicationModel, MultiChannelDiscovery, SemanticInference, and SpecialistTeam."""
        # 1. Application Model
        try:
            if hasattr(self, "application_model") and self.application_model:
                self.application_model.hydrate_from_shared_context(self.ctx)
                logger.info(f"[ApplicationModel] Hydrated from context: {len(self.application_model.endpoints)} endpoints, {len(self.application_model.hosts)} hosts")
        except Exception as _ame:
            logger.debug(f"[ApplicationModel] Hydration skipped: {_ame}")

        # 2. Multi-Channel Discovery
        try:
            if hasattr(self, "multi_channel_discovery") and self.multi_channel_discovery:
                from core.discovery.multi_channel import DiscoveredAsset, DiscoverySource
                synced_count = 0
                for ep in (self.ctx.endpoints or []):
                    ep_url = ep.get("url") if isinstance(ep, dict) else getattr(ep, "url", str(ep))
                    ep_method = ep.get("method", "GET") if isinstance(ep, dict) else getattr(ep, "method", "GET")
                    if ep_url:
                        self.multi_channel_discovery.add_asset(DiscoveredAsset(
                            url=ep_url, method=ep_method, source=DiscoverySource.CRAWL
                        ))
                        synced_count += 1
                if synced_count:
                    logger.info(f"[MultiChannelDiscovery] Ingested {synced_count} assets")
        except Exception as _mde:
            logger.debug(f"[MultiChannelDiscovery] Ingestion skipped: {_mde}")

        # 3. Semantic Inference Engine
        try:
            if hasattr(self, "semantic_inference") and self.semantic_inference:
                inferred = 0
                for ep in (self.ctx.endpoints or [])[:50]:
                    ep_dict = ep if isinstance(ep, dict) else {"url": getattr(ep, "url", str(ep))}
                    inf = self.semantic_inference.infer_endpoint(ep_dict)
                    if inf and inf.inferred_type != "unknown":
                        inferred += 1
                        ep_dict["semantic_type"] = inf.inferred_type
                        ep_dict["semantic_confidence"] = inf.confidence
                if inferred:
                    logger.info(f"[SemanticInference] Inferred semantic types for {inferred} endpoints")
        except Exception as _sie:
            logger.debug(f"[SemanticInference] Inference skipped: {_sie}")

        # 4. Source Intelligence Graph
        try:
            if hasattr(self, "source_intelligence") and self.source_intelligence:
                for jep in (getattr(self.ctx, "js_endpoints", []) or []):
                    jurl = jep if isinstance(jep, str) else jep.get("url", "")
                    if jurl:
                        self.source_intelligence.add_node("endpoint", jurl)
        except Exception as _sige:
            logger.debug(f"[SourceIntelligence] Node addition skipped: {_sige}")

        # 5. Specialist Team Evidence Bus
        try:
            if hasattr(self, "specialist_team") and self.specialist_team:
                from core.orchestration.specialist_agents import EvidenceArtifact, SpecialistRole
                self.specialist_team.bus.publish(EvidenceArtifact(
                    producer_role=SpecialistRole.RECON,
                    artifact_type="recon_inventory",
                    data={
                        "subdomains": len(self.ctx.subdomains),
                        "endpoints": len(self.ctx.endpoints),
                        "ports": len(getattr(self.ctx, "ports", [])),
                    },
                    provenance="recon_phase"
                ))
                logger.info("[SpecialistTeam] Posted RECON inventory artifact to evidence bus")
        except Exception as _ste:
            logger.debug(f"[SpecialistTeam] Posting skipped: {_ste}")

        # 6. Phase 1.5: Business-domain app understanding + test hypotheses.
        # Try async LLM path first for richer inference; fall back to heuristic.
        try:
            if hasattr(self, "app_understanding") and self.app_understanding:
                from core.intelligence.app_understanding import AppSignals
                signals = AppSignals.from_context(self.ctx)
                try:
                    import asyncio as _aio
                    loop = _aio.get_event_loop()
                    if loop.is_running():
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor(1) as pool:
                            understanding = pool.submit(
                                _aio.run, self.app_understanding.analyze(signals)
                            ).result(timeout=30)
                    else:
                        understanding = loop.run_until_complete(
                            self.app_understanding.analyze(signals))
                except Exception:
                    understanding = self.app_understanding.heuristic(signals)
                specs = self.app_understanding.to_test_specs(
                    understanding, base_endpoints=signals.endpoints[:50])
                self.ctx.app_understanding = understanding.to_dict()
                self.ctx.business_test_specs = specs
                self._app_understanding = understanding
                self.app_understanding.populate_app_model(understanding)
                logger.info(
                    f"[AppUnderstanding] domain={understanding.business_domain} "
                    f"(conf={understanding.domain_confidence:.2f}, src={understanding.source}), "
                    f"{len(specs)} business-logic test specs, "
                    f"{len(understanding.entities)} entities, "
                    f"{len(understanding.security_invariants)} invariants")
        except Exception as _aue:
            logger.debug(f"[AppUnderstanding] skipped: {_aue}")

        # 6b. Phase 1.2: build workflow state machines + negative test cases from
        # captured multi-step flows (guarded; empty when nothing was captured).
        try:
            captured = getattr(self.ctx, "captured_requests", None) or getattr(self.ctx, "endpoints", None)
            if captured:
                from core.discovery.workflow_crawler import WorkflowCrawler
                crawler = WorkflowCrawler()
                sm = crawler.build_from_requests(captured if isinstance(captured, list) else [])
                if len(sm.steps) >= 2:
                    self.ctx.workflow_test_cases = [c.__dict__ for c in crawler.generate_test_cases(sm)]
                    logger.info("[WorkflowCrawler] %d workflow test case(s) generated",
                                len(self.ctx.workflow_test_cases))
        except Exception as _wce:
            logger.debug(f"[WorkflowCrawler] skipped: {_wce}")

        # 6c. P1-19: domain-aware workflow generation + negative testing.
        # Uses inferred domain model (entities, state transitions) to build
        # multi-step browser workflows, execute them, and run negative test
        # cases (skip-step, reorder, replay, direct-access) for biz-logic bugs.
        try:
            understanding = getattr(self, "_app_understanding", None)
            captured = getattr(self.ctx, "captured_requests", None)
            if understanding or captured:
                from core.workflows.workflow_generator import WorkflowGenerator
                from core.workflows.workflow_executor import WorkflowExecutor

                creds = {}
                if hasattr(self.ctx, "harvested_creds") and self.ctx.harvested_creds:
                    c = self.ctx.harvested_creds[0] if isinstance(self.ctx.harvested_creds, list) else {}
                    creds = {"username": c.get("username", ""), "password": c.get("password", "")}

                gen = WorkflowGenerator(
                    target_url=str(self.ctx.target),
                    understanding=understanding,
                    captured_requests=captured if isinstance(captured, list) else [],
                    credentials=creds,
                )
                workflows = gen.generate_all()
                if workflows:
                    executor = WorkflowExecutor(
                        target_url=str(self.ctx.target),
                        scan_id=getattr(self.ctx, "_scan_id", "") or getattr(self.ctx, "scan_id", ""),
                    )
                    import asyncio as _aio2
                    _coro = executor.execute_all(workflows, captured if isinstance(captured, list) else [])
                    try:
                        _loop2 = _aio2.get_event_loop()
                        if _loop2.is_running():
                            import concurrent.futures as _cf2
                            with _cf2.ThreadPoolExecutor(1) as _pool2:
                                wf_results = _pool2.submit(_aio2.run, _coro).result(timeout=120)
                        else:
                            wf_results = _loop2.run_until_complete(_coro)
                    except Exception:
                        wf_results = _aio2.run(_coro)
                    biz_findings = []
                    for wr in wf_results:
                        biz_findings.extend(wr.findings)
                    if biz_findings:
                        for f in biz_findings:
                            self.ctx.vulnerabilities.append(f)
                        logger.info("[P1-19] %d business-logic finding(s) from %d workflow(s)",
                                    len(biz_findings), len(workflows))
                    else:
                        logger.info("[P1-19] %d workflow(s) executed, no business-logic issues found",
                                    len(workflows))
        except Exception as _wfe:
            logger.debug(f"[P1-19 WorkflowExecutor] skipped: {_wfe}")

        # 7. Phase 6.2: incremental scanning. When ANTIGRAVITY_INCREMENTAL=1 and a
        # saved baseline exists, narrow ctx.endpoints to the new/changed ones.
        # Conservative: only prunes when the result is non-empty — otherwise the
        # full endpoint set is kept (never turns a scan into a no-op).
        try:
            import os as _os
            if _os.getenv("ANTIGRAVITY_INCREMENTAL") == "1":
                from core.monitoring.incremental import IncrementalScanner
                scanner = IncrementalScanner()
                plan = scanner.plan(getattr(self, "target", ""), self.ctx, incremental=True)
                if not plan.full_scan and plan.endpoints_to_scan:
                    kept = IncrementalScanner.filter_endpoints(self.ctx.endpoints or [], plan)
                    if kept:
                        logger.info("[Incremental] re-scanning %d changed/new endpoint(s) "
                                    "(was %d).", len(kept), len(self.ctx.endpoints or []))
                        self.ctx.endpoints = kept
                elif not plan.full_scan and not plan.endpoints_to_scan:
                    logger.info("[Incremental] attack surface unchanged since baseline.")
        except Exception as _ie:
            logger.debug(f"[Incremental] skipped: {_ie}")

    def _sync_scanning_to_advanced_engines(self):
        """Synchronizes ACTIVE_SCANNING results to ResourceGovernor, DifferentialEngine, AnomalyPipeline, and SpecialistTeam."""
        # 1. Resource Governor
        try:
            if hasattr(self, "resource_governor") and self.resource_governor:
                from core.orchestration.resource_governor import ResourceType, QuotaLevel
                self.resource_governor.set_quota(
                    ResourceType.HTTP_REQUESTS, QuotaLevel.SCAN, self._scan_id, limit=5000.0
                )
                self.resource_governor.set_quota(
                    ResourceType.CONCURRENT_TASKS, QuotaLevel.SCAN, self._scan_id, limit=20.0
                )
                self.resource_governor.consume(
                    ResourceType.HTTP_REQUESTS, QuotaLevel.SCAN, self._scan_id, amount=10.0
                )
        except Exception as _rge:
            logger.debug(f"[ResourceGovernor] Quotas skipped: {_rge}")

        # 2. Differential Engine & Anomaly Pipeline
        try:
            if hasattr(self, "differential_engine") and self.differential_engine:
                from core.analysis.differential_engine import ResponseSnapshot
                base_snap = ResponseSnapshot(
                    snapshot_id="baseline_root",
                    url=self.ctx.target,
                    status_code=200,
                    headers=(),
                    body_length=len(getattr(self.ctx, "body_content", "") or ""),
                    response_time_ms=50.0,
                )
                var_snap = ResponseSnapshot(
                    snapshot_id="variant_root",
                    url=self.ctx.target,
                    status_code=200,
                    headers=(),
                    body_length=len(getattr(self.ctx, "body_content", "") or ""),
                    response_time_ms=52.0,
                )
                self.differential_engine.compare(base_snap, var_snap)
        except Exception as _dfe:
            logger.debug(f"[DifferentialEngine] Baseline skipped: {_dfe}")

        # 3. Specialist Team Evidence Bus
        try:
            if hasattr(self, "specialist_team") and self.specialist_team:
                from core.orchestration.specialist_agents import EvidenceArtifact, SpecialistRole
                self.specialist_team.bus.publish(EvidenceArtifact(
                    producer_role=SpecialistRole.WEB_SEMANTICS,
                    artifact_type="scan_findings",
                    data={"finding_count": len(self.ctx.vulnerabilities)},
                    provenance="active_scanning"
                ))
                logger.info("[SpecialistTeam] Posted SCAN findings artifact to evidence bus")
        except Exception as _ste:
            logger.debug(f"[SpecialistTeam] Posting skipped: {_ste}")

    def _sync_exploit_to_advanced_engines(self):
        """Synchronizes EXPLOITATION artifacts to HypothesisLedger, EvidenceGraph, SecretLifecycleManager, and SpecialistTeam."""
        # 1. Hypothesis Ledger
        try:
            if hasattr(self, "hypothesis_ledger") and self.hypothesis_ledger:
                hypotheses_v2 = self.ctx.get("hypotheses_v2", []) if hasattr(self.ctx, "get") else getattr(self.ctx, "hypotheses_v2", [])
                for h in hypotheses_v2[:20]:
                    target = getattr(h, "target", self.ctx.target)
                    hyp_text = getattr(h, "hypothesis", getattr(h, "rationale", "generic_hypothesis"))
                    self.hypothesis_ledger.record_hypothesis(
                        url=target,
                        hypothesis=str(hyp_text),
                        prerequisites=[],
                        expected_observation="exploit_confirmation",
                    )
        except Exception as _hle:
            logger.debug(f"[HypothesisLedger] Sync skipped: {_hle}")

        # 2. Evidence Graph
        try:
            if hasattr(self, "evidence_graph") and self.evidence_graph:
                for v in (self.ctx.vulnerabilities or []):
                    v_dict = v if isinstance(v, dict) else {"title": str(v)}
                    self.evidence_graph.add_node("finding", v_dict)
                integrity_ok = self.evidence_graph.verify_integrity()
                logger.info(f"[EvidenceGraph] Synchronized {len(self.evidence_graph.nodes)} evidence nodes (integrity_valid={integrity_ok})")
        except Exception as _ege:
            logger.debug(f"[EvidenceGraph] Sync skipped: {_ege}")

        # 3. Secret Lifecycle Manager
        try:
            if hasattr(self, "secret_lifecycle") and self.secret_lifecycle:
                from core.security.secret_lifecycle import SecretLifecycleRule
                rule = SecretLifecycleRule(name="harvested_rule", max_age_seconds=86400.0, revoke_on_leak=True)
                self.secret_lifecycle.register_rule(rule)
                for cred in (getattr(self.ctx, "harvested_creds", []) or []):
                    u = cred.get("username", "anon")
                    s_id = f"cred_{u}_{self._scan_id}"
                    self.secret_lifecycle.track(
                        secret_ref=s_id,
                        rule_name="harvested_rule",
                        tenant_id=self.tenant_id
                    )
                logger.info(f"[SecretLifecycle] Tracked {len(getattr(self.ctx, 'harvested_creds', []) or [])} credentials")
        except Exception as _sle:
            logger.debug(f"[SecretLifecycle] Tracking skipped: {_sle}")

        # 4. Specialist Team Evidence Bus
        try:
            if hasattr(self, "specialist_team") and self.specialist_team:
                from core.orchestration.specialist_agents import EvidenceArtifact, SpecialistRole
                self.specialist_team.bus.publish(EvidenceArtifact(
                    producer_role=SpecialistRole.VERIFICATION,
                    artifact_type="exploit_summary",
                    data={
                        "vulnerabilities": len(self.ctx.vulnerabilities),
                        "exploits": len(self.ctx.exploit_results),
                        "harvested_creds": len(getattr(self.ctx, "harvested_creds", []) or []),
                    },
                    provenance="exploitation_phase"
                ))
                logger.info("[SpecialistTeam] Posted EXPLOIT summary artifact to evidence bus")
        except Exception as _ste:
            logger.debug(f"[SpecialistTeam] Posting skipped: {_ste}")

    AUTH_TEST_IDS = frozenset({
        "auth_login_01", "auth_session_hijack_01", "auth_default_creds_01",
        "auth_credential_stuffing_01", "auth_password_policy_01", "authentication",
    })

    def _run_v2_experiment_cycle(self, max_experiments: int = None):
        gaps = self.coverage_matrix.get_gaps()
        if not gaps:
            return

        if max_experiments is None:
            inv = getattr(self, 'endpoint_inventory_v2', None)
            try:
                n_endpoints = len(inv.list_endpoints()) if inv is not None else 0
            except Exception:
                n_endpoints = 0
            max_experiments = max(500, min(n_endpoints * 4, 5000))

        hypotheses = self.hypothesis_engine.generate(gaps)
        ranked = self.hypothesis_engine.rank(hypotheses)

        identity_ctx = self._build_identity_context()
        all_creds = identity_ctx.get("all_credentials", [])
        has_creds = bool(all_creds)

        executed = 0
        batch_size = min(len(ranked), max_experiments)
        for h in ranked[:batch_size]:
            # Skip auth tests early when no credentials are available
            if h.test_id in self.AUTH_TEST_IDS and not has_creds:
                self.coverage_matrix.update_state(h.endpoint_id, h.test_id, CoverageState.NOT_APPLICABLE)
                continue
            ep_data = self.security_context_v2.endpoints.get(h.endpoint_id, {})
            base_url = ep_data.get("url", h.endpoint_id)

            is_auth_test = h.test_id in self.AUTH_TEST_IDS
            if is_auth_test and len(all_creds) > 1:
                for cred in all_creds:
                    exp = SecurityExperiment(
                        hypothesis_id=f"{h.hypothesis_id}_{cred['role']}",
                        endpoint_id=h.endpoint_id,
                        capability=h.test_id,
                        priority=h.priority,
                        input_parameters={
                            "url": base_url,
                            "username": cred["username"],
                            "password": cred["password"],
                            "login_url": cred.get("login_url", ""),
                            "role": cred["role"],
                        },
                    )
                    self.experiment_scheduler.queue(exp)
            else:
                exp = SecurityExperiment(
                    hypothesis_id=h.hypothesis_id,
                    endpoint_id=h.endpoint_id,
                    capability=h.test_id,
                    priority=h.priority,
                    input_parameters={
                        "url": base_url,
                        **identity_ctx,
                    },
                )
                if not self.experiment_scheduler.queue(exp):
                    continue

        while self.experiment_scheduler.size() > 0 and executed < max_experiments:
            exp = self.experiment_scheduler.next()
            if not exp:
                break

            result = self.pipeline_v2.execute(exp)
            executed += 1

            if result.finding:
                self.knowledge_graph.add_finding(result.finding)
                self.security_context_v2.add_finding(result.finding.finding_id, result.finding.to_dict())
            if result.evidence:
                self.knowledge_graph.add_evidence(result.evidence)
                if result.finding:
                    self.knowledge_graph.connect_evidence(result.finding.finding_id, result.evidence.evidence_id)

            if not result.success and result.error:
                error_code = result.execution_result.error_code if result.execution_result else ""
                if error_code == "NO_CREDENTIALS":
                    self.coverage_matrix.update_state(exp.endpoint_id, exp.capability, CoverageState.NOT_APPLICABLE)
                    continue
                exc = Exception(result.error)
                ft = self.failure_classifier.classify(exc, {"error_code": error_code})
                action = self.recovery_policy.get_action(ft)
                if action == RetryAction.BLOCK:
                    self.coverage_matrix.update_state(exp.endpoint_id, exp.capability, CoverageState.BLOCKED)
                # Include the underlying error (truncated) so classified failures
                # are diagnosable — otherwise a burst of identical "tool_execution_error"
                # lines hides WHY experiments failed.
                _err = str(result.error).replace("\n", " ")[:160]
                logger.info(f"[V2Recovery] {ft.value} → {action.value} for "
                            f"{exp.capability}@{exp.endpoint_id}: {_err}")

        conv = self.convergence_engine.calculate_convergence()
        logger.info(f"[V2Cycle] Executed {executed} experiments, coverage={conv:.1%}, gaps={len(self.coverage_matrix.get_gaps())}")
