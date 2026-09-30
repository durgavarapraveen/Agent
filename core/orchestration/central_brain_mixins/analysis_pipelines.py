from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class AnalysisPipelinesMixin:
    """Self-contained analysis runners invoked by the main loop / scheduler:
    SAST (source + CodeQL), JS-bundle + DOM-sink analysis, semantic API fuzzing
    with coverage, and format probes. Each adds findings to ctx; none drive
    phase transitions. Extracted from CentralBrain.
    """

    async def _run_sast_pipeline(self) -> None:
        from core.analysis.source_extractor import (
            extract_exposed_git, rehydrate_sourcemap, run_semgrep)
        from core.analysis.codeql_runner import run_codeql, llm_review_finding

        scan_id = getattr(self, "_scan_id", None) or "unscoped"
        base = getattr(self.ctx, "target", None)
        if not base:
            return

        source_trees = []
        # 3.1 — git leak
        exposed = any(
            "/.git/" in str(v.get("location", ""))
            or "git config" in str(v.get("title", "")).lower()
            for v in (self.ctx.vulnerabilities or []))
        if exposed:
            tree = extract_exposed_git(base, scan_id)
            if tree:
                source_trees.append(tree)
        # 3.2 — sourcemap rehydration for every same-origin bundle
        try:
            base_host = str(base).split("/")[2] if "://" in base else base
        except Exception:
            base_host = ""
        for js_url in list(getattr(self.ctx, "js_bundles", []) or [])[:20]:
            if base_host and base_host not in js_url:
                continue
            tree = rehydrate_sourcemap(js_url, scan_id)
            if tree:
                source_trees.append(tree)

        if not source_trees:
            logger.info("[SAST] no source recovered — skipping semgrep/codeql")
            return

        for tree in source_trees:
            # 3.3 — semgrep
            findings = run_semgrep(tree)
            # 3.4 — codeql (best-effort)
            try:
                findings.extend(run_codeql(tree))
            except Exception as e:
                logger.debug(f"[SAST] codeql failed: {e}")
            logger.info(f"[SAST] {tree}: {len(findings)} raw findings")
            # 3.5 — hand each to the LLM code reviewer, cap so we don't
            # overspend the LLM budget on a huge tree.
            for f in findings[:50]:
                if hasattr(self.ctx, "add_vulnerability"):
                    self.ctx.add_vulnerability(f)
                try:
                    proposal = await llm_review_finding(f, tree)
                    if proposal:
                        # Publish the proposed exploit as a note on the
                        # scratchpad so the ExploitPhase picks it up.
                        try:
                            from core.orchestration.agent_scratchpad import get_scratchpad
                            pad = get_scratchpad(scan_id, "sast-reviewer")
                            pad.post("tool", proposal, topic="sast_exploit_proposal")
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug(f"[SAST] LLM review failed for {f.get('rule_id')}: {e}")

    async def _run_bundle_and_dom_analysis(self) -> None:
        base = getattr(self.ctx, "target", None) or getattr(self, "target", None)
        if not base:
            return
        try:
            from core.exploitation.js_bundle_analyzer import analyze_bundles
            routes = await analyze_bundles(self.ctx, base)
            if routes:
                logger.info(f"[BundleAnalyzer] extracted {len(routes)} route(s) from JS bundles")
        except Exception as e:
            logger.debug(f"[BundleAnalyzer] skipped: {e}")
        try:
            from core.exploitation.dom_sink_monitor import run_dom_sink_monitor
            findings = await run_dom_sink_monitor(self.ctx, base)
            for f in findings or []:
                if isinstance(f, dict):
                    f.setdefault("phase", "recon")
                    f.setdefault("tool", "dom_sink_monitor")
                    if hasattr(self.ctx, "add_vulnerability"):
                        self.ctx.add_vulnerability(f)
            logger.info(f"[DOMSinkMonitor] found {len(findings or [])} client-side sink hit(s)")
        except Exception as e:
            logger.debug(f"[DOMSinkMonitor] skipped: {e}")

    async def _run_semantic_fuzz_with_coverage(self) -> None:
        try:
            from core.exploitation.semantic_api_fuzzer import run_semantic_fuzz
            from core.exploitation.coverage_tracker import CoverageTracker
        except Exception as e:
            logger.debug(f"[SemanticFuzz] import failed: {e}")
            return
        if not getattr(self.ctx, "captured_requests", None):
            if getattr(self.ctx, "browser_status", "") == "UNAVAILABLE":
                logger.info("[SemanticFuzz] captured_requests UNAVAILABLE (browser missing) "
                            "— not a negative result; skipping")
            else:
                logger.info("[SemanticFuzz] no captured_requests — skipping")
            return
        tracker = CoverageTracker()
        # Expose the tracker to the fuzzer via ctx so it can filter blind
        # mutations. The fuzzer treats a missing tracker as no-op.
        self.ctx.coverage_tracker = tracker
        findings = await run_semantic_fuzz(self.ctx)
        for f in findings or []:
            if isinstance(f, dict):
                f.setdefault("phase", "exploit")
                f.setdefault("tool", "semantic_api_fuzzer")
                if hasattr(self.ctx, "add_vulnerability"):
                    self.ctx.add_vulnerability(f)
        logger.info(f"[SemanticFuzz] {len(findings or [])} finding(s); "
                    f"coverage across {len(tracker._buckets)} endpoint bucket(s)")

    async def _run_format_probes(self) -> None:
        try:
            from core.exploitation.format_probes import available_probes, get_probe
            from core.orchestration.agent_scratchpad import get_scratchpad
        except Exception as e:
            logger.debug(f"[FormatProbes] import failed: {e}")
            return
        scan_id = getattr(self, "_scan_id", None) or "unscoped"
        # Filter to endpoints that look like uploads or dataset-preview surfaces.
        endpoints = list(getattr(self.ctx, "endpoints", []) or [])
        upload_eps = [e for e in endpoints
                      if any(k in str(e).lower()
                             for k in ("upload", "dataset", "preview",
                                       "import", "attachment", "file"))]
        if not upload_eps:
            logger.info("[FormatProbes] no upload/preview endpoints — skipping")
            return
        pad = get_scratchpad(scan_id, "format-probes")
        probes = available_probes()
        logger.info(f"[FormatProbes] queueing {len(probes)} probe(s) × "
                    f"{len(upload_eps)} endpoint(s)")
        for probe_name in probes:
            try:
                probe = get_probe(probe_name)()
            except Exception as e:
                logger.debug(f"[FormatProbes] probe {probe_name} build failed: {e}")
                continue
            if not probe.get("payload"):
                continue
            for ep in upload_eps[:5]:
                pad.post("tool", {
                    "probe": probe_name,
                    "endpoint": str(ep),
                    "filename": probe.get("filename"),
                    "mime": probe.get("mime"),
                    "sink_signature": probe.get("sink_signature", []),
                    "rationale": probe.get("rationale", ""),
                }, topic="format_probe_ready")
