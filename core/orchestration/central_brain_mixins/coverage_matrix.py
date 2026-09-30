from __future__ import annotations

import logging

from core.convergence import CompletionValidator
from core.coverage.convergence_engine import ConvergenceEngineV2
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.execution.execution_pipeline import ExecutionPipelineV2

logger = logging.getLogger(__name__)


class CoverageMatrixMixin:
    """Build the ep×test coverage matrix from the attack surface and bridge V1
    findings into it. Extracted from CentralBrain; operates on shared self attrs
    (self.coverage_matrix, self.endpoint_inventory, self.applicability_engine, ...).
    """

    def _build_coverage_matrix_from_surface(self):
        endpoints = self.endpoint_inventory.list_endpoints()
        # Drop non-actionable URLs (JS build internals / source-parse artifacts)
        # before they enter the coverage matrix — each junk endpoint multiplies the
        # ep×test denominator (coverage-denominator explosion) and wastes probe
        # budget. Same high-precision filter the surface classifier uses.
        try:
            from core.recon.surface_classifier import _is_non_actionable_url
            _before = len(endpoints)
            endpoints = [ep for ep in endpoints
                         if not _is_non_actionable_url(ep.get("url", "") or ep.get("endpoint_id", ""))]
            if len(endpoints) != _before:
                logger.info("[CoverageMatrix] excluded %d non-actionable endpoint(s) "
                            "from the coverage surface", _before - len(endpoints))
        except Exception:
            pass
        ep_ids = [ep.get("endpoint_id", ep.get("url", "")) for ep in endpoints]

        applicable_pairs = []
        not_discovered_pairs = []
        identities = list(self.security_context_v2.identities.keys()) or ["default"]

        # Phase 5/30: Use classify_all_tests for NOT_DISCOVERED distinction
        discovered_features = {}
        if hasattr(self.ctx, 'attack_surface') and self.ctx.attack_surface:
            surface = self.ctx.attack_surface
            discovered_features = {
                "has_jwt": any("jwt" in str(t).lower() for t in getattr(surface, '_technologies', {}).values()),
                "has_graphql": any("graphql" in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values()),
                "has_websocket": any("ws" in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values()),
                "has_login": any(kw in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values() for kw in ("login", "signin", "auth")),
                "has_otp": any(kw in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values() for kw in ("otp", "mfa", "2fa")),
            }

        for ep in endpoints:
            classified = self.applicability_engine.classify_all_tests(
                ep, identities=identities, discovered_features=discovered_features,
            )
            ep_id = ep.get("endpoint_id", ep.get("url", ""))
            for t in classified.get("applicable", []):
                applicable_pairs.append((ep_id, t.test_id))
            for t in classified.get("not_discovered", []):
                not_discovered_pairs.append((ep_id, t.test_id))

        if not applicable_pairs:
            return

        # Include NOT_DISCOVERED test IDs in the matrix so they can be promoted later
        nd_test_ids = {p[1] for p in not_discovered_pairs}
        all_ep_ids = list({p[0] for p in applicable_pairs} | {p[0] for p in not_discovered_pairs})
        all_test_ids = list({p[1] for p in applicable_pairs} | nd_test_ids)
        # Pass the REAL per-endpoint applicable pairs so non-applicable cells in
        # the ep×test grid start NOT_APPLICABLE — prevents the coverage
        # denominator from exploding to the full cross-product (~55k) and keeps
        # convergence meaningful.
        self.coverage_matrix = CoverageMatrix(
            all_ep_ids, all_test_ids, applicable=set(applicable_pairs))

        # Mark NOT_DISCOVERED cells (update_state is the real API; the old
        # .update() name silently AttributeError'd and never marked them).
        _app_set = set(applicable_pairs)
        for ep_id, test_id in not_discovered_pairs:
            if (ep_id, test_id) not in _app_set:
                self.coverage_matrix.update_state(ep_id, test_id, CoverageState.NOT_DISCOVERED)

        self.convergence_engine = ConvergenceEngineV2(self.coverage_matrix)
        # P1-F2 / P1-F1: keep the completion validator and ctx-exposed engine
        # pointed at the freshly-rebuilt live V2 engine.
        try:
            self.completion_validator = CompletionValidator(self.coverage_engine, self.convergence_engine)
        except Exception:
            pass
        try:
            if getattr(self, "ctx", None) is not None:
                self.ctx.convergence_engine = self.convergence_engine
        except Exception:
            pass
        self.pipeline_v2 = ExecutionPipelineV2(
            executor_registry=self.executor_registry,
            tool_portfolio=self.tool_portfolio,
            coverage_matrix=self.coverage_matrix,
            finding_store=self.finding_store_v2,
            evidence_validator=self.evidence_validator,
        )
        logger.info(f"[CoverageMatrix] Built: {len(all_ep_ids)} endpoints × {len(all_test_ids)} tests "
                    f"= {len(applicable_pairs)} applicable + {len(not_discovered_pairs)} not_discovered")

    def _sync_v1_findings_to_coverage_matrix(self):
        if not hasattr(self, 'coverage_matrix') or not self.coverage_matrix:
            return

        matrix = self.coverage_matrix.get_matrix()
        if not matrix:
            return

        _VULN_TO_TESTS = {
            "NUCLEI_MATCH": ["info_disclosure_01", "cors_misconfig_01"],
            "NIKTO_FINDING": ["info_disclosure_01", "path_directory_01"],
            "MISSING_HEADER": ["header_injection_01", "info_disclosure_01"],
            "TLS_WEAKNESS": ["info_disclosure_01"],
            "INFO_DISCLOSURE": ["info_disclosure_01"],
        }
        _KEYWORD_TO_TESTS = {
            "sqli": ["sqli_basic_01", "sqli_time_based_01", "sqli_error_based_01", "sqli_union_01"],
            "sql injection": ["sqli_basic_01", "sqli_time_based_01", "sqli_error_based_01"],
            "xss": ["xss_reflected_01", "xss_stored_01", "xss_dom_01"],
            "cross-site scripting": ["xss_reflected_01", "xss_stored_01"],
            "csrf": ["csrf_token_01"],
            "ssrf": ["ssrf_basic_01", "ssrf_cloud_01"],
            "command injection": ["cmdi_basic_01"],
            "path traversal": ["path_traversal_01"],
            "directory": ["path_directory_01"],
            "open redirect": ["open_redirect_01"],
            "cors": ["cors_misconfig_01"],
            "idor": ["authz_idor_01", "authz_horizontal_01"],
            "privilege": ["authz_priv_esc_01"],
            "brute": ["auth_login_01"],
            "default cred": ["auth_default_creds_01"],
            "session": ["auth_session_hijack_01"],
            "jwt": ["jwt_manipulation_01", "jwt_algo_confusion_01", "jwt_none_algo_01"],
            "xxe": ["xxe_basic_01"],
            "ssti": ["ssti_basic_01"],
            "template injection": ["ssti_basic_01"],
            "nosql": ["nosqli_basic_01", "nosqli_logical_01"],
            "file upload": ["upload_type_01", "upload_rce_01"],
            "graphql": ["graphql_introspection_01", "graphql_mutation_01"],
            "websocket": ["ws_hijack_01"],
            "race condition": ["race_condition_01"],
            "ldap": ["ldap_injection_01"],
            "nuclei": ["info_disclosure_01"],
        }

        ep_ids = list(matrix.keys())
        confirmed_cells = set()
        tested_tests = set()

        for vuln in getattr(self.ctx, 'vulnerabilities', []):
            if not isinstance(vuln, dict):
                continue
            vtype = vuln.get("type", "")
            title = (vuln.get("title", "") or "").lower()
            location = vuln.get("location", "") or vuln.get("target", "")

            matched_tests = set()
            if vtype in _VULN_TO_TESTS:
                matched_tests.update(_VULN_TO_TESTS[vtype])
            for kw, tids in _KEYWORD_TO_TESTS.items():
                if kw in title:
                    matched_tests.update(tids)

            if not matched_tests:
                matched_tests.add("info_disclosure_01")

            best_ep = None
            if location:
                loc_lower = location.lower()
                for eid in ep_ids:
                    if eid.lower() in loc_lower or loc_lower in eid.lower():
                        best_ep = eid
                        break
            if not best_ep and ep_ids:
                best_ep = ep_ids[0]

            if best_ep:
                for tid in matched_tests:
                    if tid in matrix.get(best_ep, {}):
                        self.coverage_matrix.update_state(best_ep, tid, CoverageState.CONFIRMED)
                        confirmed_cells.add((best_ep, tid))
                        tested_tests.add(tid)

        _TOOL_CAPS_TO_TESTS = {
            "vulnerability_scanning": [
                "sqli_basic_01", "xss_reflected_01", "xss_stored_01", "cmdi_basic_01",
                "path_traversal_01", "path_directory_01", "info_disclosure_01",
                "cors_misconfig_01", "header_injection_01", "open_redirect_01",
                "ssti_basic_01", "csrf_token_01",
            ],
            "tls_analysis": ["info_disclosure_01"],
            "port_scanning": ["info_disclosure_01"],
            "header_analysis": ["header_injection_01", "cors_misconfig_01", "info_disclosure_01"],
        }

        ran_caps = set()
        for task in getattr(self.ctx, 'completed_tasks', []):
            if isinstance(task, dict):
                ran_caps.add(task.get("capability", ""))
            elif isinstance(task, str):
                ran_caps.add(task)

        for cap, test_ids in _TOOL_CAPS_TO_TESTS.items():
            if cap not in ran_caps:
                continue
            for eid in ep_ids:
                for tid in test_ids:
                    if tid not in matrix.get(eid, {}):
                        continue
                    if (eid, tid) in confirmed_cells:
                        continue
                    self.coverage_matrix.update_state(eid, tid, CoverageState.REJECTED)
                    tested_tests.add(tid)

        total_cells = sum(len(tests) for tests in matrix.values())
        gaps_after = len(self.coverage_matrix.get_gaps())
        logger.info(
            f"[V1→V2Bridge] Synced {len(self.ctx.vulnerabilities)} findings → "
            f"{len(confirmed_cells)} confirmed, {total_cells - gaps_after - len(confirmed_cells)} rejected, "
            f"{gaps_after} remaining gaps (was {total_cells})"
        )
