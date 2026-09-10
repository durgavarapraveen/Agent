"""Tests for Phase 2-10 hardening components.

Covers: AuthorizationAuthority, ExecutionContract, ConnectionPinning,
EgressTelemetry, BrowserWorker, ApplicationModel, SemanticInference,
SessionModel, AuthorizationMatrix, WorkflowStateMachine, ConcurrencyEngine,
HypothesisLedger, TypedActionPlanner, EvidenceGraph, OracleEngine.
"""
import asyncio
import time
import pytest

# ── Phase 2.1: Authorization Authority ──

from core.security.authorization_authority import AuthorizationAuthority, AuthorizationScope


class TestAuthorizationAuthority:
    def setup_method(self):
        AuthorizationAuthority._instance = None
        self.auth = AuthorizationAuthority.get()

    def test_singleton(self):
        assert self.auth is AuthorizationAuthority.get()

    def test_register_and_authorize(self):
        scope = AuthorizationScope(
            hosts={"example.com"}, capabilities={"scan"}, identities={"agent-1"},
        )
        self.auth.register_scope("s1", scope)
        ok, _ = self.auth.authorize_execution("s1", "example.com", "scan", "agent-1")
        assert ok

    def test_deny_unknown_auth_id(self):
        ok, reason = self.auth.authorize_execution("nonexistent", "x", "y", "z")
        assert not ok
        assert "Unknown" in reason

    def test_deny_out_of_scope_target(self):
        scope = AuthorizationScope(hosts={"safe.com"})
        self.auth.register_scope("s2", scope)
        ok, _ = self.auth.authorize_execution("s2", "evil.com", "", "")
        assert not ok

    def test_budget_enforcement(self):
        scope = AuthorizationScope(hosts={"t.com"}, request_budget=2)
        self.auth.register_scope("s3", scope)
        self.auth.authorize_execution("s3", "t.com", "", "")
        self.auth.authorize_execution("s3", "t.com", "", "")
        ok, reason = self.auth.authorize_execution("s3", "t.com", "", "")
        assert not ok
        assert "budget" in reason.lower()

    def test_time_window(self):
        scope = AuthorizationScope(
            hosts={"t.com"},
            time_window_start=time.time() + 9999,
            time_window_end=time.time() + 99999,
        )
        self.auth.register_scope("s4", scope)
        ok, reason = self.auth.authorize_execution("s4", "t.com", "", "")
        assert not ok
        assert "early" in reason.lower()

    def test_cidr_authorization(self):
        scope = AuthorizationScope(cidrs={"10.0.0.0/8"})
        self.auth.register_scope("s5", scope)
        ok, _ = self.auth.authorize_execution("s5", "10.0.1.50", "", "")
        assert ok

    def test_wildcard_requires_lab_mode(self):
        scope = AuthorizationScope(hosts={"*"}, lab_mode=False)
        self.auth.register_scope("s6", scope)
        ok, reason = self.auth.authorize_execution("s6", "any.com", "", "")
        assert not ok
        assert "lab mode" in reason.lower()

    def test_wildcard_with_lab_mode(self):
        scope = AuthorizationScope(hosts={"*"}, lab_mode=True)
        self.auth.register_scope("s7", scope)
        ok, _ = self.auth.authorize_execution("s7", "anything.com", "", "")
        assert ok


# ── Phase 2.2: Execution Contract ──

from core.security.execution_contract import ExecutionContract
from core.security.platform_contract import ContractViolation


class TestExecutionContract:
    def _make_contract(self, **overrides):
        defaults = dict(
            scan_id="scan-1", experiment_id="exp-1", target="example.com",
            capability="nmap", identity="agent-1", impact_class="safe",
            budget=100, expiry_ts=time.time() + 3600, authorization_ref="auth-1",
        )
        defaults.update(overrides)
        return ExecutionContract(**defaults)

    def test_sign_and_verify(self):
        c = self._make_contract().sign()
        assert c.verify()

    def test_unsigned_fails(self):
        with pytest.raises(ContractViolation, match="missing"):
            self._make_contract().verify()

    def test_tamper_detection(self):
        c = self._make_contract().sign()
        object.__setattr__(c, "target", "evil.com")
        with pytest.raises(ContractViolation, match="tamper"):
            c.verify()

    def test_expired_contract(self):
        c = self._make_contract(expiry_ts=time.time() - 1).sign()
        with pytest.raises(ContractViolation, match="expired"):
            c.verify()

    def test_immutable(self):
        c = self._make_contract()
        with pytest.raises(AttributeError):
            c.target = "other"


# ── Phase 3.2: Connection Pinning ──

from core.security.connection_pinning import ConnectionPinning, EgressTelemetry, EgressRecord


class TestConnectionPinning:
    def setup_method(self):
        ConnectionPinning._instance = None
        self.cp = ConnectionPinning.get()

    def test_singleton(self):
        assert self.cp is ConnectionPinning.get()

    def test_pin_and_verify(self):
        self.cp._pins["test.local"] = "1.2.3.4"
        assert self.cp.verify_connection("test.local", "1.2.3.4")
        assert not self.cp.verify_connection("test.local", "5.6.7.8")

    def test_clear_pin(self):
        self.cp._pins["a.local"] = "1.1.1.1"
        self.cp.clear_pin("a.local")
        assert self.cp.get_pinned_ip("a.local") is None


class TestEgressTelemetry:
    def setup_method(self):
        EgressTelemetry._instance = None
        self.et = EgressTelemetry.get()

    def test_record_and_export(self):
        self.et.record("h.com", ["1.2.3.4"], "1.2.3.4", 443, "https", "ALLOW")
        records = self.et.export()
        assert len(records) == 1
        assert records[0]["target_host"] == "h.com"
        assert records[0]["policy_decision"] == "ALLOW"

    def test_filter_by_host(self):
        self.et.record("a.com", ["1.1.1.1"], "1.1.1.1", 80, "http", "ALLOW")
        self.et.record("b.com", ["2.2.2.2"], "2.2.2.2", 80, "http", "DENY")
        assert len(self.et.get_records("a.com")) == 1

    def test_max_records(self):
        et = EgressTelemetry(max_records=5)
        for i in range(10):
            et.record(f"h{i}.com", [f"1.1.1.{i}"], f"1.1.1.{i}", 80, "http", "ALLOW")
        assert len(et.export()) == 5


# ── Phase 5.1/5.2: Browser Worker ──

from core.browser.browser_worker import BrowserWorker, BrowserSecurityPolicy, BrowserObservation


class TestBrowserWorker:
    def test_session_lifecycle(self):
        bw = BrowserWorker()
        sid = bw.start_session()
        assert sid
        bw.record_navigation("https://test.com", 200)
        obs = bw.end_session()
        assert len(obs) == 1

    def test_scheme_blocking(self):
        bw = BrowserWorker()
        bw.start_session()
        assert bw.authorize_navigation("https://ok.com")
        assert not bw.authorize_navigation("ftp://bad.com")

    def test_navigation_depth_limit(self):
        bw = BrowserWorker(policy=BrowserSecurityPolicy(max_navigation_depth=2))
        bw.start_session()
        bw._navigation_depth = 2
        assert not bw.authorize_navigation("https://deep.com")

    def test_request_budget(self):
        bw = BrowserWorker(policy=BrowserSecurityPolicy(max_requests_per_page=1))
        bw.start_session()
        assert bw.authorize_request("https://a.com")
        assert not bw.authorize_request("https://b.com")

    def test_download_blocking(self):
        bw = BrowserWorker(policy=BrowserSecurityPolicy(allow_downloads=False))
        bw.start_session()
        assert not bw.authorize_request("https://a.com/file.zip", resource_type="download")

    def test_egress_check(self):
        bw = BrowserWorker(egress_checker=lambda url: "allowed" in url)
        bw.start_session()
        assert bw.authorize_navigation("https://allowed.com")
        assert not bw.authorize_navigation("https://blocked.com")

    def test_observation_types(self):
        bw = BrowserWorker()
        bw.start_session()
        bw.record_navigation("https://t.com", 200)
        bw.record_console_event("error", "err msg", "https://t.com")
        bw.record_dom_snapshot("https://t.com", "hash1", 10)
        bw.record_storage_mutation("localStorage", "key1", "https://t.com")
        bw.record_service_worker("install", "/sw.js", "https://t.com")
        bw.record_frame("https://t.com/f", "https://t.com", True)
        bw.record_websocket("wss://t.com/ws", "send", 100)
        bw.record_redirect("https://t.com/old", "https://t.com/new", 302)
        obs = bw.end_session()
        types = {o.observation_type for o in obs}
        assert types == {"navigation", "console", "dom_snapshot", "storage_mutation",
                         "service_worker", "frame", "websocket", "redirect"}

    def test_export_evidence(self):
        bw = BrowserWorker()
        bw.start_session()
        bw.record_navigation("https://t.com", 200)
        export = bw.export_evidence()
        assert len(export) == 1
        assert export[0]["is_untrusted"] is True
        assert "session_id" in export[0]


# ── Phase 6.2: Semantic Inference ──

from core.knowledge.semantic_inference import SemanticInferenceEngine, InferenceResult


class TestSemanticInference:
    def test_graphql_schema(self):
        si = SemanticInferenceEngine()
        r = si.infer_endpoint({"endpoint_id": "e1", "schema": "type Query { graphql }"})
        assert r.inferred_type == "graphql"
        assert r.confidence > 0.5

    def test_openapi_schema(self):
        si = SemanticInferenceEngine()
        r = si.infer_endpoint({"endpoint_id": "e2", "schema": "openapi: 3.0"})
        assert r.inferred_type == "rest"

    def test_websocket_header(self):
        si = SemanticInferenceEngine()
        r = si.infer_endpoint({"endpoint_id": "e3", "headers": {"Upgrade": "websocket"}})
        assert r.inferred_type == "websocket"

    def test_sse_content_type(self):
        si = SemanticInferenceEngine()
        r = si.infer_endpoint({"endpoint_id": "e4", "content_type": "text/event-stream"})
        assert r.inferred_type == "sse"

    def test_grpc_content_type(self):
        si = SemanticInferenceEngine()
        r = si.infer_endpoint({"endpoint_id": "e5", "content_type": "application/grpc+proto"})
        assert r.inferred_type == "grpc_web"

    def test_soap_shape(self):
        si = SemanticInferenceEngine()
        r = si.infer_endpoint({"endpoint_id": "e6", "request_shape": {"soapenv:Envelope": {}}})
        assert r.inferred_type == "soap"

    def test_configurable_weights(self):
        si = SemanticInferenceEngine(confidence_weights={"content_type": 0.9})
        r = si.infer_endpoint({"endpoint_id": "e7", "content_type": "application/json"})
        assert r.confidence == 0.9

    def test_caches_inference(self):
        si = SemanticInferenceEngine()
        si.infer_endpoint({"endpoint_id": "cached"})
        assert si.get_inference("cached") is not None

    def test_confidence_capped(self):
        si = SemanticInferenceEngine(confidence_weights={"schema_found": 0.6, "schema_type_match": 0.6})
        r = si.infer_endpoint({"endpoint_id": "e8", "schema": "openapi: 3.0"})
        assert r.confidence <= 1.0


# ── Phase 7.1: Identity/Session Model ──

from core.identity.session_model import (
    IdentityManager as SessionIdentityManager, SessionModel, SecretsVault, IdentityContext,
)


class TestSessionModel:
    def test_vault_redaction(self):
        vault = SecretsVault()
        vault.store_secret("api_key", "s3cret123")
        assert vault.redact("my key is s3cret123 ok") == "my key is [REDACTED] ok"

    def test_session_token_vault(self):
        vault = SecretsVault()
        ctx = IdentityContext(role="admin")
        session = SessionModel(vault, ctx)
        session.set_token("access", "tok-abc")
        assert session.tokens["access"] == "[REDACTED]"
        assert session.get_token("access") == "tok-abc"

    def test_identity_manager_sessions(self):
        mgr = SessionIdentityManager()
        s1 = mgr.create_identity("admin")
        s2 = mgr.create_identity("user")
        assert mgr.get_session(s1.identity.id) is s1
        assert mgr.get_session(s2.identity.id) is s2

    def test_anonymous_default(self):
        mgr = SessionIdentityManager()
        anon = mgr.get_session("anonymous_default")
        assert anon is not None
        assert anon.identity.role == "anonymous"


# ── Phase 7.2: Authorization Matrix ──

from core.identity.authorization_matrix import AuthorizationMatrix, AccessTester


class TestAuthorizationMatrix:
    def test_record_and_check(self):
        mgr = SessionIdentityManager()
        matrix = AuthorizationMatrix(mgr)
        matrix.record_authorization("res1", "read", "user1", True)
        matrix.record_authorization("res1", "write", "user1", False)
        assert matrix.check_authorization("res1", "read", "user1") is True
        assert matrix.check_authorization("res1", "write", "user1") is False
        assert matrix.check_authorization("res1", "delete", "user1") is None

    def test_snapshot(self):
        mgr = SessionIdentityManager()
        matrix = AuthorizationMatrix(mgr)
        matrix.record_authorization("r", "a", "u1", True)
        snap = matrix.get_matrix_snapshot()
        assert "r|a" in snap["authorized"]

    def test_access_tester_budget(self):
        mgr = SessionIdentityManager()
        s1 = mgr.create_identity("user")
        matrix = AuthorizationMatrix(mgr)
        tester = AccessTester(matrix, safety_budget=1)
        results = tester.orchestrate_cross_identity_experiment("r1", "a1", [s1.identity.id, s1.identity.id])
        assert len(results) == 1  # budget = 1


# ── Phase 8.1: Workflow State Machine ──

from core.workflows.state_machine import WorkflowStateMachine, WorkflowState, WorkflowTransition


class TestWorkflowStateMachine:
    def _build_machine(self):
        m = WorkflowStateMachine("test")
        m.add_state(WorkflowState(name="start", is_initial=True))
        m.add_state(WorkflowState(name="middle"))
        m.add_state(WorkflowState(name="end", is_terminal=True))
        m.add_transition(WorkflowTransition(from_state="start", to_state="middle", action="go"))
        m.add_transition(WorkflowTransition(from_state="middle", to_state="end", action="finish"))
        return m

    def test_step(self):
        m = self._build_machine()
        assert m.current_state == "start"
        assert m.step("go", {})
        assert m.current_state == "middle"

    def test_invalid_transition(self):
        m = self._build_machine()
        assert not m.step("finish", {})

    def test_rollback(self):
        m = self._build_machine()
        m.step("go", {})
        m.rollback()
        assert m.current_state == "start"

    def test_precondition_pass(self):
        m = WorkflowStateMachine("test")
        m.add_state(WorkflowState(name="a", is_initial=True))
        m.add_state(WorkflowState(name="b"))
        m.add_transition(WorkflowTransition(from_state="a", to_state="b", action="go",
                                             preconditions=["authenticated"]))
        assert m.step("go", {"authenticated": True})

    def test_precondition_fail(self):
        m = WorkflowStateMachine("test")
        m.add_state(WorkflowState(name="a", is_initial=True))
        m.add_state(WorkflowState(name="b"))
        m.add_transition(WorkflowTransition(from_state="a", to_state="b", action="go",
                                             preconditions=["authenticated"]))
        assert not m.step("go", {})

    def test_get_valid_actions(self):
        m = self._build_machine()
        assert m.get_valid_actions() == ["go"]

    def test_is_terminal(self):
        m = self._build_machine()
        assert not m.is_terminal()
        m.step("go", {})
        m.step("finish", {})
        assert m.is_terminal()


# ── Phase 8.2: Concurrency Engine ──

from core.workflows.concurrency_engine import ConcurrencyEngine, ConcurrencyExperiment


class TestConcurrencyEngine:
    def test_budget_enforcement(self):
        engine = ConcurrencyEngine(impact_budget=1)
        assert engine.experiments_run == 0

    def test_configurable_fanout(self):
        engine = ConcurrencyEngine(max_fanout=5)
        assert engine.max_fanout == 5

    def test_analyze_results(self):
        engine = ConcurrencyEngine()
        results = [{"status": "success"}, {"status": "success"}, {"status": "fail"}]
        analysis = engine.analyze_results(results)
        assert analysis["race_condition_likely"] is True
        assert analysis["successes"] == 2

    @pytest.mark.asyncio
    async def test_execute_race(self):
        engine = ConcurrencyEngine(impact_budget=10, max_fanout=3)
        async def dummy(**kwargs):
            return {"status": "success"}
        exp = ConcurrencyExperiment(experiment_id="e1", target_resource="/api/transfer",
                                     action="POST", workers=3)
        results = await engine.execute_race_condition_test(exp, dummy)
        assert len(results) == 3
        assert engine.experiments_run == 1


# ── Phase 9.1: Hypothesis Ledger ──

from core.coverage.hypothesis_ledger import HypothesisLedger, infer_vuln_class


class TestHypothesisLedger:
    def test_new_hypothesis(self):
        ledger = HypothesisLedger()
        ok, reason = ledger.should_run("https://t.com/api", "SQL injection on id param")
        assert ok
        assert reason == "new"

    def test_terminal_state(self):
        ledger = HypothesisLedger()
        ledger.record_experiment_outcome("https://t.com/api", "SQL injection", "CONFIRMED", 1.0)
        ok, reason = ledger.should_run("https://t.com/api", "SQL injection")
        assert not ok
        assert "CONFIRMED" in reason

    def test_attempt_budget(self):
        ledger = HypothesisLedger(max_attempts=2)
        ledger.record_experiment_outcome("https://t.com/api", "XSS test", "OPEN", 0.1)
        ledger.record_experiment_outcome("https://t.com/api", "XSS test", "OPEN", 0.1)
        ok, reason = ledger.should_run("https://t.com/api", "XSS test")
        assert not ok
        assert "NEGATIVE" in reason

    def test_infer_vuln_class(self):
        assert infer_vuln_class("SQL injection on login") == "SQLI"
        assert infer_vuln_class("Cross-site scripting via param") == "XSS"
        assert infer_vuln_class("SSRF via url parameter") == "SSRF"
        assert infer_vuln_class("unknown test") == "GENERIC"

    def test_snapshot(self):
        ledger = HypothesisLedger()
        ledger.record_hypothesis("https://t.com", "SQL injection", ["auth"], "error msg")
        snap = ledger.snapshot()
        assert len(snap) == 1


# ── Phase 9.2: Typed Action Planner ──

from core.reasoning.typed_planner import TypedActionPlanner, TypedPlan, TypedAction, BLOCKED_TOOLS


class TestTypedActionPlanner:
    def test_blocks_shell(self):
        planner = TypedActionPlanner(ledger=HypothesisLedger())
        for tool in BLOCKED_TOOLS:
            plan = TypedPlan(hypothesis="t", prerequisites=[], actions=[TypedAction(tool, {}, "x")])
            assert not planner.validate_plan(plan)

    def test_allows_http_tool(self):
        planner = TypedActionPlanner(ledger=HypothesisLedger())
        plan = TypedPlan(hypothesis="t", prerequisites=[], actions=[TypedAction("http_request", {}, "x")])
        assert planner.validate_plan(plan)

    def test_allowlist_enforcement(self):
        planner = TypedActionPlanner(ledger=HypothesisLedger(), allowed_tools=frozenset({"nmap"}))
        ok = TypedPlan(hypothesis="t", prerequisites=[], actions=[TypedAction("nmap", {}, "x")])
        bad = TypedPlan(hypothesis="t", prerequisites=[], actions=[TypedAction("sqlmap", {}, "x")])
        assert planner.validate_plan(ok)
        assert not planner.validate_plan(bad)

    def test_submit_records_hypothesis(self):
        ledger = HypothesisLedger()
        planner = TypedActionPlanner(ledger=ledger)
        plan = TypedPlan(hypothesis="SQLI on /login", prerequisites=["auth"],
                          actions=[TypedAction("http_request", {"url": "/login"}, "error")])
        assert planner.submit_plan(plan, url="https://t.com/login")
        snap = ledger.snapshot()
        assert len(snap) == 1


# ── Phase 10.1: Evidence Graph ──

from core.evidence.evidence_graph import EvidenceGraph, EvidenceNode


class TestEvidenceGraph:
    def test_add_and_link(self):
        g = EvidenceGraph()
        req_id = g.add_node("request", {"url": "https://t.com", "method": "GET"})
        resp_id = g.add_node("response", {"status": 200})
        g.add_edge(req_id, resp_id, "received_response")
        assert len(g.nodes) == 2
        assert len(g.edges) == 1

    def test_integrity(self):
        g = EvidenceGraph()
        g.add_node("request", {"url": "https://t.com"})
        assert g.verify_integrity()

    def test_tamper_detection(self):
        g = EvidenceGraph()
        nid = g.add_node("request", {"url": "https://t.com"})
        g.nodes[nid].data["url"] = "https://evil.com"
        assert not g.verify_integrity()

    def test_link_experiment(self):
        g = EvidenceGraph()
        req = g.add_node("request", {})
        resp = g.add_node("response", {})
        ident = g.add_node("identity", {"role": "admin"})
        exp = g.link_experiment("exp-1", req, resp, ident)
        assert len(g.edges) == 3

    def test_export(self):
        g = EvidenceGraph()
        g.add_node("test", {"key": "val"})
        export = g.export()
        assert len(export["nodes"]) == 1
        assert export["nodes"][0]["type"] == "test"


# ── Phase 10.2: Oracle Engine ──

from core.evidence.oracle import OracleEngine, OracleResult, get_oracle_engine


class TestOracleEngine:
    def test_all_14_classes(self):
        engine = OracleEngine()
        assert len(engine.supported_classes()) == 14

    def test_unknown_class_inconclusive(self):
        engine = OracleEngine()
        result = engine.evaluate("UNKNOWN_CLASS", {})
        assert not result.is_vulnerable
        assert "Inconclusive" in result.reasoning

    def test_sqli_error_detection(self):
        engine = OracleEngine()
        result = engine.evaluate("SQLI", {"response_body": "SQL syntax error near 'test'"})
        assert result.is_vulnerable
        assert result.confidence >= 0.9

    def test_sqli_timing(self):
        engine = OracleEngine()
        result = engine.evaluate("SQLI", {"response_time_ms": 6000})
        assert result.is_vulnerable

    def test_sqli_configurable_threshold(self):
        engine = OracleEngine(config={"sqli_time_threshold_ms": 10000})
        result = engine.evaluate("SQLI", {"response_time_ms": 6000})
        assert not result.is_vulnerable

    def test_xss_dom_alert(self):
        engine = OracleEngine()
        result = engine.evaluate("XSS", {"dom_events": [{"type": "alert", "evidence_id": "e1"}]})
        assert result.is_vulnerable
        assert result.confidence == 1.0

    def test_xss_reflection(self):
        engine = OracleEngine()
        result = engine.evaluate("XSS", {"response_body": "<script>alert(1)</script>",
                                          "payload": "<script>alert(1)</script>"})
        assert result.is_vulnerable
        assert result.requires_manual_confirmation

    def test_ssrf_oob(self):
        engine = OracleEngine()
        result = engine.evaluate("SSRF", {"oob_interactions": [{"type": "dns", "evidence_id": "e1"}]})
        assert result.is_vulnerable

    def test_auth_bypass(self):
        engine = OracleEngine()
        result = engine.evaluate("AUTH_BYPASS", {
            "status_code": 200, "requires_auth": True, "session_role": "anonymous",
        })
        assert result.is_vulnerable

    def test_csrf(self):
        engine = OracleEngine()
        result = engine.evaluate("CSRF", {"state_changed_without_token": True})
        assert result.is_vulnerable

    def test_register_custom_oracle(self):
        engine = OracleEngine()
        engine.register("CUSTOM", lambda ev, cfg: OracleResult(True, 0.5, [], "custom"))
        result = engine.evaluate("CUSTOM", {})
        assert result.is_vulnerable

    def test_singleton(self):
        from core.evidence.oracle import _engine_lock, _engine_instance
        import core.evidence.oracle as omod
        omod._engine_instance = None
        e1 = get_oracle_engine()
        e2 = get_oracle_engine()
        assert e1 is e2

    def test_redirect_module(self):
        from core.verification.oracle_engine import OracleEngine as OE2
        assert OE2 is OracleEngine
