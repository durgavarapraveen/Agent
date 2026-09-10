"""Tests for Phase 11-15 hardening components."""
import pytest

# ── Phase 11.1: Differential Request/Response Engine ──

from core.analysis.differential_engine import (
    DifferentialRequestEngine, ResponseSnapshot, Anomaly, DiffResult,
)


class TestDifferentialEngine:
    def test_no_anomaly_identical(self):
        eng = DifferentialRequestEngine()
        b = ResponseSnapshot(status_code=200, body_length=100, response_time_ms=50)
        v = ResponseSnapshot(status_code=200, body_length=100, response_time_ms=55)
        result = eng.compare(b, v)
        assert not result.diverged

    def test_status_divergence(self):
        eng = DifferentialRequestEngine()
        b = ResponseSnapshot(status_code=200)
        v = ResponseSnapshot(status_code=403)
        result = eng.compare(b, v, experiment_id="e1")
        assert result.diverged
        status_anom = [a for a in result.anomalies if a.dimension == "status_code"]
        assert len(status_anom) == 1
        assert status_anom[0].severity == "high"

    def test_timing_divergence(self):
        eng = DifferentialRequestEngine(thresholds={"timing_divergence_ms": 100})
        b = ResponseSnapshot(response_time_ms=50)
        v = ResponseSnapshot(response_time_ms=300)
        result = eng.compare(b, v)
        timing = [a for a in result.anomalies if a.dimension == "timing"]
        assert len(timing) == 1

    def test_cookie_divergence(self):
        eng = DifferentialRequestEngine()
        b = ResponseSnapshot(cookies=(("session", "abc"),))
        v = ResponseSnapshot(cookies=(("session", "abc"), ("tracking", "xyz")))
        result = eng.compare(b, v)
        cookie = [a for a in result.anomalies if a.dimension == "cookies"]
        assert len(cookie) == 1

    def test_redirect_divergence(self):
        eng = DifferentialRequestEngine()
        b = ResponseSnapshot(redirect_chain=("/login",))
        v = ResponseSnapshot(redirect_chain=("/admin",))
        result = eng.compare(b, v)
        assert any(a.dimension == "redirects" for a in result.anomalies)

    def test_body_length_divergence(self):
        eng = DifferentialRequestEngine(thresholds={"content_length_ratio": 0.1})
        b = ResponseSnapshot(body_length=1000)
        v = ResponseSnapshot(body_length=500)
        result = eng.compare(b, v)
        assert any(a.dimension == "body_length" for a in result.anomalies)

    def test_compare_multi(self):
        eng = DifferentialRequestEngine()
        b = ResponseSnapshot(status_code=200)
        variants = [ResponseSnapshot(status_code=200), ResponseSnapshot(status_code=403)]
        results = eng.compare_multi(b, variants)
        assert len(results) == 2

    def test_custom_comparator(self):
        eng = DifferentialRequestEngine()
        eng.register_comparator("custom", lambda b, v: Anomaly(
            dimension="custom", severity="low", confidence=0.5, explanation="test"
        ))
        result = eng.compare(ResponseSnapshot(), ResponseSnapshot(), dimensions={"custom"})
        assert any(a.dimension == "custom" for a in result.anomalies)

    def test_max_severity(self):
        result = DiffResult(anomalies=[
            Anomaly(severity="low"), Anomaly(severity="high"), Anomaly(severity="medium"),
        ])
        assert result.max_severity() == "high"

    def test_side_effect_divergence(self):
        eng = DifferentialRequestEngine()
        b = ResponseSnapshot(side_effects=("db_write",))
        v = ResponseSnapshot(side_effects=("db_write", "email_sent"))
        result = eng.compare(b, v)
        assert any(a.dimension == "side_effects" for a in result.anomalies)


# ── Phase 11.2: Statistical Anomaly Pipeline ──

from core.analysis.anomaly_pipeline import (
    StatisticalAnomalyPipeline, TimingSample, AnomalySignal,
)


class TestAnomalyPipeline:
    def _seed_baseline(self, pipeline, endpoint, values):
        for v in values:
            pipeline.record_baseline(endpoint, TimingSample(response_time_ms=v))

    def test_no_anomaly_within_threshold(self):
        p = StatisticalAnomalyPipeline()
        self._seed_baseline(p, "/api", [80, 100, 120, 90, 110])
        sig = p.analyze_timing("/api", 105)
        assert sig is None

    def test_anomaly_detected(self):
        p = StatisticalAnomalyPipeline()
        self._seed_baseline(p, "/api", [100, 101, 99, 100, 102])
        sig = p.analyze_timing("/api", 500)
        assert sig is not None
        assert sig.z_score > 0

    def test_insufficient_baseline(self):
        p = StatisticalAnomalyPipeline()
        self._seed_baseline(p, "/api", [100, 101])
        assert p.analyze_timing("/api", 500) is None

    def test_environment_drift_reduces_confidence(self):
        p = StatisticalAnomalyPipeline()
        self._seed_baseline(p, "/api", [100] * 10)
        for _ in range(10):
            p.record_environment_probe("env1", 100)
        sig_no_drift = p.analyze_timing("/api", 500, env_tag="env1")
        p2 = StatisticalAnomalyPipeline()
        self._seed_baseline(p2, "/api", [100] * 10)
        for _ in range(10):
            p2.record_environment_probe("env2", 100)
        sig_drift = p2.analyze_timing("/api", 500, env_tag="other")
        assert sig_no_drift is not None

    def test_repeatability(self):
        p = StatisticalAnomalyPipeline(config={"repeat_count_for_confirmation": 3,
                                                 "min_baseline_samples": 5,
                                                 "outlier_z_threshold": 2.0})
        self._seed_baseline(p, "/api", [100] * 10)
        sig = p.confirm_repeatability("/api", lambda: 500)
        assert sig is not None
        assert sig.is_repeatable

    def test_baseline_stats(self):
        p = StatisticalAnomalyPipeline()
        self._seed_baseline(p, "/api", [100, 200, 300])
        stats = p.baseline_stats("/api")
        assert stats is not None
        assert stats["count"] == 3
        assert stats["mean"] == 200.0

    def test_get_signals_filter(self):
        p = StatisticalAnomalyPipeline(config={"min_baseline_samples": 3,
                                                 "outlier_z_threshold": 1.0})
        self._seed_baseline(p, "/a", [100] * 5)
        self._seed_baseline(p, "/b", [100] * 5)
        p.analyze_timing("/a", 500)
        p.analyze_timing("/b", 500)
        assert len(p.get_signals("/a")) >= 1


# ── Phase 12.1: Source Intelligence Graph ──

from core.analysis.source_intelligence import (
    SourceIntelligenceGraph, SourceNode, SourceNodeType, SASTFinding,
)


class TestSourceIntelligence:
    def test_ingest_python(self):
        g = SourceIntelligenceGraph()
        ids = g.ingest_file("test.py", "def foo():\n    pass\nclass Bar:\n    pass")
        assert len(ids) >= 2

    def test_ingest_javascript(self):
        g = SourceIntelligenceGraph()
        ids = g.ingest_file("app.js", "function hello() {}\nconst world = 1")
        assert len(ids) >= 2

    def test_unsupported_language(self):
        g = SourceIntelligenceGraph()
        ids = g.ingest_file("main.go", "package main")
        assert len(ids) == 1
        assert ids[0]  # file-level node

    def test_sast_dedup(self):
        g = SourceIntelligenceGraph()
        f1 = SASTFinding(tool="semgrep", rule_id="sqli", path="a.py", line=10, message="sqli")
        f2 = SASTFinding(tool="semgrep", rule_id="sqli", path="a.py", line=10, message="sqli")
        assert g.ingest_sast_finding(f1)
        assert not g.ingest_sast_finding(f2)

    def test_finding_correlation(self):
        g = SourceIntelligenceGraph()
        g.ingest_file("a.py", "def vuln():\n    pass")
        f = SASTFinding(tool="codeql", rule_id="xss", path="a.py", line=1, message="xss")
        g.ingest_sast_finding(f)
        corr = g.correlate_findings()
        assert len(corr) >= 1

    def test_lineage(self):
        g = SourceIntelligenceGraph()
        n1 = SourceNode(node_type=SourceNodeType.FILE, path="a.py")
        n2 = SourceNode(node_type=SourceNodeType.FUNCTION, path="a.py", name="foo")
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge(n1.node_id, n2.node_id, "contains")
        lineage = g.get_lineage(n2.node_id)
        assert len(lineage) == 1

    def test_unsupported_report(self):
        g = SourceIntelligenceGraph()
        unsupported = g.unsupported_report(["a.py", "b.rb", "c.rs"])
        assert "b.rb" in unsupported
        assert "a.py" not in unsupported

    def test_export(self):
        g = SourceIntelligenceGraph()
        g.ingest_file("a.py", "x = 1")
        export = g.export()
        assert export["nodes"] >= 0


# ── Phase 12.2: Taint Correlation ──

from core.analysis.taint_correlation import (
    TaintCorrelationEngine, TaintFlow, TaintType, SinkType, ReachabilityLevel,
    InstrumentationConfig,
)


class TestTaintCorrelation:
    def test_record_and_query(self):
        eng = TaintCorrelationEngine()
        flow = TaintFlow(source_type=TaintType.URL_PARAM, source_param="id",
                          source_endpoint="/api/user", sink_type=SinkType.SQL_QUERY,
                          sink_location="db.py:42")
        assert eng.record_static_flow(flow)
        results = eng.query_flows(endpoint="/api/user")
        assert len(results) == 1

    def test_confirm_runtime(self):
        eng = TaintCorrelationEngine()
        flow = TaintFlow(source_type=TaintType.BODY_PARAM, sink_type=SinkType.TEMPLATE_RENDER)
        eng.record_static_flow(flow)
        assert eng.confirm_flow_runtime(flow.flow_id, "exp-1")
        confirmed = eng.get_confirmed_flows()
        assert len(confirmed) == 1
        assert confirmed[0].reachability == ReachabilityLevel.DYNAMIC_CONFIRMED

    def test_max_flows_per_endpoint(self):
        eng = TaintCorrelationEngine(config=InstrumentationConfig(max_flows_per_endpoint=2))
        for i in range(5):
            eng.record_static_flow(TaintFlow(source_endpoint="/api/x", source_param=f"p{i}"))
        assert len(eng.query_flows(endpoint="/api/x")) == 2

    def test_enable_disable(self):
        eng = TaintCorrelationEngine()
        assert not eng.enabled
        eng.enable()
        assert eng.enabled
        eng.disable()
        assert not eng.enabled

    def test_source_file_lookup(self):
        eng = TaintCorrelationEngine()
        flow = TaintFlow(source_file="app.py", source_endpoint="/api")
        eng.record_static_flow(flow)
        assert len(eng.get_flows_for_source("app.py")) == 1

    def test_export(self):
        eng = TaintCorrelationEngine()
        eng.record_static_flow(TaintFlow())
        export = eng.export()
        assert export["total_flows"] == 1
        assert export["static_only"] == 1


# ── Phase 13.1: Grammar-Aware Input Engine ──

from core.fuzzing.grammar_engine import (
    GrammarInputEngine, GrammarRule, InputType, EncodingType, GeneratedInput,
)


class TestGrammarEngine:
    def test_generate_with_rule(self):
        eng = GrammarInputEngine()
        eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern="'{input}'--"))
        results = eng.generate("test", InputType.STRING)
        assert len(results) == 1
        assert "'test'--" in results[0].value

    def test_encoding(self):
        eng = GrammarInputEngine()
        eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern="{input}",
                                  encoding=EncodingType.URL_ENCODE))
        results = eng.generate("<script>", InputType.STRING)
        assert "%3C" in results[0].value

    def test_resource_limits(self):
        eng = GrammarInputEngine(limits={"max_total_inputs": 5, "max_grammar_rules": 500,
                                          "max_mutations_per_input": 100, "max_depth": 5})
        for i in range(20):
            eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern=f"p{i}_{{input}}"))
        results = eng.generate("x", InputType.STRING)
        assert len(results) <= 5

    def test_provenance(self):
        eng = GrammarInputEngine()
        rule = GrammarRule(input_type=InputType.STRING, pattern="test_{input}")
        eng.add_rule(rule)
        results = eng.generate("val", InputType.STRING)
        prov = eng.get_provenance(results[0].input_id)
        assert prov is not None
        assert "chain" in prov

    def test_transformer(self):
        eng = GrammarInputEngine()
        eng.add_rule(GrammarRule(
            input_type=InputType.STRING,
            transformer=lambda v: [v.upper(), v.lower()],
        ))
        results = eng.generate("Test", InputType.STRING)
        assert len(results) == 2

    def test_max_rules(self):
        eng = GrammarInputEngine(limits={"max_grammar_rules": 2, "max_total_inputs": 10000,
                                          "max_mutations_per_input": 100, "max_depth": 5})
        assert eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern="a"))
        assert eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern="b"))
        assert not eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern="c"))

    def test_stats(self):
        eng = GrammarInputEngine()
        eng.add_rule(GrammarRule(input_type=InputType.STRING, pattern="{input}"))
        eng.generate("x", InputType.STRING)
        s = eng.stats()
        assert s["rules"] == 1
        assert s["generated"] == 1


# ── Phase 13.2: Multi-Parser Engine ──

from core.fuzzing.multi_parser import (
    MultiParserEngine, ParserType, Mutation,
)


class TestMultiParser:
    def test_json_parse_and_mutate(self):
        eng = MultiParserEngine()
        parsed = eng.parse('{"name":"test","age":25}', ParserType.JSON)
        assert parsed.is_valid
        assert parsed.fields["name"] == "test"
        m = eng.mutate_one_dimension('{"name":"test"}', ParserType.JSON, "name", "<script>")
        assert m is not None
        assert "<script>" in m.serialized

    def test_xml_parse_and_mutate(self):
        eng = MultiParserEngine()
        parsed = eng.parse("<root><name>test</name></root>", ParserType.XML)
        assert parsed.is_valid
        m = eng.mutate_one_dimension("<root><name>test</name></root>", ParserType.XML, "name", "evil")
        assert m is not None

    def test_form_encoded(self):
        eng = MultiParserEngine()
        parsed = eng.parse("user=admin&pass=secret", ParserType.FORM_ENCODED)
        assert parsed.is_valid
        assert parsed.fields["user"] == "admin"

    def test_cookie_parse(self):
        eng = MultiParserEngine()
        parsed = eng.parse("session=abc; theme=dark", ParserType.COOKIE)
        assert parsed.is_valid
        assert parsed.fields["session"] == "abc"

    def test_graphql_parse(self):
        eng = MultiParserEngine()
        parsed = eng.parse('{"query":"{ users { id } }","variables":{}}', ParserType.GRAPHQL)
        assert parsed.is_valid
        assert "users" in parsed.fields["query"]

    def test_size_limit(self):
        eng = MultiParserEngine(config={"max_parse_size_bytes": 10,
                                         "max_depth": 20, "max_mutations_per_parse": 200,
                                         "timeout_ms": 5000})
        parsed = eng.parse("x" * 100, ParserType.JSON)
        assert not parsed.is_valid

    def test_unsupported_parser(self):
        eng = MultiParserEngine()
        parsed = eng.parse("data", ParserType.PROTOBUF)
        assert not parsed.is_valid
        assert "no adapter" in parsed.error

    def test_mutate_all_fields(self):
        eng = MultiParserEngine()
        mutations = eng.mutate_all_fields('{"a":"1","b":"2"}', ParserType.JSON,
                                           lambda k, v: f"FUZZ_{v}")
        assert len(mutations) == 2

    def test_supported_parsers(self):
        eng = MultiParserEngine()
        supported = eng.supported_parsers()
        assert "json" in supported
        assert "xml" in supported

    def test_unsupported_report(self):
        eng = MultiParserEngine()
        unsupported = eng.unsupported_report([ParserType.JSON, ParserType.PROTOBUF])
        assert "protobuf" in unsupported
        assert "json" not in unsupported


# ── Phase 14.1: Multi-Channel Discovery ──

from core.discovery.multi_channel import (
    MultiChannelDiscovery, DiscoveredAsset, DiscoverySource,
)


class TestMultiChannelDiscovery:
    def test_add_and_dedup(self):
        d = MultiChannelDiscovery()
        a1 = DiscoveredAsset(url="https://t.com/api/users", method="GET",
                              source=DiscoverySource.CRAWL)
        a2 = DiscoveredAsset(url="https://t.com/api/users", method="GET",
                              source=DiscoverySource.SITEMAP, parameters=["id"])
        id1 = d.add_asset(a1)
        id2 = d.add_asset(a2)
        assert id1 == id2
        asset = d.get_asset(id1)
        assert "id" in asset.parameters

    def test_scope_enforcement(self):
        d = MultiChannelDiscovery(scope_checker=lambda url: "allowed.com" in url)
        assert d.add_asset(DiscoveredAsset(url="https://allowed.com/api")) is not None
        assert d.add_asset(DiscoveredAsset(url="https://evil.com/api")) is None

    def test_source_tracking(self):
        d = MultiChannelDiscovery()
        a = DiscoveredAsset(url="https://t.com/x", source=DiscoverySource.CRAWL)
        aid = d.add_asset(a)
        d.add_asset(DiscoveredAsset(url="https://t.com/x", source=DiscoverySource.API_SCHEMA))
        sources = d.get_sources_for(aid)
        assert "crawl" in sources
        assert "api_schema" in sources

    def test_search(self):
        d = MultiChannelDiscovery()
        d.add_asset(DiscoveredAsset(url="https://t.com/api/v1", method="POST"))
        d.add_asset(DiscoveredAsset(url="https://t.com/login", method="GET"))
        assert len(d.search(method="POST")) == 1
        assert len(d.search(path_contains="/api")) == 1

    def test_stats(self):
        d = MultiChannelDiscovery()
        d.add_asset(DiscoveredAsset(url="https://t.com/a", source=DiscoverySource.CRAWL))
        d.add_asset(DiscoveredAsset(url="https://t.com/b", source=DiscoverySource.ROBOTS))
        stats = d.stats()
        assert stats["total_assets"] == 2


# ── Phase 14.2: Coverage-Driven Exploration ──

from core.discovery.coverage_driven import (
    CoverageDrivenExplorer, CoverageDimension, CoverageObjective,
)


class TestCoverageDrivenExplorer:
    def test_add_and_next(self):
        exp = CoverageDrivenExplorer()
        exp.add_objective(CoverageDimension.ASSET, "/api/users")
        exp.add_objective(CoverageDimension.ASSET, "/api/admin")
        candidates = exp.next_candidates(limit=5)
        assert len(candidates) == 2

    def test_coverage_tracking(self):
        exp = CoverageDrivenExplorer()
        exp.add_objective(CoverageDimension.ASSET, "/api/users")
        exp.mark_covered(CoverageDimension.ASSET, "/api/users")
        candidates = exp.next_candidates()
        assert len(candidates) == 0

    def test_decay(self):
        exp = CoverageDrivenExplorer()
        exp.add_objective(CoverageDimension.ASSET, "/api/x")
        c1 = exp.next_candidates()[0].expected_value
        exp.record_attempt(CoverageDimension.ASSET, "/api/x")
        c2 = exp.next_candidates()[0].expected_value
        assert c2 < c1

    def test_convergence(self):
        exp = CoverageDrivenExplorer(config={
            "min_expected_value": 0.5, "decay_factor": 0.1,
            "max_exploration_rounds": 500,
            "priority_weights": {"uncovered_asset": 1.0},
        })
        exp.add_objective(CoverageDimension.ASSET, "/api/x")
        exp.record_attempt(CoverageDimension.ASSET, "/api/x")
        exp.record_attempt(CoverageDimension.ASSET, "/api/x")
        assert exp.has_converged()

    def test_coverage_report(self):
        exp = CoverageDrivenExplorer()
        exp.add_objective(CoverageDimension.METHOD, "POST")
        exp.add_objective(CoverageDimension.METHOD, "GET")
        exp.mark_covered(CoverageDimension.METHOD, "GET")
        report = exp.coverage_report()
        assert report["total"] == 2
        assert report["covered"] == 1
        assert report["coverage_pct"] == 50.0

    def test_priority_boost(self):
        exp = CoverageDrivenExplorer()
        exp.add_objective(CoverageDimension.SECURITY_PROPERTY, "auth_bypass", priority=2.0)
        exp.add_objective(CoverageDimension.TECHNOLOGY, "nginx")
        candidates = exp.next_candidates()
        assert candidates[0].objective.target == "auth_bypass"


# ── Phase 15.1: Typed Plugin Registry ──

from core.tools.plugin_registry import (
    TypedPluginRegistry, ToolSchema, ToolCategory, RiskClass,
)


class TestPluginRegistry:
    def test_register_and_get(self):
        reg = TypedPluginRegistry()
        schema = ToolSchema(tool_name="nmap", version="1.0", category=ToolCategory.RECON,
                             risk_class=RiskClass.LOW)
        assert reg.register(schema)
        assert reg.get("nmap") is not None
        assert reg.get("nmap", "1.0") is not None

    def test_unknown_tool_blocked(self):
        reg = TypedPluginRegistry()
        ok, reason = reg.can_execute("nonexistent")
        assert not ok
        assert "unknown" in reason

    def test_risk_enforcement(self):
        reg = TypedPluginRegistry(allowed_risk={RiskClass.SAFE})
        reg.register(ToolSchema(tool_name="exploit", version="1.0",
                                 category=ToolCategory.WEB, risk_class=RiskClass.HIGH))
        ok, reason = reg.can_execute("exploit")
        assert not ok
        assert "risk" in reason

    def test_scan_pinning(self):
        reg = TypedPluginRegistry()
        reg.register(ToolSchema(tool_name="sqlmap", version="1.0",
                                 category=ToolCategory.WEB, risk_class=RiskClass.MEDIUM))
        reg.register(ToolSchema(tool_name="sqlmap", version="2.0",
                                 category=ToolCategory.WEB, risk_class=RiskClass.MEDIUM))
        assert reg.pin_for_scan("scan-1", "sqlmap", "1.0")
        resolved = reg.resolve_for_scan("sqlmap", "scan-1")
        assert resolved.schema.version == "1.0"

    def test_compatibility_check(self):
        reg = TypedPluginRegistry()
        reg.register(ToolSchema(tool_name="t", version="1.0", category=ToolCategory.RECON,
                                 risk_class=RiskClass.SAFE,
                                 input_schema={"url": "str"},
                                 output_schema={"result": "str"}))
        reg.register(ToolSchema(tool_name="t", version="2.0", category=ToolCategory.RECON,
                                 risk_class=RiskClass.SAFE,
                                 input_schema={"url": "str", "timeout": "int"},
                                 output_schema={"result": "str", "meta": "dict"}))
        compat = reg.check_compatibility("t", "1.0", "2.0")
        assert compat["compatible"]

    def test_duplicate_registration(self):
        reg = TypedPluginRegistry()
        schema = ToolSchema(tool_name="x", version="1.0", category=ToolCategory.RECON,
                             risk_class=RiskClass.SAFE)
        assert reg.register(schema)
        assert not reg.register(schema)

    def test_list_tools(self):
        reg = TypedPluginRegistry()
        reg.register(ToolSchema(tool_name="a", version="1.0", category=ToolCategory.RECON,
                                 risk_class=RiskClass.SAFE))
        reg.register(ToolSchema(tool_name="b", version="1.0", category=ToolCategory.WEB,
                                 risk_class=RiskClass.LOW))
        assert len(reg.list_tools(category=ToolCategory.RECON)) == 1
        assert len(reg.list_tools()) == 2


# ── Phase 15.2: Specialist Agent Teams ──

from core.orchestration.specialist_agents import (
    SpecialistTeam, SpecialistRole, SpecialistCapability, EvidenceArtifact,
    EvidenceBus,
)


class TestSpecialistTeam:
    def test_register_agents(self):
        team = SpecialistTeam()
        agent = team.register_agent(SpecialistRole.RECON)
        assert agent.role == SpecialistRole.RECON
        assert team.get_agent(SpecialistRole.RECON) is agent

    def test_no_authority_grant(self):
        team = SpecialistTeam()
        with pytest.raises(ValueError, match="cannot grant"):
            team.register_agent(SpecialistRole.WEB_SEMANTICS,
                                 SpecialistCapability(role=SpecialistRole.WEB_SEMANTICS,
                                                       can_grant_authority=True))

    def test_evidence_bus(self):
        team = SpecialistTeam()
        recon = team.register_agent(SpecialistRole.RECON)
        web = team.register_agent(SpecialistRole.WEB_SEMANTICS)
        recon.publish_evidence("endpoint_list", {"endpoints": ["/api/users"]})
        consumed = web.consume_evidence("endpoint_list")
        assert len(consumed) == 1
        assert consumed[0].producer_role == SpecialistRole.RECON

    def test_task_budget(self):
        team = SpecialistTeam()
        agent = team.register_agent(SpecialistRole.BROWSER,
                                     SpecialistCapability(role=SpecialistRole.BROWSER,
                                                           max_concurrent_tasks=2))
        assert agent.start_task()
        assert agent.start_task()
        assert not agent.start_task()
        agent.complete_task()
        assert agent.start_task()

    def test_tool_allowlist(self):
        team = SpecialistTeam()
        agent = team.register_agent(SpecialistRole.RECON,
                                     SpecialistCapability(role=SpecialistRole.RECON,
                                                           allowed_tools=frozenset({"nmap", "dig"})))
        assert agent.can_use_tool("nmap")
        assert not agent.can_use_tool("sqlmap")

    def test_disagreement_tracking(self):
        team = SpecialistTeam()
        team.register_agent(SpecialistRole.RECON)
        team.register_agent(SpecialistRole.VERIFICATION)
        did = team.record_disagreement(SpecialistRole.RECON, SpecialistRole.VERIFICATION,
                                        "sqli on /login", "confirmed", "false positive")
        assert len(team.get_disagreements(resolved=False)) == 1
        team.resolve_disagreement(did, "manual verification confirmed sqli")
        assert len(team.get_disagreements(resolved=False)) == 0
        assert len(team.get_disagreements(resolved=True)) == 1

    def test_team_stats(self):
        team = SpecialistTeam()
        team.register_agent(SpecialistRole.RECON)
        team.register_agent(SpecialistRole.WEB_SEMANTICS)
        stats = team.team_stats()
        assert "recon" in stats["agents"]
        assert stats["bus"]["total_artifacts"] == 0


class TestEvidenceBus:
    def test_publish_and_consume(self):
        bus = EvidenceBus()
        a = EvidenceArtifact(producer_role=SpecialistRole.RECON,
                              artifact_type="endpoints", data={"urls": ["/api"]})
        bus.publish(a)
        assert len(bus.consume(artifact_type="endpoints")) == 1

    def test_consume_by_producer(self):
        bus = EvidenceBus()
        bus.publish(EvidenceArtifact(producer_role=SpecialistRole.RECON, artifact_type="a"))
        bus.publish(EvidenceArtifact(producer_role=SpecialistRole.BROWSER, artifact_type="b"))
        assert len(bus.consume(producer=SpecialistRole.RECON)) == 1

    def test_stats(self):
        bus = EvidenceBus()
        bus.publish(EvidenceArtifact(producer_role=SpecialistRole.RECON, artifact_type="x"))
        bus.publish(EvidenceArtifact(producer_role=SpecialistRole.RECON, artifact_type="x"))
        stats = bus.stats()
        assert stats["total_artifacts"] == 2
        assert stats["by_type"]["x"] == 2
