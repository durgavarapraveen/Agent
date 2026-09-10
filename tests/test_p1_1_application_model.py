import pytest
import threading
from unittest.mock import MagicMock, patch

from core.intelligence.application_model import (
    ApplicationModel, ModelEvent,
    HostRecord, ServiceInfo, RoleInfo, Resource,
    StateTransition, TrustBoundary, DataFlow, SinkInfo,
    DependencyInfo, CacheInfo, QueueInfo, SecurityInvariant,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    ApplicationModel.reset_for_tests()
    yield
    ApplicationModel.reset_for_tests()


# ═══════════════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════════════

class TestSingleton:
    def test_get_returns_same_instance(self):
        a = ApplicationModel.get("https://target.com")
        b = ApplicationModel.get()
        assert a is b

    def test_reset_creates_new(self):
        a = ApplicationModel.get("t1")
        ApplicationModel.reset_for_tests()
        b = ApplicationModel.get("t2")
        assert a is not b
        assert b.target == "t2"


# ═══════════════════════════════════════════════════════════════════════
# Hosts
# ═══════════════════════════════════════════════════════════════════════

class TestHosts:
    def test_add_host(self):
        m = ApplicationModel("https://example.com")
        rec = m.add_host("example.com", ip_addresses=["1.2.3.4"])
        assert rec.hostname == "example.com"
        assert "1.2.3.4" in rec.ip_addresses
        assert len(m.hosts) == 1

    def test_dedup_host(self):
        m = ApplicationModel()
        m.add_host("h1.com", ip_addresses=["1.1.1.1"])
        m.add_host("h1.com", ip_addresses=["2.2.2.2"])
        assert len(m.hosts) == 1
        assert "2.2.2.2" in m.hosts["h1.com"].ip_addresses

    def test_case_insensitive(self):
        m = ApplicationModel()
        m.add_host("Example.COM")
        assert "example.com" in m.hosts


# ═══════════════════════════════════════════════════════════════════════
# Services
# ═══════════════════════════════════════════════════════════════════════

class TestServices:
    def test_add_service(self):
        m = ApplicationModel()
        svc = m.add_service("h1", 443, service_name="https")
        assert svc.port == 443
        assert svc.key == "h1:443/tcp"

    def test_dedup_service_updates_banner(self):
        m = ApplicationModel()
        m.add_service("h1", 80)
        m.add_service("h1", 80, banner="nginx/1.25")
        assert len(m.services) == 1
        assert m.services["h1:80/tcp"].banner == "nginx/1.25"

    def test_services_for_host(self):
        m = ApplicationModel()
        m.add_service("h1", 80)
        m.add_service("h1", 443)
        m.add_service("h2", 8080)
        assert len(m.services_for_host("h1")) == 2


# ═══════════════════════════════════════════════════════════════════════
# Technologies
# ═══════════════════════════════════════════════════════════════════════

class TestTechnologies:
    def test_add_technology(self):
        m = ApplicationModel()
        m.add_technology("h1", "nginx", "1.25", "web_server")
        assert len(m.technologies["h1"]) == 1

    def test_dedup_updates_version(self):
        m = ApplicationModel()
        m.add_technology("h1", "nginx")
        m.add_technology("h1", "Nginx", "1.25")
        assert len(m.technologies["h1"]) == 1
        assert m.technologies["h1"][0]["version"] == "1.25"


# ═══════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════

class TestEndpoints:
    def test_add_endpoint(self):
        m = ApplicationModel()
        assert m.add_endpoint("ep1", {"url": "/api/users"}) is True
        assert m.add_endpoint("ep1", {"url": "/api/users"}) is False
        assert len(m.endpoints) == 1

    def test_add_parameter(self):
        m = ApplicationModel()
        m.add_parameter("ep1", {"name": "id", "type": "query"})
        m.add_parameter("ep1", {"name": "id", "type": "query"})
        assert len(m.parameters["ep1"]) == 1

    def test_add_schema(self):
        m = ApplicationModel()
        m.add_schema("ep1", {"type": "object", "properties": {"id": {"type": "integer"}}})
        assert "ep1" in m.schemas


# ═══════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════

class TestIdentitiesRolesSessions:
    def test_add_identity(self):
        m = ApplicationModel()
        m.add_identity("admin", {"username": "admin", "role": "admin"})
        assert "admin" in m.identities

    def test_add_role(self):
        m = ApplicationModel()
        m.add_role(RoleInfo(role_id="r1", name="admin", privilege_level=10,
                            permissions=["read", "write", "delete"]))
        assert m.roles["r1"].privilege_level == 10

    def test_add_session(self):
        m = ApplicationModel()
        m.add_session("s1", {"identity_id": "admin", "token": "abc"})
        assert "s1" in m.sessions


# ═══════════════════════════════════════════════════════════════════════
# Resources
# ═══════════════════════════════════════════════════════════════════════

class TestResources:
    def test_add_resource(self):
        m = ApplicationModel()
        m.add_resource(Resource(
            resource_id="r1", resource_type="user_profile",
            name="User Profile", owner_identity_id="admin",
            endpoint_ids=["ep1"], access_control="rbac",
        ))
        assert m.resources["r1"].resource_type == "user_profile"


# ═══════════════════════════════════════════════════════════════════════
# Workflows + State Transitions
# ═══════════════════════════════════════════════════════════════════════

class TestWorkflowsTransitions:
    def test_add_workflow(self):
        m = ApplicationModel()
        m.add_workflow("wf1", {"name": "login_flow", "steps": ["GET /login", "POST /login"]})
        assert "wf1" in m.workflows

    def test_add_state_transition(self):
        m = ApplicationModel()
        t = StateTransition(
            from_state="unauthenticated", to_state="authenticated",
            trigger="POST /login", endpoint_id="ep_login",
            requires_auth=False, side_effects=["set_cookie"],
        )
        m.add_state_transition(t)
        assert t.key in m.state_transitions


# ═══════════════════════════════════════════════════════════════════════
# Trust Boundaries
# ═══════════════════════════════════════════════════════════════════════

class TestTrustBoundaries:
    def test_add_boundary(self):
        m = ApplicationModel()
        m.add_trust_boundary(TrustBoundary(
            boundary_id="b1", name="Auth boundary",
            boundary_type="auth",
            from_zone="public", to_zone="authenticated",
            crossing_endpoints=["ep1", "ep2"],
            controls=["jwt_validation"],
        ))
        assert len(m.endpoints_crossing_boundary("b1")) == 2

    def test_missing_boundary(self):
        m = ApplicationModel()
        assert m.endpoints_crossing_boundary("nonexistent") == []


# ═══════════════════════════════════════════════════════════════════════
# Data Flows
# ═══════════════════════════════════════════════════════════════════════

class TestDataFlows:
    def test_add_flow(self):
        m = ApplicationModel()
        m.add_trust_boundary(TrustBoundary(
            boundary_id="b1", name="TLS", boundary_type="network"))
        m.add_data_flow(DataFlow(
            flow_id="df1", name="user_data_to_db",
            source_component="api", destination_component="postgres",
            data_type="PII", classification="sensitive",
            crosses_boundary="b1",
        ))
        assert len(m.flows_crossing_boundary("b1")) == 1

    def test_no_flows(self):
        m = ApplicationModel()
        assert m.flows_crossing_boundary("b1") == []


# ═══════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════

class TestSinks:
    def test_client_sink(self):
        m = ApplicationModel()
        m.add_client_sink(SinkInfo(
            sink_id="cs1", sink_type="xss",
            location="/search", endpoint_id="ep_search",
            parameter_name="q", context="innerHTML",
        ))
        sinks = m.sinks_for_endpoint("ep_search")
        assert len(sinks["client"]) == 1
        assert sinks["client"][0].sink_type == "xss"

    def test_server_sink(self):
        m = ApplicationModel()
        m.add_server_sink(SinkInfo(
            sink_id="ss1", sink_type="sql",
            location="/api/users", endpoint_id="ep_users",
            parameter_name="id",
        ))
        sinks = m.sinks_for_endpoint("ep_users")
        assert len(sinks["server"]) == 1

    def test_sinks_for_unknown_endpoint(self):
        m = ApplicationModel()
        sinks = m.sinks_for_endpoint("nope")
        assert sinks == {"client": [], "server": []}


# ═══════════════════════════════════════════════════════════════════════
# Dependencies
# ═══════════════════════════════════════════════════════════════════════

class TestDependencies:
    def test_add_dependency(self):
        m = ApplicationModel()
        m.add_dependency(DependencyInfo(
            dep_id="stripe", name="Stripe API",
            dep_type="api", url="https://api.stripe.com",
        ))
        assert m.dependencies["stripe"].dep_type == "api"


# ═══════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════

class TestCachesQueues:
    def test_add_cache(self):
        m = ApplicationModel()
        m.add_cache(CacheInfo(
            cache_id="c1", cache_type="cdn", location="cloudflare",
            headers_observed={"cf-cache-status": "HIT"},
        ))
        assert m.caches["c1"].cache_type == "cdn"

    def test_add_queue(self):
        m = ApplicationModel()
        m.add_queue(QueueInfo(
            queue_id="q1", queue_type="webhook",
            name="payment_webhook", endpoint_ids=["ep_webhook"],
        ))
        assert m.queues["q1"].queue_type == "webhook"


# ═══════════════════════════════════════════════════════════════════════
# Security Invariants
# ═══════════════════════════════════════════════════════════════════════

class TestSecurityInvariants:
    def test_add_invariant(self):
        m = ApplicationModel()
        m.add_invariant(SecurityInvariant(
            invariant_id="inv1",
            description="All admin endpoints require authentication",
            invariant_type="auth",
            endpoint_ids=["ep_admin"],
        ))
        assert m.security_invariants["inv1"].status == "active"

    def test_violate_invariant(self):
        m = ApplicationModel()
        m.add_invariant(SecurityInvariant(
            invariant_id="inv1",
            description="No unauthenticated admin access",
            invariant_type="auth",
        ))
        m.violate_invariant("inv1", {"endpoint": "ep_admin", "evidence": "200 without token"})
        inv = m.security_invariants["inv1"]
        assert inv.status == "violated"
        assert len(inv.violations) == 1
        assert "timestamp" in inv.violations[0]

    def test_check_invariants(self):
        m = ApplicationModel()
        m.add_invariant(SecurityInvariant(invariant_id="i1", description="a", invariant_type="auth"))
        m.add_invariant(SecurityInvariant(invariant_id="i2", description="b", invariant_type="access"))
        m.violate_invariant("i2", {"reason": "bypass"})
        results = m.check_invariants()
        statuses = dict(results)
        assert statuses["i1"] == "active"
        assert statuses["i2"] == "violated"

    def test_violate_nonexistent(self):
        m = ApplicationModel()
        m.violate_invariant("nope", {})  # no error


# ═══════════════════════════════════════════════════════════════════════
# Events
# ═══════════════════════════════════════════════════════════════════════

class TestEvents:
    def test_listener_called(self):
        m = ApplicationModel()
        events = []
        m.on(ModelEvent.HOST_ADDED, lambda e, k, d: events.append((e, k)))
        m.add_host("test.com")
        assert len(events) == 1
        assert events[0] == (ModelEvent.HOST_ADDED, "test.com")

    def test_listener_not_called_on_dedup(self):
        m = ApplicationModel()
        events = []
        m.on(ModelEvent.HOST_ADDED, lambda e, k, d: events.append(k))
        m.add_host("test.com")
        m.add_host("test.com")
        assert len(events) == 1

    def test_invariant_violated_event(self):
        m = ApplicationModel()
        violations = []
        m.on(ModelEvent.INVARIANT_VIOLATED, lambda e, k, d: violations.append(k))
        m.add_invariant(SecurityInvariant(invariant_id="inv1", description="x", invariant_type="auth"))
        m.violate_invariant("inv1", {"detail": "bypass"})
        assert violations == ["inv1"]

    def test_bad_listener_doesnt_crash(self):
        m = ApplicationModel()
        m.on(ModelEvent.HOST_ADDED, lambda e, k, d: 1/0)
        m.add_host("test.com")  # should not raise
        assert "test.com" in m.hosts


# ═══════════════════════════════════════════════════════════════════════
# Hydration from SharedContextV2
# ═══════════════════════════════════════════════════════════════════════

class TestHydration:
    def test_hydrate_basic(self):
        ctx = MagicMock()
        ctx.target = "https://example.com"
        ctx.subdomains = ["api.example.com", "dev.example.com"]
        ctx.ips = ["10.0.0.1"]
        ctx.ports = [{"port": 80, "host": "example.com", "protocol": "tcp"}]
        ctx.technologies = {"example.com": ["nginx", "python"]}
        ctx.endpoints = {"ep1": {"url": "/api"}, "ep2": {"url": "/login"}}
        ctx.identities = {"admin": {"username": "admin"}}
        ctx.sessions = {"s1": {"token": "abc"}}
        ctx.external_dependencies = [{"host": "cdn.example.com", "url": "https://cdn.example.com"}]
        ctx.headers = {"example.com": {"cache-control": "max-age=300", "x-cache": "HIT"}}
        ctx.ssl_info = {"example.com": {"protocol": "TLSv1.3"}}

        m = ApplicationModel()
        m.hydrate_from_shared_context(ctx)

        assert len(m.hosts) >= 3  # example.com + 2 subdomains + 1 IP
        assert len(m.services) == 1
        assert len(m.endpoints) == 2
        assert len(m.identities) == 1
        assert len(m.dependencies) == 1
        assert len(m.caches) == 1
        assert len(m.trust_boundaries) == 1

    def test_hydrate_empty_ctx(self):
        ctx = MagicMock(spec=[])
        ctx.target = ""
        m = ApplicationModel()
        m.hydrate_from_shared_context(ctx)
        assert len(m.hosts) == 0

    def test_hydrate_technologies_dict_format(self):
        ctx = MagicMock()
        ctx.target = "https://t.com"
        ctx.subdomains = []
        ctx.ips = []
        ctx.ports = []
        ctx.technologies = {"t.com": [{"name": "Django", "version": "4.2"}]}
        ctx.endpoints = {}
        ctx.identities = {}
        ctx.sessions = {}
        ctx.external_dependencies = []
        ctx.headers = {}
        ctx.ssl_info = {}

        m = ApplicationModel()
        m.hydrate_from_shared_context(ctx)
        assert m.technologies["t.com"][0]["name"] == "Django"
        assert m.technologies["t.com"][0]["version"] == "4.2"


# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════

class TestSummary:
    def test_summary_structure(self):
        m = ApplicationModel("https://t.com")
        m.add_host("t.com")
        m.add_service("t.com", 443)
        m.add_endpoint("ep1", {})
        m.add_invariant(SecurityInvariant(invariant_id="i1", description="x", invariant_type="auth"))
        m.violate_invariant("i1", {})

        s = m.summary()
        assert s["target"] == "https://t.com"
        assert s["hosts"] == 1
        assert s["services"] == 1
        assert s["endpoints"] == 1
        assert s["invariants_violated"] == 1

    def test_attack_surface_summary_keys(self):
        m = ApplicationModel()
        s = m.get_attack_surface_summary()
        expected_keys = {
            "hosts", "services", "technologies", "endpoints", "parameters",
            "schemas", "identities", "roles", "sessions", "resources",
            "workflows", "state_transitions", "trust_boundaries", "data_flows",
            "client_sinks", "server_sinks", "dependencies", "caches", "queues",
            "security_invariants",
        }
        assert set(s.keys()) == expected_keys


# ═══════════════════════════════════════════════════════════════════════
# Thread Safety
# ═══════════════════════════════════════════════════════════════════════

class TestThreadSafety:
    def test_concurrent_adds(self):
        m = ApplicationModel()
        errors = []

        def add_hosts(start):
            try:
                for i in range(100):
                    m.add_host(f"h{start + i}.com")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_hosts, args=(i * 100,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(m.hosts) == 400

    def test_concurrent_services(self):
        m = ApplicationModel()
        errors = []

        def add_svcs(start):
            try:
                for i in range(50):
                    m.add_service("h1", start + i)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_svcs, args=(i * 50,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(m.services) == 200


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
