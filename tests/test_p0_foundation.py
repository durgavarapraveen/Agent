import unittest

from core.security.security_context import SecurityContext
from core.security.capability_registry import CapabilityRegistry, CapabilityDefinition
from core.security.authorization_service import AuthorizationService, AuthorizationPolicy
from core.reasoning.reasoning_engine import ReasoningEngine


class DummyExecutor:
    pass


class TestSecurityContext(unittest.TestCase):

    def test_security_context_creation(self):
        ctx = SecurityContext(target="example.com", scope=["*.example.com"])
        self.assertEqual(ctx.target, "example.com")
        self.assertEqual(ctx.scope, ["*.example.com"])
        self.assertIsInstance(ctx.identities, dict)
        self.assertIsInstance(ctx.endpoints, dict)
        self.assertIsInstance(ctx.findings, dict)
        self.assertIsInstance(ctx.experiments, dict)
        self.assertIsInstance(ctx.coverage_state, dict)

    def test_security_context_scope_check(self):
        ctx = SecurityContext(target="example.com", scope=["*.example.com", "api.test.io"])
        self.assertTrue(ctx.is_in_scope("sub.example.com"))
        self.assertTrue(ctx.is_in_scope("deep.sub.example.com"))
        self.assertTrue(ctx.is_in_scope("example.com"))
        self.assertTrue(ctx.is_in_scope("api.test.io"))
        self.assertFalse(ctx.is_in_scope("evil.com"))
        self.assertFalse(ctx.is_in_scope("notexample.com"))


class TestCapabilityRegistry(unittest.TestCase):

    def test_capability_registry_registration(self):
        reg = CapabilityRegistry()
        defn = CapabilityDefinition(name="nmap", executor_class=DummyExecutor)
        reg.register(defn)
        self.assertTrue(reg.exists("nmap"))
        self.assertIn("nmap", reg.list_capabilities())
        self.assertEqual(reg.get_definition("nmap"), defn)

    def test_capability_registry_resolve_returns_executor_class(self):
        reg = CapabilityRegistry()
        reg.register(CapabilityDefinition(name="nmap", executor_class=DummyExecutor))
        self.assertIs(reg.resolve("nmap"), DummyExecutor)

    def test_capability_registry_reject_unknown_returns_none(self):
        reg = CapabilityRegistry()
        self.assertIsNone(reg.resolve("nonexistent"))
        self.assertFalse(reg.exists("nonexistent"))
        self.assertIsNone(reg.get_definition("nonexistent"))


class TestAuthorizationService(unittest.TestCase):

    def _make_service(self):
        svc = AuthorizationService()
        svc.register_policy(AuthorizationPolicy(
            target="juice-shop",
            allowed_identities=["admin", "tester"],
            allowed_actions=["scan", "fuzz", "enumerate"],
            blocked_patterns=[r"/admin", r"/internal"],
        ))
        return svc

    def test_authorization_service_allows_authorized(self):
        svc = self._make_service()
        self.assertTrue(svc.check_authorized("juice-shop", "tester", "scan"))

    def test_authorization_service_blocks_blocked_patterns(self):
        svc = self._make_service()
        self.assertFalse(svc.check_authorized("juice-shop", "admin", "/admin/delete"))
        self.assertFalse(svc.check_authorized("juice-shop", "tester", "/internal/secrets"))

    def test_authorization_service_rejects_unauthorized_identity(self):
        svc = self._make_service()
        self.assertFalse(svc.check_authorized("juice-shop", "stranger", "scan"))


class TestReasoningEngine(unittest.TestCase):

    def test_reasoning_engine_has_no_execute_methods(self):
        engine = ReasoningEngine()
        self.assertFalse(hasattr(engine, "execute_tool"))
        self.assertFalse(hasattr(engine, "modify_task_state"))
        self.assertFalse(hasattr(engine, "mark_finding_confirmed"))
        self.assertFalse(hasattr(engine, "run_experiment"))
        self.assertTrue(hasattr(engine, "propose_hypothesis"))
        self.assertTrue(hasattr(engine, "rank_hypotheses"))
        self.assertTrue(hasattr(engine, "explain_reasoning"))


if __name__ == "__main__":
    unittest.main()
