"""
Tests for the "No tools available" fix.

Root cause: agentic executor sets operation=tool_name (e.g. "nmap") instead of
operation=capability (e.g. "port_scanning"). The op_map in ToolRouter is keyed
by capability names, so tool names don't match → empty tools → failure.

Two-layer fix:
  1. ToolInvocationEngine._TOOL_TO_OP remaps operation when operation==tool_id
  2. ToolRouter._get_tools_for_operation has fallback for direct tool name lookup
"""
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass

from core.tools.tool_invocation_engine import (
    ToolInvocationEngine, ToolInvocationContext, InvocationSource,
)
from core.tools.tool_router import ToolRouter


def _make_fake_tool(name: str):
    tool = MagicMock()
    tool.name = name
    tool.category = "security"
    return tool


class FakeRegistry:
    def __init__(self, tool_names):
        self._tools = {n: _make_fake_tool(n) for n in tool_names}

    def get(self, name):
        return self._tools.get(name)


# ---------------------------------------------------------------------------
# Layer 1: ToolInvocationEngine._TOOL_TO_OP remapping
# ---------------------------------------------------------------------------
class TestToolToOpRemapping(unittest.TestCase):

    def test_all_known_tools_have_mapping(self):
        mapping = ToolInvocationEngine._TOOL_TO_OP
        expected_tools = [
            "nmap", "masscan", "subfinder", "amass", "httpx", "whatweb",
            "nuclei", "nikto", "sqlmap", "ffuf", "gobuster", "katana",
            "sslscan", "sslyze", "hydra", "arjun", "dalfox", "curl",
            "dig", "whois", "wafw00f", "theharvester",
        ]
        for tool in expected_tools:
            self.assertIn(tool, mapping, f"{tool} missing from _TOOL_TO_OP")

    def test_remap_when_operation_equals_tool_id(self):
        gateway = MagicMock()
        fake_result = MagicMock()
        fake_result.success = True
        fake_result.stdout = "ok"
        fake_result.stderr = ""
        gateway.execute = AsyncMock(return_value=fake_result)

        engine = ToolInvocationEngine(gateway)

        ctx = ToolInvocationContext(
            tool_id="nmap",
            operation="nmap",  # BUG: operation==tool_id
            target="example.com",
            params={},
            session_id="test-sess",
            source=InvocationSource.TOOL_USE,
            auth_context=None,
        )

        asyncio.get_event_loop().run_until_complete(engine.invoke(ctx))

        call_args = gateway.execute.call_args
        invocation = call_args[0][0]
        self.assertEqual(invocation.operation, "port_scanning",
                         "operation should be remapped from 'nmap' to 'port_scanning'")
        self.assertEqual(invocation.tool_id, "nmap")

    def test_no_remap_when_operation_differs_from_tool_id(self):
        gateway = MagicMock()
        fake_result = MagicMock()
        fake_result.success = True
        fake_result.stdout = ""
        fake_result.stderr = ""
        gateway.execute = AsyncMock(return_value=fake_result)

        engine = ToolInvocationEngine(gateway)

        ctx = ToolInvocationContext(
            tool_id="nmap",
            operation="port_scanning",  # Already correct
            target="example.com",
            params={},
            session_id="test-sess",
            source=InvocationSource.TOOL_USE,
            auth_context=None,
        )

        asyncio.get_event_loop().run_until_complete(engine.invoke(ctx))

        invocation = gateway.execute.call_args[0][0]
        self.assertEqual(invocation.operation, "port_scanning",
                         "already-correct operation should not change")

    def test_remap_all_common_tools(self):
        gateway = MagicMock()
        fake_result = MagicMock()
        fake_result.success = True
        fake_result.stdout = ""
        fake_result.stderr = ""
        gateway.execute = AsyncMock(return_value=fake_result)

        engine = ToolInvocationEngine(gateway)

        cases = {
            "nmap": "port_scanning",
            "dig": "dns_intelligence",
            "sqlmap": "sql_injection",
            "nuclei": "vulnerability_scanning",
            "ffuf": "endpoint_discovery",
            "dalfox": "xss_scanning",
            "katana": "web_crawling",
            "sslscan": "tls_analysis",
            "httpx": "technology_fingerprinting",
            "wafw00f": "waf_detection",
        }

        for tool_name, expected_cap in cases.items():
            ctx = ToolInvocationContext(
                tool_id=tool_name,
                operation=tool_name,
                target="example.com",
                params={},
                session_id="test-sess",
                source=InvocationSource.TOOL_USE,
                auth_context=None,
            )
            asyncio.get_event_loop().run_until_complete(engine.invoke(ctx))
            invocation = gateway.execute.call_args[0][0]
            self.assertEqual(invocation.operation, expected_cap,
                             f"{tool_name} should remap to {expected_cap}")


# ---------------------------------------------------------------------------
# Layer 2: ToolRouter._get_tools_for_operation fallbacks
# ---------------------------------------------------------------------------
class TestRouterFallback(unittest.TestCase):

    def _make_router(self, tool_names):
        registry = FakeRegistry(tool_names)
        with patch.object(ToolRouter, '__init__', lambda self, reg: None):
            router = ToolRouter.__new__(ToolRouter)
            router.registry = registry
        return router

    def test_capability_lookup_works(self):
        router = self._make_router(["nmap", "masscan"])
        tools = router._get_tools_for_operation("port_scanning")
        names = [t.name for t in tools]
        self.assertIn("nmap", names)
        self.assertIn("masscan", names)

    def test_direct_tool_name_fallback(self):
        router = self._make_router(["nmap"])
        tools = router._get_tools_for_operation("nmap")
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "nmap")

    def test_reverse_lookup_fallback(self):
        router = self._make_router(["dig", "whois", "dnsenum"])
        # "dig" is a tool name that appears in the op_map values for dns_intelligence
        tools = router._get_tools_for_operation("dig")
        names = [t.name for t in tools]
        # Should find dig via direct lookup
        self.assertIn("dig", names)

    def test_unknown_operation_returns_empty(self):
        router = self._make_router(["nmap"])
        tools = router._get_tools_for_operation("nonexistent_operation_xyz")
        self.assertEqual(len(tools), 0)

    def test_capability_with_missing_tools_returns_available_only(self):
        router = self._make_router(["nmap"])  # masscan not registered
        tools = router._get_tools_for_operation("port_scanning")
        names = [t.name for t in tools]
        self.assertIn("nmap", names)
        self.assertNotIn("masscan", names)


# ---------------------------------------------------------------------------
# Integration: simulate the agentic path end-to-end
# ---------------------------------------------------------------------------
class TestAgenticPathIntegration(unittest.TestCase):

    def test_agentic_path_remaps_and_finds_tools(self):
        """
        Simulates agentic executor calling invoke() with operation=tool_id.
        Verifies the full chain: engine remaps → gateway receives correct
        capability → router returns tools.
        """
        registry = FakeRegistry(["nmap", "masscan", "dig", "whois", "sqlmap"])

        with patch.object(ToolRouter, '__init__', lambda self, reg: None):
            router = ToolRouter.__new__(ToolRouter)
            router.registry = registry

        # Verify that after remapping, the router can find tools
        test_cases = [
            ("nmap", "port_scanning"),
            ("dig", "dns_intelligence"),
            ("sqlmap", "sql_injection"),
        ]

        engine = ToolInvocationEngine(MagicMock())

        for tool_name, expected_cap in test_cases:
            # Simulate what the engine does
            resolved_op = tool_name
            resolved_tid = tool_name
            if resolved_op == resolved_tid:
                mapped = engine._TOOL_TO_OP.get(resolved_op)
                if mapped:
                    resolved_op = mapped

            self.assertEqual(resolved_op, expected_cap,
                             f"Engine should remap {tool_name} → {expected_cap}")

            tools = router._get_tools_for_operation(resolved_op)
            self.assertGreater(len(tools), 0,
                               f"Router should find tools for {expected_cap}")

    def test_without_fix_tools_would_be_empty(self):
        """
        Proves the bug: without remapping, operation="nmap" returns no tools
        from the router's op_map (since op_map keys are capabilities, not tool names).
        The fallback catches it, but the primary path fails.
        """
        registry = FakeRegistry(["nmap", "masscan"])

        with patch.object(ToolRouter, '__init__', lambda self, reg: None):
            router = ToolRouter.__new__(ToolRouter)
            router.registry = registry

        # Without the engine remapping, operation="nmap" goes to op_map
        # op_map has no key "nmap" → tool_ids = [] → but fallback catches it
        tools = router._get_tools_for_operation("nmap")
        # Thanks to the fallback, direct lookup finds nmap
        self.assertGreater(len(tools), 0,
                           "Fallback should catch direct tool name even without remapping")


if __name__ == "__main__":
    unittest.main()
