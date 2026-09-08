"""Smoke test: ToolRegistry registers its defaults, including the P2-8
structured HTTP ops and the shell tools the router selects by capability.
"""
from __future__ import annotations

import pytest


def test_registry_registers_defaults() -> None:
    from core.tools.tool_registry import ToolRegistry
    reg = ToolRegistry()

    # Registry API varies over refactors — accept either .tools dict or .list().
    if hasattr(reg, "tools") and isinstance(reg.tools, dict):
        names = set(reg.tools.keys())
    elif hasattr(reg, "list"):
        names = {t.name for t in reg.list()}
    else:
        pytest.fail("ToolRegistry exposes neither .tools nor .list()")

    assert len(names) >= 20, f"too few tools registered: {len(names)}"


def test_structured_http_ops_registered() -> None:
    """P2-8: HTTP ops must be first-class tools the router can pick."""
    from core.tools.tool_registry import ToolRegistry
    reg = ToolRegistry()

    if hasattr(reg, "tools") and isinstance(reg.tools, dict):
        names = set(reg.tools.keys())
    else:
        names = {t.name for t in reg.list()}

    required = {
        "http_fetch", "extract_links", "extract_api_routes",
        "extract_file_links", "extract_regex", "parse_html",
        "parse_json", "compare_responses", "extract_headers",
    }
    missing = required - names
    assert not missing, f"structured HTTP ops missing from registry: {sorted(missing)}"


def test_tool_router_resolves_capability_to_tool() -> None:
    """`http_fetch` capability must resolve to at least one tool."""
    from core.tools.tool_registry import ToolRegistry
    from core.tools.tool_router import ToolRouter
    router = ToolRouter(ToolRegistry())

    # Router API surface varies; try common method names.
    fn = getattr(router, "_get_tools_for_operation", None) \
         or getattr(router, "get_tools_for_operation", None) \
         or getattr(router, "resolve", None)
    if fn is None:
        pytest.skip("router has no public capability→tool resolver method")

    tools = fn("http_fetch")
    assert tools, "router could not resolve capability 'http_fetch'"
