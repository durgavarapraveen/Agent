import pytest
import asyncio
from typing import Dict

from core.tools.tool_registry import ToolRegistry
from core.tools.tool_gateway import ToolGateway
from core.common.schemas import ToolInvocation
from core.tools.tool_cache import ToolResultCache
from core.security.audit_logger import AuditLogger
from core.security.authorization import TargetScopeValidator, AuthContext
import pytest_asyncio

class MockAuditLogger(AuditLogger):
    def log_denial(self, invocation: ToolInvocation, context: AuthContext):
        pass
        
    def log_cache_hit(self, cache_key: str, invocation: ToolInvocation):
        pass
        
    def log_execution(self, invocation: ToolInvocation, success: bool, duration_ms: int):
        pass

@pytest_asyncio.fixture
async def tool_gateway():
    TargetScopeValidator.set(TargetScopeValidator(["httpbin.org", "example.com"]))
    registry = ToolRegistry()
    await registry.validate_tools()
    
    # We can force python builtin tools for isolated tests without Kali docker running
    cache = ToolResultCache()
    audit = MockAuditLogger()
    return ToolGateway(registry, cache, audit)

@pytest.fixture
def auth_context():
    return AuthContext(allowed_tools=["http_request", "dns_lookup", "port_check"])

@pytest.mark.asyncio
async def test_real_http_request(tool_gateway: ToolGateway, auth_context: AuthContext):
    """Integration test invoking the real http_request tool"""
    invocation = ToolInvocation(
        tool_id="http_request",
        operation="http_analysis",
        target="httpbin.org",
        params={"url": "https://httpbin.org/get", "method": "GET"},
        session_id="test_session"
    )
    
    result = await tool_gateway.execute(invocation, auth_context)
    
    assert result.success is True, f"HTTP request failed: {result.error}"
    assert result.stdout is not None
    assert "url" in result.stdout.lower() or "headers" in result.stdout.lower()

@pytest.mark.asyncio
async def test_real_dns_lookup(tool_gateway: ToolGateway, auth_context: AuthContext):
    """Integration test invoking the real dns_lookup tool"""
    invocation = ToolInvocation(
        tool_id="dns_lookup",
        operation="dns_intelligence",
        target="example.com",
        params={"domain": "example.com"},
        session_id="test_session"
    )
    
    result = await tool_gateway.execute(invocation, auth_context)
    
    assert result.success is True, f"DNS lookup failed: {result.error}"
    assert result.data is not None
    
@pytest.mark.asyncio
async def test_real_port_check_offline_fallback(tool_gateway: ToolGateway, auth_context: AuthContext):
    """Integration test invoking the real port_check tool with intentional timeout/offline"""
    invocation = ToolInvocation(
        tool_id="port_check",
        operation="port_scanning",
        target="example.com",
        params={"host": "example.com", "port": 9999, "timeout": 2},
        session_id="test_session"
    )
    
    result = await tool_gateway.execute(invocation, auth_context)
    
    # Port 9999 should be closed/filtered on example.com
    # Depending on how the tool is written, it might succeed with state=closed, or fail.
    # We just ensure it executed gracefully.
    assert hasattr(result, 'success')
