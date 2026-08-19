import pytest
from scope.manager import ScopeManager
from core.exceptions import ScopeViolationException

@pytest.fixture
def scope_manager():
    return ScopeManager(
        allowed_domains=["example.com", "*.example.com"],
        allowed_ips=["192.168.0.0/16"],
        execution_mode="PASSIVE"
    )

class TestScopeManager:
    def test_domain_validation(self, scope_manager):
        assert scope_manager.validate_url("https://example.com")
        assert scope_manager.validate_url("https://sub.example.com")
        assert not scope_manager.validate_url("https://other.com")
    
    def test_ip_validation(self, scope_manager):
        assert scope_manager._is_ip_allowed("192.168.1.1")
        assert scope_manager._is_ip_allowed("192.168.255.255")
        assert not scope_manager._is_ip_allowed("10.0.0.1")
    
    def test_tool_execution_validation(self, scope_manager):
        # Should pass for in-scope target
        result = scope_manager.validate_tool_execution(
            "nmap",
            "https://example.com"
        )
        assert result is True
    
    def test_tool_execution_out_of_scope(self, scope_manager):
        # Should fail for out-of-scope target
        with pytest.raises(ScopeViolationException):
            scope_manager.validate_tool_execution(
                "nmap",
                "https://other.com"
            )
    
    def test_passive_mode_restrictions(self, scope_manager):
        scope_manager.execution_mode = "PASSIVE"
        
        # Active tools should fail in PASSIVE mode
        with pytest.raises(ScopeViolationException):
            scope_manager.validate_tool_execution(
                "exploit_tool",
                "https://example.com"
            )
    
    def test_dangerous_operations_blocked(self, scope_manager):
        # Dangerous operations should always be blocked
        with pytest.raises(ScopeViolationException):
            scope_manager.validate_tool_execution(
                "delete_file",
                "https://example.com"
            )
    
    def test_scope_summary(self, scope_manager):
        summary = scope_manager.get_scope_summary()
        assert "allowed_domains" in summary
        assert "execution_mode" in summary
        assert summary["execution_mode"] == "PASSIVE"
