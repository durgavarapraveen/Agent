"""P0.3 tool capability (Kali-backend aware) + P0.4 execution truth."""
import pytest

from core.tools.tool_health import ToolHealthManager, HealthState
from core.common.schemas import ToolResult, ToolExecutionStatus


# ---- P0.3 ------------------------------------------------------------------

def test_host_miss_but_kali_available_is_ready(monkeypatch):
    import core.tools.tool_health as th
    monkeypatch.setattr(th.shutil, "which", lambda *_a, **_k: None)  # host miss

    class _Kali:
        @staticmethod
        def get_container(auto_create=False): return "kali-container"
        @staticmethod
        def is_tool_installed(tool, bypass_cache=False): return True
        @staticmethod
        def is_native_environment(): return False
    import agents.kali_executor as ke
    monkeypatch.setattr(ke, "KaliDockerExecutor", _Kali)

    h = ToolHealthManager().probe("nmap")
    assert h.state == HealthState.READY
    assert h.kali_available is True
    assert h.execution_backend == "kali"
    assert h.is_available() is True


def test_host_miss_no_backend_is_unknown_not_unavailable(monkeypatch):
    import core.tools.tool_health as th
    monkeypatch.setattr(th.shutil, "which", lambda *_a, **_k: None)

    class _Kali:
        @staticmethod
        def get_container(auto_create=False): return None
        @staticmethod
        def is_native_environment(): return False
    import agents.kali_executor as ke
    monkeypatch.setattr(ke, "KaliDockerExecutor", _Kali)

    h = ToolHealthManager().probe("feroxbuster")
    assert h.state == HealthState.UNKNOWN         # NOT UNAVAILABLE
    assert h.is_available() is True


def test_absent_everywhere_is_unavailable(monkeypatch):
    import core.tools.tool_health as th
    monkeypatch.setattr(th.shutil, "which", lambda *_a, **_k: None)

    class _Kali:
        @staticmethod
        def get_container(auto_create=False): return "kali-container"
        @staticmethod
        def is_tool_installed(tool, bypass_cache=False): return False
        @staticmethod
        def is_native_environment(): return False
    import agents.kali_executor as ke
    monkeypatch.setattr(ke, "KaliDockerExecutor", _Kali)

    h = ToolHealthManager().probe("nonexistent-tool")
    assert h.state == HealthState.UNAVAILABLE
    assert h.execution_backend == "none"
    assert h.is_available() is False


# ---- P0.4 ------------------------------------------------------------------

def test_skipped_fresh_is_not_success_but_non_failing():
    r = ToolResult(tool="nmap", capability="port_scan",
                   status=ToolExecutionStatus.SKIPPED_FRESH, exit_code=0)
    assert r.status == ToolExecutionStatus.SKIPPED_FRESH   # not SUCCESS
    assert r.success is True                                # no retry


def test_cached_is_not_success_status():
    r = ToolResult(tool="nmap", capability="port_scan",
                   status=ToolExecutionStatus.CACHED)
    assert r.status == ToolExecutionStatus.CACHED
    assert str(r.status.value) != "SUCCESS"
    assert r.success is True


def test_nonzero_exit_never_success():
    r = ToolResult(tool="curl", capability="http",
                   status=ToolExecutionStatus.SUCCESS, exit_code=7)
    assert r.success is False


def test_stamp_cached_marks_cache_hit():
    from core.tools.tool_gateway import ToolGateway
    gw = ToolGateway.__new__(ToolGateway)   # no __init__ needed for helper
    orig = ToolResult(tool="nmap", capability="port_scan",
                      status=ToolExecutionStatus.SUCCESS, exit_code=0, stdout="open 80")
    stamped = gw._stamp_cached(orig)
    assert stamped.status == ToolExecutionStatus.CACHED
    assert stamped.metadata.get("cache_hit") is True
    assert stamped.metadata.get("original_status") == "SUCCESS"
    assert stamped.stdout == "open 80"       # payload preserved


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
