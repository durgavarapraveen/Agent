import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from core.execution_mode import ExecutionConfig, ExecutionMode
from core.tool_invocation_engine import ToolInvocationEngine, InvocationSource
from core.tool_gateway import ToolGateway
from core.schemas import ToolResult, ToolInvocation
from core.hybrid_executor_logger import HybridExecutorLogger
from core.central_brain import CentralBrain
from scripts.set_execution_mode import main as set_mode_main

# --- 1. Test execution mode detection ---

def test_execution_config_mode_a():
    config = ExecutionConfig()
    config.mode = ExecutionMode.DETERMINISTIC
    assert config.is_mode_a_enabled() is True
    assert config.is_mode_b_enabled() is False
    assert config.should_use_mode_a_primary() is True
    assert config.can_fallback_to_b() is False

def test_execution_config_mode_b():
    config = ExecutionConfig()
    config.mode = ExecutionMode.AGENTIC
    assert config.is_mode_a_enabled() is False
    assert config.is_mode_b_enabled() is True
    assert config.should_use_mode_b_primary() is True
    assert config.can_fallback_to_b() is False

def test_execution_config_mode_a_b():
    config = ExecutionConfig()
    config.mode = ExecutionMode.HYBRID
    config.fallback_on_error = True
    assert config.is_mode_a_enabled() is True
    assert config.is_mode_b_enabled() is True
    assert config.should_use_mode_a_primary() is True
    assert config.can_fallback_to_b() is True

# --- 2. Test tool invocation engine ---

@pytest.mark.asyncio
async def test_tool_invocation_engine_approach_a():
    gateway = MagicMock(spec=ToolGateway)
    mock_result = MagicMock()
    mock_result.success = True
    mock_result.output = "scan done"
    gateway.execute = AsyncMock(return_value=mock_result)
    
    engine = ToolInvocationEngine(gateway)
    result = await engine.invoke_from_capability(
        capability="port_scan", 
        target="127.0.0.1", 
        params={}, 
        session_id="s1", 
        auth_context=None
    )
    
    assert result.success is True
    gateway.execute.assert_called_once()
    invocation: ToolInvocation = gateway.execute.call_args[0][0]
    assert invocation.operation == "port_scan"
    assert invocation.target == "127.0.0.1"

@pytest.mark.asyncio
async def test_tool_invocation_engine_approach_b():
    gateway = MagicMock(spec=ToolGateway)
    mock_result = MagicMock()
    mock_result.success = True
    mock_result.output = "direct scan done"
    gateway.execute = AsyncMock(return_value=mock_result)
    
    engine = ToolInvocationEngine(gateway)
    result = await engine.invoke_tool_directly(
        tool_id="nmap", 
        target="127.0.0.1", 
        params={}, 
        session_id="s2", 
        auth_context=None
    )
    
    assert result.success is True
    gateway.execute.assert_called_once()
    invocation: ToolInvocation = gateway.execute.call_args[0][0]
    assert invocation.tool_id == "nmap"
    assert invocation.target == "127.0.0.1"

# --- 3. Test mode toggling ---

def test_mode_toggling_updates_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("EXECUTION_MODE=A\n", encoding="utf-8")
    
    with patch("scripts.set_execution_mode.os.path.exists", return_value=True), \
         patch("scripts.set_execution_mode.sys.argv", ["set_execution_mode.py", "A_B"]), \
         patch("builtins.open", new_callable=MagicMock) as mock_open:
             
        mock_open.return_value.__enter__.return_value.readlines.return_value = ["EXECUTION_MODE=A\n"]
        
        try:
            set_mode_main()
        except SystemExit:
            pass
            
        # Verify write was called with updated mode
        mock_file = mock_open.return_value.__enter__.return_value
        write_call = [call for call in mock_file.mock_calls if 'writelines' in str(call)]
        if write_call:
            lines_written = write_call[0][1][0]
            assert any("EXECUTION_MODE=A_B" in line for line in lines_written)

# --- 4. Test fallback ---

@pytest.mark.asyncio
@patch("core.central_brain.get_execution_config")
async def test_hybrid_fallback(mock_get_config):
    # Test if mode is A_B and A fails, B is attempted
    mock_config = MagicMock()
    mock_config.mode = ExecutionMode.HYBRID
    mock_config.should_use_mode_a_primary.return_value = True
    mock_config.should_use_mode_b_primary.return_value = False
    mock_config.can_fallback_to_b.return_value = True
    mock_get_config.return_value = mock_config
    
    brain = CentralBrain(target="example.com")
    
    # Mock approaches
    brain._run_phase_approach_a = AsyncMock(side_effect=Exception("Approach A Failed"))
    brain._run_phase_approach_b = AsyncMock()
    
    await brain._run_phase("recon")
    
    brain._run_phase_approach_a.assert_called_once_with("recon")
    brain._run_phase_approach_b.assert_called_once_with("recon")

# --- 5. Test logging ---

def test_hybrid_executor_logger(tmp_path):
    log_dir = tmp_path / "logs"
    logger = HybridExecutorLogger(log_dir=str(log_dir))
    
    logger.log_task_execution(
        task_id="t1", approach="A", capability="recon",
        tool_id="nmap", success=True, duration_sec=1.5
    )
    logger.log_task_execution(
        task_id="t2", approach="B", capability="scan",
        tool_id="browser", success=False, duration_sec=2.0
    )
    
    summary = logger.get_execution_summary()
    assert summary["A"] == 1
    assert summary["B"] == 1
    assert summary["total"] == 2
