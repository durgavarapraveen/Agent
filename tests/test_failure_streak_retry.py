"""
Unit tests for JSON response validation, failure streak counter tracking,
retry loops with backoff, diagnostic logging, and safe fallback mechanisms.
"""

import asyncio
import json
import logging
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agents.llm_client import (
    LLMProvider, TaskTier, validate_json_payload
)
from core.schemas import NormalizedLLMResponse, BrainDecisionAction, TaskSpec, CapabilityType
from core.central_brain import CentralBrain


class MockLLMProvider(LLMProvider):
    def __init__(self, responses=None):
        self.responses = responses or []
        self.call_count = 0
        self.prompts_received = []

    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: str = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: str = None) -> NormalizedLLMResponse:
        self.prompts_received.append(prompt)
        if self.call_count < len(self.responses):
            res = self.responses[self.call_count]
            self.call_count += 1
            return res
        self.call_count += 1
        return NormalizedLLMResponse(content="", structured_output=None, provider="mock", model="mock")

    async def is_available(self) -> bool:
        return True


def test_validate_json_payload():
    assert validate_json_payload({"action": "phase_complete"}) is True
    assert validate_json_payload({"action": "spawn_agents", "agent_specs": []}) is True
    assert validate_json_payload({}) is False
    assert validate_json_payload(None) is False
    assert validate_json_payload("not a dict") is False
    assert validate_json_payload([], mandatory_fields=["action"]) is False
    assert validate_json_payload({"action": "spawn_agents"}, mandatory_fields=["action"]) is True
    assert validate_json_payload({"other": "field"}, mandatory_fields=["action"]) is False


@pytest.mark.anyio
async def test_llm_provider_generate_json_with_retry_success(caplog):
    caplog.set_level(logging.WARNING)
    # First response empty, second response valid JSON
    responses = [
        NormalizedLLMResponse(content="{}", structured_output={}, provider="mock", model="mock"),
        NormalizedLLMResponse(content='{"action": "phase_complete"}', structured_output={"action": "phase_complete"}, provider="mock", model="mock"),
    ]
    provider = MockLLMProvider(responses)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        data, raw = await provider.generate_json_with_retry(
            "test prompt", mandatory_fields=["action"], max_retries=3, initial_backoff=0.01
        )

    assert data == {"action": "phase_complete"}
    assert raw == '{"action": "phase_complete"}'
    assert provider.call_count == 2
    # Verify diagnostic warning logged with raw response
    assert "Attempt 1/3 failed: empty {} or malformed JSON received" in caplog.text
    assert "Raw response: '{}'" in caplog.text


@pytest.mark.anyio
async def test_llm_provider_generate_json_with_retry_exhausted(caplog):
    caplog.set_level(logging.WARNING)
    responses = [
        NormalizedLLMResponse(content="{}", structured_output={}, provider="mock", model="mock"),
        NormalizedLLMResponse(content="bad json payload", structured_output=None, provider="mock", model="mock"),
        NormalizedLLMResponse(content="", structured_output=None, provider="mock", model="mock"),
    ]
    provider = MockLLMProvider(responses)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        data, raw = await provider.generate_json_with_retry(
            "test prompt", max_retries=3, initial_backoff=0.01
        )

    assert data == {}
    assert provider.call_count == 3
    assert "Attempt 1/3 failed" in caplog.text
    assert "Attempt 2/3 failed" in caplog.text
    assert "Attempt 3/3 failed" in caplog.text


@pytest.mark.anyio
async def test_central_brain_failure_streak_and_retry(caplog):
    caplog.set_level(logging.WARNING)
    brain = CentralBrain("example.com")
    brain.max_agents_per_phase = 1
    
    # Mock LLM provider returns empty {} first, then valid decision
    valid_payload = {
        "action": "spawn_agent",
        "agent_spec": {
            "objective": "Scan target headers",
            "tools": ["http_request"]
        }
    }
    responses = [
        NormalizedLLMResponse(content="{}", structured_output={}, provider="mock", model="mock"),
        NormalizedLLMResponse(
            content=json.dumps(valid_payload),
            structured_output=valid_payload,
            provider="mock",
            model="mock"
        ),
    ]
    mock_llm = MockLLMProvider(responses)
    brain.llm = mock_llm

    assert brain.failure_streak == 0
    assert brain.consecutive_agent_failures == 0

    mock_agent = AsyncMock()
    mock_agent.agent_id = "AGENT-1"
    mock_agent.execute = AsyncMock(return_value={"status": "success", "results": "done"})

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with patch.object(brain.spawner, "spawn", MagicMock(return_value=mock_agent)):
            await brain._run_phase("recon")

    # Verify failure streak incremented on first attempt, then reset to 0 on valid payload
    assert brain.failure_streak == 0
    assert "Attempt 1/3 received empty {} or malformed JSON" in caplog.text
    assert "Raw response: '{}'" in caplog.text


@pytest.mark.anyio
async def test_central_brain_fallback_on_max_retries(caplog):
    caplog.set_level(logging.WARNING)
    brain = CentralBrain("http://example.com")
    brain.max_agents_per_phase = 1
    
    # LLM always returns empty {}
    responses = [
        NormalizedLLMResponse(content="{}", structured_output={}, provider="mock", model="mock")
        for _ in range(10)
    ]
    brain.llm = MockLLMProvider(responses)

    mock_agent = AsyncMock()
    mock_agent.agent_id = "FALLBACK-AGENT"
    mock_agent.execute = AsyncMock(return_value={"status": "success"})

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with patch.object(brain.spawner, "spawn", MagicMock(return_value=mock_agent)):
            await brain._run_phase("recon")

    # Verify fallback executed and warning logged
    assert "received empty {} or malformed JSON" in caplog.text
    assert "[CentralBrain] Failure threshold reached" in caplog.text or "Brain returned empty/invalid response" in caplog.text
