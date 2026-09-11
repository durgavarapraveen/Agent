"""Phase 9.1 — Amazon Bedrock provider."""
from __future__ import annotations

import json

from agents.providers.bedrock_provider import BedrockProvider
from agents.universal_llm_harness import ProviderType, TaskTier


class _FakeBody:
    def __init__(self, data):
        self._data = json.dumps(data).encode()

    def read(self):
        return self._data


class _FakeBedrockClient:
    def __init__(self, response=None, raise_exc=None):
        self.response = response
        self.raise_exc = raise_exc
        self.last_model = None
        self.last_body = None

    def invoke_model(self, modelId, body):
        self.last_model = modelId
        self.last_body = json.loads(body)
        if self.raise_exc:
            raise self.raise_exc
        return {"body": _FakeBody(self.response)}


def test_bedrock_provider_type_registered():
    assert ProviderType.BEDROCK.value == "bedrock"


def test_tier_model_selection():
    p = BedrockProvider(small_model="haiku-x", large_model="sonnet-y",
                        client=_FakeBedrockClient())
    assert p.get_model_for_tier(TaskTier.SMALL) == "haiku-x"
    assert p.get_model_for_tier(TaskTier.LARGE) == "sonnet-y"


async def test_generate_response_parses_bedrock():
    client = _FakeBedrockClient(response={
        "content": [{"type": "text", "text": "hello from claude"}],
        "usage": {"input_tokens": 100, "output_tokens": 50},
        "stop_reason": "end_turn",
    })
    p = BedrockProvider(small_model="us.anthropic.claude-haiku-4-5-v1",
                        large_model="us.anthropic.claude-sonnet-4-v1", client=client)
    resp = await p.generate_response("hi", system="be brief", tier=TaskTier.LARGE)
    assert resp.content == "hello from claude"
    assert resp.provider == "bedrock"
    assert resp.model == "us.anthropic.claude-sonnet-4-v1"
    assert resp.usage["input_tokens"] == 100
    assert resp.cost_usd > 0
    assert resp.error is None
    # System prompt + bedrock version were sent.
    assert client.last_body["system"] == "be brief"
    assert client.last_body["anthropic_version"] == "bedrock-2023-05-31"


async def test_generate_response_json_format():
    client = _FakeBedrockClient(response={
        "content": [{"type": "text", "text": '```json\n{"vuln": true}\n```'}],
        "usage": {"input_tokens": 10, "output_tokens": 5}})
    p = BedrockProvider(client=client)
    resp = await p.generate_response("classify", response_format="json")
    assert resp.structured_output == {"vuln": True}


async def test_generate_response_handles_error():
    client = _FakeBedrockClient(raise_exc=RuntimeError("throttled"))
    p = BedrockProvider(client=client)
    resp = await p.generate_response("hi")
    assert resp.error and "throttled" in resp.error
    assert resp.content == ""


async def test_is_available_with_injected_client():
    assert await BedrockProvider(client=_FakeBedrockClient()).is_available() is True
