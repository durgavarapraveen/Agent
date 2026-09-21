"""Settings endpoints — LLM provider + DeepSeek API key.

Extracted from the server.py god-file into a focused APIRouter. The global
X-API-Key auth middleware in server.py still applies to these routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/llm-provider")
def get_llm_provider():
    try:
        from agents.llm_harness_adapter import get_provider
        return {"provider": get_provider(), "options": ["claude_cli", "bedrock", "deepseek"]}
    except Exception as e:
        raise HTTPException(500, f"provider read failed: {e}")


class LLMProviderBody(BaseModel):
    provider: str = Field(..., max_length=32)


@router.post("/llm-provider")
def set_llm_provider(body: LLMProviderBody):
    try:
        from agents.llm_harness_adapter import set_provider
        p = set_provider(body.provider)
        return {"provider": p, "note": "Applies to the next scan you start."}
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    except Exception as e:
        raise HTTPException(500, f"provider write failed: {e}")


@router.get("/metasploit")
def get_metasploit():
    try:
        from core.utils.scan_flags import metasploit_enabled
        return {"enabled": metasploit_enabled()}
    except Exception as e:
        raise HTTPException(500, f"metasploit read failed: {e}")


class MetasploitBody(BaseModel):
    enabled: bool = Field(default=False)


@router.post("/metasploit")
def set_metasploit(body: MetasploitBody):
    try:
        from core.utils.scan_flags import set_metasploit_enabled, metasploit_enabled
        set_metasploit_enabled(bool(body.enabled))
        return {"enabled": metasploit_enabled(),
                "note": "Read-only auxiliary scanners only. Applies to the next scan you start."}
    except Exception as e:
        raise HTTPException(500, f"metasploit write failed: {e}")


@router.get("/deepseek-key")
def get_deepseek_key():
    try:
        from agents.llm_harness_adapter import has_deepseek_api_key
        return {"configured": has_deepseek_api_key()}
    except Exception as e:
        raise HTTPException(500, f"deepseek key read failed: {e}")


class DeepSeekKeyBody(BaseModel):
    api_key: str = Field(default="", max_length=512)


@router.post("/deepseek-key")
def set_deepseek_key(body: DeepSeekKeyBody):
    try:
        from agents.llm_harness_adapter import set_deepseek_api_key, has_deepseek_api_key
        set_deepseek_api_key(body.api_key)
        return {"configured": has_deepseek_api_key(),
                "note": "Applies to the next scan you start."}
    except Exception as e:
        raise HTTPException(500, f"deepseek key write failed: {e}")
