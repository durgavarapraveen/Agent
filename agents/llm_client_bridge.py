"""
Claude Bridge Provider - Routes to Claude Bridge Server
Drop into: agents/llm_client_bridge.py

Usage: Set LLM_PROVIDER=bridge in .env
"""

import json
import logging
from typing import Dict, Optional
from enum import Enum
import httpx

logger = logging.getLogger(__name__)

# Import the base class from llm_client
from agents.llm_client import LLMProvider, TaskTier

# ═══════════════════════════════════════════════════════════════════════════
# BRIDGE PROVIDER (implements LLMProvider interface)
# ═══════════════════════════════════════════════════════════════════════════

class ClaudeBridgeProvider(LLMProvider):
    """Claude Bridge HTTP provider - routes to local Claude CLI"""
    
    MODEL_MAP = {
        "haiku": "haiku",
        "sonnet": "sonnet", 
        "opus": "opus",
        "claude-3-haiku": "haiku",
        "claude-3-sonnet": "sonnet",
        "claude-3-opus": "opus",
    }
    
    def __init__(self, base_url: str = "http://localhost:8000", default_model: str = "sonnet"):
        self.base_url = base_url.rstrip("/")
        self.default_model = self._map_model(default_model)
        self.timeout = 330  # 30s buffer over server timeout (300s for Sonnet on Windows)
        logger.info(f"ClaudeBridgeProvider initialized: {self.base_url}")
        logger.info(f"Default model: {self.default_model}")
    
    def _map_model(self, model: str) -> str:
        """Map model names to bridge server format"""
        return self.MODEL_MAP.get(model.lower(), "haiku")
    
    async def is_available(self) -> bool:
        """Check if bridge server is running"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/health")
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Bridge unavailable: {e}")
            return False
    
    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                       system: Optional[str] = None, max_tokens: int = 1024,
                       temperature: float = 0.3) -> str:
        """
        Generate text via bridge server
        
        Returns: response text
        """
        
        # Build prompt with system context if provided
        full_prompt = prompt
        if system:
            full_prompt = f"{system}\n\n{prompt}"
        
        logger.debug(f"Generating via bridge ({self.default_model}): {prompt[:80]}...")
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/chat",
                    json={
                        "prompt": full_prompt,
                        "model": self.default_model,
                        "timeout": 300  # Sonnet needs ~3 min on Windows
                    }
                )
            
            if response.status_code != 200:
                logger.error(f"Bridge error {response.status_code}: {response.text}")
                raise RuntimeError(f"Bridge server error: {response.text}")
            
            data = response.json()
            return data.get("response", "")
        
        except httpx.TimeoutException:
            logger.error("Bridge request timed out (300s)")
            raise TimeoutError("Claude response timed out")
        except Exception as e:
            logger.error(f"Bridge error: {e}")
            raise
    
    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                           system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        """
        Generate JSON response via bridge server
        
        Returns: parsed JSON dict
        """
        
        # Build prompt with system context if provided
        full_prompt = prompt
        if system:
            full_prompt = f"{system}\n\n{prompt}"
        
        # Add JSON instruction to prompt
        json_prompt = f"""{full_prompt}

Respond ONLY with valid JSON (no markdown, no extra text). Parse and return immediately."""
        
        logger.debug(f"Generating JSON via bridge ({self.default_model}): {prompt[:80]}...")
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/chat",
                    json={
                        "prompt": json_prompt,
                        "model": self.default_model,
                        "timeout": 300  # Sonnet needs ~3 min on Windows
                    }
                )
            
            if response.status_code != 200:
                logger.error(f"Bridge error {response.status_code}: {response.text}")
                return None
            
            data = response.json()
            response_text = data.get("response", "")
            
            # Parse JSON from response
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from Claude: {response_text[:200]}")
                return None
        
        except httpx.TimeoutException:
            logger.error("Bridge request timed out (300s)")
            return None
        except Exception as e:
            logger.error(f"Bridge error: {e}")
            return None

# ═══════════════════════════════════════════════════════════════════════════
# USAGE
# ═══════════════════════════════════════════════════════════════════════════

"""
SETUP:

1. Copy this file to: agents/llm_client_bridge.py

2. In agents/llm_client.py, add this case to _create_from_config():

    elif provider_name == "bridge":
        try:
            from agents.llm_client_bridge import ClaudeBridgeProvider
            bridge_url = config.get("BRIDGE_URL", "http://localhost:8000")
            bridge_model = config.get("BRIDGE_MODEL", "sonnet")
            logger.info(f"Using Claude Bridge: {bridge_url} ({bridge_model})")
            return ClaudeBridgeProvider(bridge_url, bridge_model)
        except (ImportError, ValueError) as e:
            logger.error(f"Bridge init failed: {e}")
            return NullProvider()

3. Update .env:
    LLM_PROVIDER=bridge
    BRIDGE_URL=http://localhost:8000
    BRIDGE_MODEL=sonnet

4. Start bridge server in terminal 1:
    python claude_bridge_server.py

5. Run agent in terminal 2:
    python main.py --target https://juice-shop.herokuapp.com --tier POC

Agent will automatically use Claude Bridge!
"""