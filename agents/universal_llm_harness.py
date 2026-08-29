"""
Universal LLM Harness - Provider-agnostic orchestration layer
Supports: OpenAI, Claude, Gemini, DeepSeek, Ollama, Groq, Azure, Custom

Core features:
  - Single interface for all providers
  - Token budget tracking & cost monitoring
  - Automatic retry & rate limiting
  - Response normalization
  - Structured JSON fallback parsing
  - Task-tier optimization (SMALL/LARGE)
  - Provider auto-discovery & fallback
"""

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, List, Any, Tuple

import httpx

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ═══════════════════════════════════════════════════════════════

class TaskTier(Enum):
    """Task complexity tier - determines model selection"""
    SMALL = "small"   # Fast, cheaper model for simple tasks
    LARGE = "large"   # Powerful model for complex reasoning


class ProviderType(Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    CLAUDE = "claude"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    GROQ = "groq"
    OLLAMA = "ollama"
    AZURE = "azure"
    CUSTOM = "custom"


# ═══════════════════════════════════════════════════════════════
# COST TRACKING
# ═══════════════════════════════════════════════════════════════

@dataclass
class PricingTier:
    """Pricing per 1K tokens"""
    input: float      # $/1K tokens
    output: float     # $/1K tokens


# Global pricing reference (2024 rates)
PROVIDER_PRICING = {
    "openai": {
        "gpt-4": PricingTier(0.03, 0.06),
        "gpt-4-turbo": PricingTier(0.01, 0.03),
        "gpt-3.5-turbo": PricingTier(0.0005, 0.0015),
    },
    "anthropic": {
        "claude-3-opus": PricingTier(0.015, 0.075),
        "claude-3-sonnet": PricingTier(0.003, 0.015),
        "claude-3-haiku": PricingTier(0.00025, 0.00125),
    },
    "google": {
        "gemini-pro": PricingTier(0.0005, 0.0015),
        "gemini-pro-vision": PricingTier(0.001, 0.002),
    },
    "deepseek": {
        "deepseek-chat": PricingTier(0.00014, 0.00028),
        "deepseek-coder": PricingTier(0.00027, 0.00081),
        "deepseek-flash": PricingTier(0.00022, 0.00066),
        "deepseek-pro": PricingTier(0.00066, 0.00198),
    },
    "groq": {
        "mixtral-8x7b": PricingTier(0.0, 0.0),  # Free tier
        "llama2-70b": PricingTier(0.0, 0.0),
    },
    "ollama": {
        "any": PricingTier(0.0, 0.0),  # Local, no cost
    },
    "azure": {
        "gpt-4": PricingTier(0.03, 0.06),
        "gpt-35-turbo": PricingTier(0.0015, 0.002),
    }
}


@dataclass
class UsageMetrics:
    """Track per-request & aggregate usage"""
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    latency_ms: float = 0.0
    error: Optional[str] = None


class TokenBudget:
    """Multi-provider token & cost budget tracker"""
    
    def __init__(self, max_budget_usd: float = 100.0):
        self.max_budget_usd = max_budget_usd
        self.spent_usd = 0.0
        self.requests: List[UsageMetrics] = []
    
    def log_request(self, metric: UsageMetrics):
        """Log request metrics"""
        self.spent_usd += metric.cost_usd
        self.requests.append(metric)
        pct = (self.spent_usd / self.max_budget_usd) * 100
        logger.info(
            f"[COST] {metric.provider}/{metric.model} | "
            f"${self.spent_usd:.4f}/{self.max_budget_usd:.2f} ({pct:.1f}%) | "
            f"Tokens: {metric.total_tokens} | Latency: {metric.latency_ms:.0f}ms"
        )
    
    def can_afford(self, estimated_tokens: int, provider: str, model: str) -> bool:
        """Check if budget allows request"""
        if estimated_tokens <= 0:
            return True
        
        # Estimate max cost (assume output=2x input)
        pricing = self._get_pricing(provider, model)
        estimated_cost = (estimated_tokens * pricing.input) + \
                        (estimated_tokens * 2 * pricing.output)
        remaining = self.max_budget_usd - self.spent_usd
        return estimated_cost <= remaining
    
    def _get_pricing(self, provider: str, model: str) -> PricingTier:
        """Get pricing for model"""
        provider_lower = provider.lower()
        model_lower = model.lower()
        
        if provider_lower not in PROVIDER_PRICING:
            return PricingTier(0.001, 0.001)  # Safe default
        
        provider_pricing = PROVIDER_PRICING[provider_lower]
        if model_lower in provider_pricing:
            return provider_pricing[model_lower]
        
        # Fallback to first available or default
        return next(iter(provider_pricing.values())) if provider_pricing else PricingTier(0.001, 0.001)
    
    def stats(self) -> Dict[str, Any]:
        """Get aggregate statistics"""
        total_cost = sum(r.cost_usd for r in self.requests)
        total_tokens = sum(r.total_tokens for r in self.requests)
        avg_latency = sum(r.latency_ms for r in self.requests) / len(self.requests) if self.requests else 0
        
        provider_breakdown = {}
        for req in self.requests:
            key = f"{req.provider}/{req.model}"
            if key not in provider_breakdown:
                provider_breakdown[key] = {"requests": 0, "tokens": 0, "cost": 0.0}
            provider_breakdown[key]["requests"] += 1
            provider_breakdown[key]["tokens"] += req.total_tokens
            provider_breakdown[key]["cost"] += req.cost_usd
        
        return {
            "total_requests": len(self.requests),
            "total_tokens": total_tokens,
            "total_cost_usd": total_cost,
            "remaining_budget_usd": self.max_budget_usd - total_cost,
            "avg_latency_ms": avg_latency,
            "provider_breakdown": provider_breakdown,
            "errors": [r.error for r in self.requests if r.error],
        }


# ═══════════════════════════════════════════════════════════════
# NORMALIZED RESPONSE
# ═══════════════════════════════════════════════════════════════

@dataclass
class LLMResponse:
    """Normalized response across all providers"""
    content: str
    structured_output: Optional[Dict[str, Any]] = None
    finish_reason: Optional[str] = None
    provider: str = "unknown"
    model: str = "unknown"
    usage: Optional[Dict[str, int]] = None
    cost_usd: float = 0.0
    error: Optional[str] = None
    latency_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════
# PROVIDER BASE CLASS
# ═══════════════════════════════════════════════════════════════

class LLMProvider(ABC):
    """Abstract base for all LLM providers"""
    
    def __init__(self, provider_type: ProviderType, budget: TokenBudget):
        self.provider_type = provider_type
        self.budget = budget
        self.timeout = 120
        self.session: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self.session = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
    
    @abstractmethod
    async def is_available(self) -> bool:
        """Check provider availability"""
        pass
    
    @abstractmethod
    def get_small_model(self) -> str:
        """Get small/fast model name"""
        pass
    
    @abstractmethod
    def get_large_model(self) -> str:
        """Get large/powerful model name"""
        pass
    
    def get_model_for_tier(self, tier: TaskTier) -> str:
        """Select model based on tier"""
        return self.get_small_model() if tier == TaskTier.SMALL else self.get_large_model()
    
    @abstractmethod
    async def generate_response(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        """Generate LLM response"""
        pass
    
    async def generate_text(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        tier: TaskTier = TaskTier.SMALL
    ) -> str:
        """Generate plain text response"""
        resp = await self.generate_response(prompt, system, max_tokens, temperature, tier=tier)
        return resp.content if not resp.error else ""
    
    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        mandatory_fields: Optional[List[str]] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> Dict[str, Any]:
        """Generate JSON response with fallback parsing"""
        resp = await self.generate_response(
            prompt, system, max_tokens, 0.1, "json", tier
        )
        
        if resp.error:
            logger.error(f"JSON request failed: {resp.error}")
            return {}
        
        # Try structured output first
        if resp.structured_output:
            return resp.structured_output
        
        # Fallback: parse from content
        if resp.content:
            try:
                clean = re.sub(r'```json\n?|\n?```', '', resp.content).strip()
                parsed = json.loads(clean)
                return parsed
            except:
                # Try regex extraction
                match = re.search(r'\{[\s\S]*\}', resp.content)
                if match:
                    try:
                        return json.loads(match.group(0))
                    except:
                        pass
        
        logger.warning(f"Failed to parse JSON from response: {resp.content[:200]}")
        return {}
    
    def _parse_json_response(self, content: str) -> Optional[Dict]:
        """Robust JSON parsing with multiple fallbacks"""
        if not content:
            return None
        
        try:
            return json.loads(content)
        except:
            pass
        
        # Try without markdown
        try:
            clean = re.sub(r'```json\n?|\n?```', '', content).strip()
            return json.loads(clean)
        except:
            pass
        
        # Extract JSON object
        match = re.search(r'\{[\s\S]*\}', content)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        
        # Extract JSON array
        match = re.search(r'\[[\s\S]*\]', content)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        
        return None


# ═══════════════════════════════════════════════════════════════
# PROVIDER IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════

class DeepSeekProvider(LLMProvider):
    """DeepSeek OpenAI-compatible API"""
    
    def __init__(
        self,
        api_key: str,
        small_model: str = "deepseek-chat",
        large_model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com",
        budget: Optional[TokenBudget] = None
    ):
        super().__init__(ProviderType.DEEPSEEK, budget or TokenBudget())
        self.api_key = api_key
        self.small_model = small_model
        self.large_model = large_model
        self.base_url = base_url.rstrip("/")
    
    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.small_model, "messages": [{"role": "user", "content": "test"}]}
                )
                return r.status_code == 200
        except:
            return False
    
    def get_small_model(self) -> str:
        return self.small_model
    
    def get_large_model(self) -> str:
        return self.large_model
    
    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        
        if not self.budget.can_afford(max_tokens, "deepseek", model):
            return LLMResponse(
                content="", provider="deepseek", model=model,
                error="Budget exceeded"
            )
        
        start_time = datetime.now()
        messages = [
            {"role": "system", "content": system or "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
        
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False
        }
        
        if response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        
        try:
            if not self.session:
                self.session = httpx.AsyncClient(timeout=self.timeout)
            
            r = await self.session.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload
            )
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            if r.status_code == 200:
                data = r.json()
                choice = data["choices"][0]
                content = choice.get("message", {}).get("content", "")
                usage = data.get("usage", {})
                
                # Calculate cost
                input_tokens = usage.get("prompt_tokens", 0)
                output_tokens = usage.get("completion_tokens", 0)
                pricing = self.budget._get_pricing("deepseek", model)
                cost = (input_tokens * pricing.input) + (output_tokens * pricing.output)
                
                # Log metrics
                metric = UsageMetrics(
                    provider="deepseek", model=model,
                    input_tokens=input_tokens, output_tokens=output_tokens,
                    total_tokens=input_tokens + output_tokens, cost_usd=cost,
                    latency_ms=latency_ms
                )
                self.budget.log_request(metric)
                
                structured = self._parse_json_response(content) if response_format == "json" else None
                
                return LLMResponse(
                    content=content, structured_output=structured,
                    finish_reason=choice.get("finish_reason"),
                    provider="deepseek", model=model, cost_usd=cost,
                    usage=usage, latency_ms=latency_ms
                )
            else:
                error = f"HTTP {r.status_code}: {r.text[:200]}"
                logger.error(error)
                return LLMResponse(
                    content="", provider="deepseek", model=model,
                    error=error, latency_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
        
        except Exception as e:
            logger.error(f"DeepSeek request failed: {e}")
            return LLMResponse(
                content="", provider="deepseek", model=model,
                error=str(e), latency_ms=(datetime.now() - start_time).total_seconds() * 1000
            )


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        small_model: str = "mistral",
        large_model: str = "llama2",
        budget: Optional[TokenBudget] = None
    ):
        super().__init__(ProviderType.OLLAMA, budget or TokenBudget())
        self.base_url = base_url.rstrip("/")
        self.small_model = small_model
        self.large_model = large_model
    
    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/api/tags")
                return r.status_code == 200
        except:
            return False
    
    def get_small_model(self) -> str:
        return self.small_model
    
    def get_large_model(self) -> str:
        return self.large_model
    
    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        start_time = datetime.now()
        
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system or "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        
        if response_format == "json":
            payload["format"] = "json"
        
        try:
            if not self.session:
                self.session = httpx.AsyncClient(timeout=self.timeout)
            
            r = await self.session.post(f"{self.base_url}/api/chat", json=payload)
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            if r.status_code == 200:
                data = r.json()
                content = data.get("message", {}).get("content", "")
                
                # Ollama doesn't return usage, estimate
                tokens_estimated = len(prompt.split()) + len(content.split())
                
                structured = self._parse_json_response(content) if response_format == "json" else None
                
                return LLMResponse(
                    content=content, structured_output=structured,
                    provider="ollama", model=model, latency_ms=latency_ms,
                    usage={"prompt_tokens": 0, "completion_tokens": 0}
                )
            else:
                return LLMResponse(
                    content="", provider="ollama", model=model,
                    error=f"HTTP {r.status_code}", latency_ms=latency_ms
                )
        
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return LLMResponse(
                content="", provider="ollama", model=model, error=str(e),
                latency_ms=(datetime.now() - start_time).total_seconds() * 1000
            )


class GroqProvider(LLMProvider):
    """Groq cloud inference (free tier)"""
    
    def __init__(
        self,
        api_key: str,
        small_model: str = "mixtral-8x7b-32768",
        large_model: str = "mixtral-8x7b-32768",
        budget: Optional[TokenBudget] = None
    ):
        super().__init__(ProviderType.GROQ, budget or TokenBudget())
        self.api_key = api_key
        self.small_model = small_model
        self.large_model = large_model
        self.base_url = "https://api.groq.com/openai/v1"
    
    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.small_model, "messages": [{"role": "user", "content": "hi"}]}
                )
                return r.status_code == 200
        except:
            return False
    
    def get_small_model(self) -> str:
        return self.small_model
    
    def get_large_model(self) -> str:
        return self.large_model
    
    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        start_time = datetime.now()
        
        messages = [
            {"role": "system", "content": system or "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
        
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        if response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        
        try:
            if not self.session:
                self.session = httpx.AsyncClient(timeout=self.timeout)
            
            r = await self.session.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload
            )
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            if r.status_code == 200:
                data = r.json()
                choice = data["choices"][0]
                content = choice.get("message", {}).get("content", "")
                usage = data.get("usage", {})
                
                structured = self._parse_json_response(content) if response_format == "json" else None
                
                return LLMResponse(
                    content=content, structured_output=structured,
                    finish_reason=choice.get("finish_reason"),
                    provider="groq", model=model,
                    usage=usage, latency_ms=latency_ms, cost_usd=0.0  # Free
                )
            else:
                return LLMResponse(
                    content="", provider="groq", model=model,
                    error=f"HTTP {r.status_code}", latency_ms=latency_ms
                )
        
        except Exception as e:
            logger.error(f"Groq request failed: {e}")
            return LLMResponse(
                content="", provider="groq", model=model, error=str(e),
                latency_ms=(datetime.now() - start_time).total_seconds() * 1000
            )


# ═══════════════════════════════════════════════════════════════
# UNIVERSAL HARNESS
# ═══════════════════════════════════════════════════════════════

class UniversalLLMHarness:
    """
    Provider-agnostic LLM harness
    Auto-selects & falls back between providers
    """
    
    def __init__(
        self,
        primary_provider: ProviderType = ProviderType.DEEPSEEK,
        fallback_providers: Optional[List[ProviderType]] = None,
        max_budget_usd: float = 100.0,
        **provider_config
    ):
        self.budget = TokenBudget(max_budget_usd)
        self.primary_provider = primary_provider
        self.fallback_providers = fallback_providers or [
            ProviderType.GROQ,
            ProviderType.OLLAMA
        ]
        self.provider_config = provider_config
        self.active_provider: Optional[LLMProvider] = None
    
    async def initialize(self):
        """Initialize & test primary provider, fallback if needed"""
        logger.info(f"[HARNESS] Initializing {self.primary_provider.value}...")
        
        # Try primary
        self.active_provider = self._create_provider(self.primary_provider)
        if await self.active_provider.is_available():
            logger.info(f"✓ Using {self.primary_provider.value}")
            return
        
        logger.warning(f"✗ {self.primary_provider.value} unavailable, trying fallbacks...")
        
        # Try fallbacks
        for fb in self.fallback_providers:
            logger.info(f"[HARNESS] Trying {fb.value}...")
            self.active_provider = self._create_provider(fb)
            if await self.active_provider.is_available():
                logger.info(f"✓ Using {fb.value}")
                return
            logger.warning(f"✗ {fb.value} unavailable")
        
        raise RuntimeError("No LLM provider available!")
    
    def _create_provider(self, provider_type: ProviderType) -> LLMProvider:
        """Factory for provider instances"""
        if provider_type == ProviderType.DEEPSEEK:
            return DeepSeekProvider(
                api_key=self.provider_config.get("deepseek_api_key", ""),
                small_model=self.provider_config.get("deepseek_small_model", "deepseek-chat"),
                large_model=self.provider_config.get("deepseek_large_model", "deepseek-chat"),
                budget=self.budget
            )
        
        elif provider_type == ProviderType.GROQ:
            return GroqProvider(
                api_key=self.provider_config.get("groq_api_key", ""),
                small_model=self.provider_config.get("groq_small_model", "mixtral-8x7b-32768"),
                large_model=self.provider_config.get("groq_large_model", "mixtral-8x7b-32768"),
                budget=self.budget
            )
        
        elif provider_type == ProviderType.OLLAMA:
            return OllamaProvider(
                base_url=self.provider_config.get("ollama_base_url", "http://localhost:11434"),
                small_model=self.provider_config.get("ollama_small_model", "mistral"),
                large_model=self.provider_config.get("ollama_large_model", "llama2"),
                budget=self.budget
            )
        
        else:
            raise ValueError(f"Unsupported provider: {provider_type}")
    
    async def generate_response(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        """Generate response from active provider"""
        if not self.active_provider:
            await self.initialize()
        
        return await self.active_provider.generate_response(
            prompt, system, max_tokens, temperature, response_format, tier
        )
    
    async def generate_text(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        tier: TaskTier = TaskTier.SMALL
    ) -> str:
        """Generate text"""
        resp = await self.generate_response(prompt, system, max_tokens, tier=tier)
        return resp.content if not resp.error else ""
    
    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        tier: TaskTier = TaskTier.SMALL
    ) -> Dict[str, Any]:
        """Generate JSON with fallback parsing"""
        resp = await self.generate_response(
            prompt, system, max_tokens, 0.1, "json", tier
        )
        return resp.structured_output or {}
    
    def stats(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return self.budget.stats()
    
    async def close(self):
        """Cleanup"""
        if self.active_provider and self.active_provider.session:
            await self.active_provider.session.aclose()


async def demo():
    """Example usage"""
    import os
    
    harness = UniversalLLMHarness(
        primary_provider=ProviderType.DEEPSEEK,
        fallback_providers=[ProviderType.GROQ, ProviderType.OLLAMA],
        max_budget_usd=50.0,
        deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", "sk-..."),
        groq_api_key=os.getenv("GROQ_API_KEY", ""),
    )
    
    try:
        await harness.initialize()
        
        # Text generation
        text = await harness.generate_text("What is cybersecurity?", max_tokens=256)
        print(f"[TEXT]\n{text}\n")
        
        # JSON generation
        json_resp = await harness.generate_json(
            "List 3 security vulnerabilities in JSON format",
            max_tokens=512
        )
        print(f"[JSON]\n{json.dumps(json_resp, indent=2)}\n")
        
        # Stats
        print(f"[STATS]\n{json.dumps(harness.stats(), indent=2)}")
    
    finally:
        await harness.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(demo())