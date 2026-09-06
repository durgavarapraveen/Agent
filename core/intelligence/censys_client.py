"""
Censys Client Implementation
Uses Censys Platform API v2 with Personal Access Token (PAT) authentication.
Header: Authorization: Bearer <CENSYS_PAT>
"""

import logging
from typing import Dict, Any, Optional
import httpx

from core.common.config import get_config

logger = logging.getLogger(__name__)

CENSYS_BASE_URL = "https://search.censys.io/api/v2"


def _sanitize_string(text: str, token: str) -> str:
    """Mask token string from any output or exception messages."""
    if not token or not text:
        return text
    return text.replace(token, "[MASKED_PAT]")


class CensysClient:
    """
    Censys Platform API Client using Personal Access Token (PAT).
    """

    def __init__(self, api_token: Optional[str] = None, base_url: str = CENSYS_BASE_URL, timeout: float = 30.0):
        config = get_config()
        token = api_token if api_token is not None else config.CENSYS_PAT
        
        # Legacy fallback deprecation warning check
        legacy_keys = ["CENSYS_UID", "CENSYS_SECRET", "CENSYS_API_ID", "CENSYS_API_SECRET"]
        found_legacy = [k for k in legacy_keys if config.get(k)]
        if found_legacy:
            logger.warning(
                f"[CensysClient] Legacy Censys credentials ({', '.join(found_legacy)}) are deprecated. "
                "Please configure CENSYS_PAT instead."
            )

        if not token or token.strip() == "" or token == "xxxxx":
            self.api_token = ""
            logger.warning("[CensysClient] Censys PAT not configured or contains placeholder value.")
        else:
            self.api_token = token.strip()
            logger.info("[CensysClient] Censys authentication configured successfully.")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._cache: Dict[str, Dict[str, Any]] = {}

    @property
    def is_configured(self) -> bool:
        """Check if client has a valid token configured."""
        return bool(self.api_token and self.api_token != "xxxxx")

    def _get_headers(self) -> Dict[str, str]:
        """Generate request headers with Bearer Token authentication.

        Callers must gate on `is_configured` before invoking this. All public
        `search_*`/`get_*` methods now return an empty result set instead of
        raising, so this helper is only reached when a token is present.
        """
        if not self.is_configured:
            raise RuntimeError("Censys PAT not configured; caller should short-circuit")
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "User-Agent": "AntiGravity-Security-Agent/1.0"
        }

    async def search_hosts(self, query: str, per_page: int = 10) -> Dict[str, Any]:
        """
        Search hosts using Censys Platform API v2 (cached for Free Tier preservation).
        Endpoint: GET /hosts/search
        """
        if not self.is_configured:
            # Graceful degradation — OSINT is optional. Log at INFO once per
            # call and return an empty result rather than exploding the whole
            # recon phase because one provider isn't configured.
            logger.info("[CensysClient] CENSYS_PAT not configured; returning empty result")
            return {"result": {"hits": [], "total": 0}, "code": "unconfigured"}

        cache_key = f"hosts:{query}:{per_page}"
        if cache_key in self._cache:
            logger.debug(f"[CensysClient] Returning cached host search results for '{query}' (Free Tier optimization)")
            return self._cache[cache_key]

        url = f"{self.base_url}/hosts/search"
        params = {"q": query, "per_page": min(per_page, 100)}
        headers = self._get_headers()

        from core.intelligence._provider_gate import get_gate, ProviderCircuitOpen
        _gate = get_gate("censys")
        try:
            async with _gate.acquire():
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(url, params=params, headers=headers)
                    if resp.status_code == 429:
                        _gate.record_failure(reason="429")
                    result = self._handle_response(resp)
                    _gate.record_success()
                    self._cache[cache_key] = result
                    return result
        except ProviderCircuitOpen as ce:
            logger.warning("[CensysClient] %s — returning empty result", ce)
            return {"result": {"hits": [], "total": 0}, "code": "circuit_open"}
        except (PermissionError, ValueError):
            raise
        except Exception as e:
            _gate.record_failure(reason=type(e).__name__)
            sanitized_msg = _sanitize_string(str(e), self.api_token)
            logger.error(f"[CensysClient] Host search failed: {sanitized_msg}")
            raise RuntimeError(f"Censys host search error: {sanitized_msg}") from None

    async def search_certificates(self, query: str, per_page: int = 10) -> Dict[str, Any]:
        """
        Search certificates using Censys Platform API v2 (cached for Free Tier preservation).
        Endpoint: GET /certificates/search
        """
        if not self.is_configured:
            # Graceful degradation — OSINT is optional. Log at INFO once per
            # call and return an empty result rather than exploding the whole
            # recon phase because one provider isn't configured.
            logger.info("[CensysClient] CENSYS_PAT not configured; returning empty result")
            return {"result": {"hits": [], "total": 0}, "code": "unconfigured"}

        cache_key = f"certs:{query}:{per_page}"
        if cache_key in self._cache:
            logger.debug(f"[CensysClient] Returning cached cert search results for '{query}' (Free Tier optimization)")
            return self._cache[cache_key]

        url = f"{self.base_url}/certificates/search"
        params = {"q": query, "per_page": min(per_page, 100)}
        headers = self._get_headers()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, params=params, headers=headers)
                result = self._handle_response(resp)
                self._cache[cache_key] = result
                return result
        except (PermissionError, ValueError):
            raise
        except Exception as e:
            sanitized_msg = _sanitize_string(str(e), self.api_token)
            logger.error(f"[CensysClient] Certificate search failed: {sanitized_msg}")
            raise RuntimeError(f"Censys certificate search error: {sanitized_msg}") from None

    async def get_host(self, ip: str) -> Dict[str, Any]:
        """
        Get detailed information for a specific host by IP.
        Endpoint: GET /hosts/{ip}
        """
        if not self.is_configured:
            # Graceful degradation — OSINT is optional. Log at INFO once per
            # call and return an empty result rather than exploding the whole
            # recon phase because one provider isn't configured.
            logger.info("[CensysClient] CENSYS_PAT not configured; returning empty result")
            return {"result": {"hits": [], "total": 0}, "code": "unconfigured"}

        url = f"{self.base_url}/hosts/{ip}"
        headers = self._get_headers()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                return self._handle_response(resp)
        except (PermissionError, ValueError):
            raise
        except Exception as e:
            sanitized_msg = _sanitize_string(str(e), self.api_token)
            logger.error(f"[CensysClient] Get host failed for {ip}: {sanitized_msg}")
            raise RuntimeError(f"Censys get host error: {sanitized_msg}") from None

    def _handle_response(self, resp: httpx.Response) -> Dict[str, Any]:
        """Handle HTTP response and status codes with clean error messaging."""
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            self.api_token = ""
            logger.warning("[CensysClient] Censys API request failed: 401 Unauthorized (Invalid or expired PAT). Disabling Censys for session.")
            raise PermissionError("Censys authentication failed: Invalid or expired Personal Access Token (PAT).")
        elif resp.status_code == 429:
            logger.warning("[CensysClient] Censys API request rate limited: 429 Too Many Requests")
            raise RuntimeError("Censys API rate limit exceeded. Please try again later.")
        elif resp.status_code == 403:
            self.api_token = ""
            logger.warning("[CensysClient] Censys API request forbidden: 403 Forbidden. Disabling Censys for session.")
            raise PermissionError("Censys API request forbidden: Insufficient permissions for this resource.")
        else:
            msg = f"Censys API error HTTP {resp.status_code}: {resp.text[:200]}"
            sanitized_msg = _sanitize_string(msg, self.api_token)
            logger.error(f"[CensysClient] {sanitized_msg}")
            raise RuntimeError(sanitized_msg)
