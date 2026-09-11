
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


# Common bearer-token key names captured across ~all auth APIs seen in
# the wild. Matched case-insensitively. Order matters — `access_token`
# is preferred over generic `token` when both appear.
_TOKEN_KEYS = (
    "access_token", "id_token", "jwt", "session_token", "sessionToken",
    "authToken", "auth_token", "bearer", "token",
)


def _extract_token(payload) -> Optional[str]:
    seen: list = []
    def _walk(node):
        if isinstance(node, dict):
            for want in _TOKEN_KEYS:
                for k, v in node.items():
                    if isinstance(k, str) and k.lower() == want.lower() and isinstance(v, str) and len(v) >= 8:
                        seen.append(v)
                        return
            for v in node.values():
                if isinstance(v, (dict, list)):
                    _walk(v)
                    if seen:
                        return
        elif isinstance(node, list):
            for v in node:
                _walk(v)
                if seen:
                    return
    _walk(payload)
    return seen[0] if seen else None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Actuators:

    def __init__(self, base_url: str, auth_headers: Optional[Dict[str, str]] = None,
                 timeout: int = 20, scope_validator: Optional[Any] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_headers: Dict[str, str] = dict(auth_headers or {})
        self.last_responses: list = []
        self.scope_validator = scope_validator

    def _in_scope(self, url: str) -> bool:
        try:
            from core.security.policy_engine import get_policy_engine
            host = urlparse(url).hostname or url
            decision = get_policy_engine().authorize_browser_request(url)
            if not decision.allowed:
                logger.warning(f"[Actuators] BLOCKED out-of-scope target '{url}': {decision.reason}")
                return False
            return True
        except Exception as e:
            logger.warning(f"[Actuators] Error validating target '{url}': {e}")
            return False


    async def http_request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
                           json_body: Any = None, data: Any = None,
                           params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        if not self._in_scope(url):
            return {"error": "target out of authorized scope", "blocked": True}
        merged = {**self.session_headers, **(headers or {})}
        # `HTTP_ACTUATOR_VERIFY_TLS=1` restores TLS verification. Blanket
        # `verify=False` is appropriate against self-signed pentesting targets
        # but a foot-gun when the actuator is repurposed against production.
        import os as _os_actu
        _verify_tls = _os_actu.environ.get("HTTP_ACTUATOR_VERIFY_TLS", "").strip() == "1"
        try:
            from core.network.network_broker import get_network_broker
            r = await get_network_broker().request(method.upper(), url, headers=merged, json=json_body,
                                                   data=data, params=params, timeout=self.timeout, verify=_verify_tls)
            body = r.text
            # Structured token auto-capture — the previous
            # `'"token"' in body.lower()` substring missed `access_token`,
            # `id_token`, `jwt`, `sessionToken`, and nested paths. Parse
            # JSON if the response is JSON, then walk a small allowlist
            # of key names at any depth.
            try:
                j = r.json()
                tok = _extract_token(j) if isinstance(j, (dict, list)) else None
                if tok:
                    self.session_headers["Authorization"] = f"Bearer {tok}"
            except Exception as e:
                logger.debug("token extraction from response body failed: %s", e)
            for k, v in r.cookies.items():
                cur = self.session_headers.get("Cookie", "")
                self.session_headers["Cookie"] = (cur + f"; {k}={v}").strip("; ")
            obs = {"status": r.status_code, "len": len(body), "body": body[:4000],
                   "headers": dict(r.headers)}
            self.last_responses.append(obs)
            return obs
        except Exception as e:
            return {"error": str(e)}


    def jwt_decode(self, token: str) -> Dict[str, Any]:
        try:
            h, p, _ = token.split(".")
            return {"header": json.loads(_b64url_decode(h)), "payload": json.loads(_b64url_decode(p))}
        except Exception as e:
            return {"error": f"decode failed: {e}"}

    def jwt_forge(self, payload: Dict[str, Any], alg: str = "none", key: str = "") -> Dict[str, Any]:
        try:
            header = {"typ": "JWT", "alg": alg}
            h = _b64url(json.dumps(header, separators=(",", ":")).encode())
            p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = f"{h}.{p}".encode()
            if alg.lower() == "none":
                sig = ""
            elif alg.upper() == "HS256":
                sig = _b64url(hmac.new(key.encode(), signing_input, hashlib.sha256).digest())
            else:
                return {"error": f"unsupported alg {alg}"}
            return {"token": f"{h}.{p}.{sig}"}
        except Exception as e:
            return {"error": str(e)}


    def encode(self, text: str, scheme: str = "base64") -> Dict[str, Any]:
        try:
            if scheme == "base64":
                return {"result": base64.b64encode(text.encode()).decode()}
            if scheme == "base64url":
                return {"result": _b64url(text.encode())}
            if scheme in ("md5", "sha1", "sha256"):
                return {"result": hashlib.new(scheme, text.encode()).hexdigest()}
            if scheme == "hex":
                return {"result": text.encode().hex()}
            return {"error": f"unknown scheme {scheme}"}
        except Exception as e:
            return {"error": str(e)}

    def decode(self, text: str, scheme: str = "base64") -> Dict[str, Any]:
        try:
            if scheme == "base64":
                return {"result": base64.b64decode(text).decode("utf-8", "ignore")}
            if scheme == "base64url":
                return {"result": _b64url_decode(text).decode("utf-8", "ignore")}
            if scheme == "hex":
                return {"result": bytes.fromhex(text).decode("utf-8", "ignore")}
            return {"error": f"unknown scheme {scheme}"}
        except Exception as e:
            return {"error": str(e)}


    async def upload_file(self, path: str, filename: str, content: str,
                          content_type: str = "application/octet-stream",
                          field: str = "file") -> Dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        if not self._in_scope(url):
            return {"error": "target out of authorized scope", "blocked": True}
        import os as _os_upl
        _verify_tls_up = _os_upl.environ.get("HTTP_ACTUATOR_VERIFY_TLS", "").strip() == "1"
        try:
            from core.network.network_broker import get_network_broker
            files = {field: (filename, content.encode(), content_type)}
            r = await get_network_broker().request("POST", url, files=files, headers=self.session_headers,
                                                   timeout=self.timeout, verify=_verify_tls_up)
            return {"status": r.status_code, "body": r.text[:4000]}
        except Exception as e:
            return {"error": str(e)}


# Tool schemas the LLM tool-calling / ReAct loop advertises.
ACTUATOR_TOOLS = [
    {"type": "function", "function": {
        "name": "http_request",
        "description": "Perform an HTTP request against the authorized target (REST/GraphQL, "
                       "exploit payloads, login, etc.).",
        "parameters": {"type": "object", "properties": {
            "method": {"type": "string"},
            "path": {"type": "string", "description": "relative path or absolute in-scope URL"},
            "headers": {"type": "object"}, "json_body": {"type": "object"},
            "params": {"type": "object"}}, "required": ["method", "path"]}}},
    {"type": "function", "function": {
        "name": "jwt_decode",
        "description": "Decode a JWT to inspect its header and payload.",
        "parameters": {"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]}}},
    {"type": "function", "function": {
        "name": "jwt_forge",
        "description": "Forge a JWT. alg='none' (none-algorithm) or 'HS256' with key "
                       "(algorithm-confusion). Returns the token.",
        "parameters": {"type": "object", "properties": {
            "payload": {"type": "object"}, "alg": {"type": "string"}, "key": {"type": "string"}},
            "required": ["payload"]}}},
    {"type": "function", "function": {
        "name": "encode",
        "description": "Encode/hash text (base64, base64url, md5, sha1, sha256, hex).",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string"}, "scheme": {"type": "string"}}, "required": ["text"]}}},
    {"type": "function", "function": {
        "name": "decode",
        "description": "Decode text (base64, base64url, hex).",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string"}, "scheme": {"type": "string"}}, "required": ["text"]}}},
    {"type": "function", "function": {
        "name": "upload_file",
        "description": "Upload a crafted file to an endpoint.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "filename": {"type": "string"},
            "content": {"type": "string"}, "content_type": {"type": "string"}},
            "required": ["path", "filename", "content"]}}},
]
