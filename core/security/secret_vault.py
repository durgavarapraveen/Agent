"""P0.5 — Secret Isolation Vault.

HTTP captures, checkpoints, logs, findings, and agent state must not
casually contain passwords, session cookies, Authorization headers, JWTs,
API keys, CSRF tokens, OAuth codes, or other secrets.

This module provides:
  - SecretVault: reference-based secret storage (secrets in, refs out)
  - redact_secrets(): replace secrets in text with <SECRET_REF:id> tokens
  - inject_secrets(): restore refs back to raw values (explicit capability)
  - Configurable retention with auto-expiry
  - Integration points for logging, LLM prompts, and checkpoints

Usage:
    from core.security.secret_vault import get_vault

    vault = get_vault()
    ref = vault.store("Bearer eyJhbGci...", category="authorization")
    # ref == "<SECRET_REF:a1b2c3d4>"

    # In logs/prompts/checkpoints, use ref instead of raw value.
    # To retrieve (requires explicit capability):
    raw = vault.retrieve(ref)
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_REF_PREFIX = "<SECRET_REF:"
_REF_SUFFIX = ">"
_REF_PATTERN = re.compile(r"<SECRET_REF:([a-f0-9]{12})>")

# Default retention: 1 hour
_DEFAULT_RETENTION_SECONDS = 3600.0
_MAX_SECRET_BYTES = 100_000
_MAX_VAULT_SIZE = 10_000


class SecretCategory(str, Enum):
    PASSWORD = "password"
    SESSION_COOKIE = "session_cookie"
    AUTHORIZATION = "authorization"
    JWT = "jwt"
    API_KEY = "api_key"
    CSRF_TOKEN = "csrf_token"
    OAUTH_CODE = "oauth_code"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    CREDENTIAL = "credential"
    OTHER = "other"


@dataclass
class VaultEntry:
    ref_id: str
    value: str
    category: SecretCategory
    fingerprint: str
    created_at: float = field(default_factory=time.monotonic)
    expires_at: float = 0.0
    access_count: int = 0
    last_accessed: float = 0.0

    @property
    def expired(self) -> bool:
        return self.expires_at > 0 and time.monotonic() > self.expires_at

    @property
    def ref(self) -> str:
        return f"{_REF_PREFIX}{self.ref_id}{_REF_SUFFIX}"


# ── Secret detection patterns ────────────────────────────────────────────

_SECRET_PATTERNS: List[Tuple[re.Pattern, SecretCategory]] = [
    # Bearer tokens
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/]{20,}=*"),
     SecretCategory.BEARER_TOKEN),
    # JWTs (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"),
     SecretCategory.JWT),
    # Authorization header values
    (re.compile(r"(?i)(?:Authorization|X-Api-Key|X-Auth-Token)\s*[:=]\s*[\"']?([^\s\"',}{]{8,})"),
     SecretCategory.AUTHORIZATION),
    # Passwords in key=value patterns
    (re.compile(r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*[\"']?([^\s\"',}{]{4,})"),
     SecretCategory.PASSWORD),
    # API keys (common formats)
    (re.compile(r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?key|token)\s*[:=]\s*[\"']?([A-Za-z0-9\-\._~\+\/]{16,})"),
     SecretCategory.API_KEY),
    # AWS access keys
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), SecretCategory.API_KEY),
    # GitHub PATs
    (re.compile(r"\bgh[pso]_[A-Za-z0-9]{20,}\b"), SecretCategory.API_KEY),
    # Stripe keys
    (re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b"), SecretCategory.API_KEY),
    # Session cookies
    (re.compile(r"(?i)(?:session|sid|sess_id|PHPSESSID|JSESSIONID|connect\.sid)\s*[=:]\s*[\"']?([A-Za-z0-9\-\._~\+\/]{16,})"),
     SecretCategory.SESSION_COOKIE),
    # Set-Cookie headers with session-like values
    (re.compile(r"(?i)Set-Cookie:\s*\S+=[A-Za-z0-9\-\._~\+\/]{20,}"),
     SecretCategory.SESSION_COOKIE),
    # CSRF tokens
    (re.compile(r"(?i)(?:csrf|xsrf|_token|authenticity_token)\s*[=:]\s*[\"']?([A-Za-z0-9\-\._~\+\/]{16,})"),
     SecretCategory.CSRF_TOKEN),
    # OAuth codes
    (re.compile(r"(?i)(?:code|grant|refresh_token|access_token)\s*[=:]\s*[\"']?([A-Za-z0-9\-\._~\+\/]{16,})"),
     SecretCategory.OAUTH_CODE),
    # Private keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
     SecretCategory.PRIVATE_KEY),
    # Slack tokens
    (re.compile(r"\bxox[bpoa]-[A-Za-z0-9\-]{10,}\b"), SecretCategory.API_KEY),
    # SendGrid
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), SecretCategory.API_KEY),
]


def _fingerprint(value: str) -> str:
    """Content-based fingerprint to deduplicate identical secrets."""
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


# ── Secret Vault ─────────────────────────────────────────────────────────

class SecretVault:
    """Reference-based secret storage. Secrets go in, refs come out.

    Raw secret values are stored in memory only. References like
    <SECRET_REF:a1b2c3d4> replace them in logs, prompts, and checkpoints.
    Retrieval requires explicit call — no accidental leakage.
    """

    _instance: Optional["SecretVault"] = None
    _lock = threading.RLock()

    @classmethod
    def get(cls) -> "SecretVault":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        with cls._lock:
            cls._instance = None

    def __init__(self, retention_seconds: float = _DEFAULT_RETENTION_SECONDS):
        self._entries: Dict[str, VaultEntry] = {}
        self._by_fingerprint: Dict[str, str] = {}  # fingerprint -> ref_id
        self._retention = retention_seconds
        self._vlock = threading.Lock()

    # ── Store ────────────────────────────────────────────────────────────

    def store(self, secret: str,
              category: "SecretCategory | str" = SecretCategory.OTHER,
              retention: Optional[float] = None) -> str:
        """Store a secret and return its reference string."""
        if not secret or not isinstance(secret, str):
            return ""
        if isinstance(category, str):
            try:
                category = SecretCategory(category)
            except ValueError:
                category = SecretCategory.OTHER
        if len(secret.encode("utf-8", "ignore")) > _MAX_SECRET_BYTES:
            logger.warning("[SecretVault] secret too large, truncating")
            secret = secret[:_MAX_SECRET_BYTES]

        fp = _fingerprint(secret)

        with self._vlock:
            # Deduplicate: same content gets same ref
            if fp in self._by_fingerprint:
                existing_id = self._by_fingerprint[fp]
                if existing_id in self._entries:
                    entry = self._entries[existing_id]
                    if not entry.expired:
                        return entry.ref

            # Evict expired entries if vault is full
            if len(self._entries) >= _MAX_VAULT_SIZE:
                self._evict_expired()
            if len(self._entries) >= _MAX_VAULT_SIZE:
                logger.error("[SecretVault] vault full, cannot store")
                return ""

            ref_id = uuid.uuid4().hex[:12]
            ttl = retention if retention is not None else self._retention
            entry = VaultEntry(
                ref_id=ref_id,
                value=secret,
                category=category,
                fingerprint=fp,
                expires_at=time.monotonic() + ttl if ttl > 0 else 0.0,
            )
            self._entries[ref_id] = entry
            self._by_fingerprint[fp] = ref_id

        logger.debug("[SecretVault] stored %s (category=%s)", entry.ref, category.value)
        return entry.ref

    # ── Retrieve ─────────────────────────────────────────────────────────

    def retrieve(self, ref_or_id: str) -> Optional[str]:
        """Retrieve a raw secret by its reference or ref_id.

        This is the ONLY way to get raw secrets back. Callers must have
        explicit authorization — this is NOT for casual access.
        """
        ref_id = ref_or_id
        m = _REF_PATTERN.search(ref_or_id)
        if m:
            ref_id = m.group(1)

        with self._vlock:
            entry = self._entries.get(ref_id)
            if not entry:
                return None
            if entry.expired:
                del self._entries[ref_id]
                self._by_fingerprint.pop(entry.fingerprint, None)
                return None
            entry.access_count += 1
            entry.last_accessed = time.monotonic()
            return entry.value

    # ── Redact ───────────────────────────────────────────────────────────

    def redact(self, text: str) -> str:
        """Replace all detected secrets in text with vault references.

        Secrets are stored in the vault and replaced with <SECRET_REF:id>.
        This is the primary integration point for logging and LLM prompts.
        """
        if not text or not isinstance(text, str):
            return text or ""

        for pattern, category in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                secret_value = match.group(0)
                if _REF_PREFIX in secret_value:
                    continue
                ref = self.store(secret_value, category=category)
                if ref:
                    text = text.replace(secret_value, ref)

        return text

    def redact_dict(self, data: Dict[str, Any],
                    sensitive_keys: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Redact secret values in a dictionary (shallow copy).

        Keys matching sensitive_keys have their values vault-stored.
        All string values are pattern-scanned regardless.
        """
        if not data or not isinstance(data, dict):
            return data or {}

        if sensitive_keys is None:
            sensitive_keys = _SENSITIVE_KEYS

        out = {}
        for k, v in data.items():
            k_lower = k.lower().replace("-", "_").replace(" ", "_")
            if k_lower in sensitive_keys and isinstance(v, str) and v:
                ref = self.store(v, category=_categorize_key(k_lower))
                out[k] = ref
            elif isinstance(v, str):
                out[k] = self.redact(v)
            elif isinstance(v, dict):
                out[k] = self.redact_dict(v, sensitive_keys)
            elif isinstance(v, list):
                out[k] = [
                    self.redact(item) if isinstance(item, str)
                    else self.redact_dict(item, sensitive_keys) if isinstance(item, dict)
                    else item
                    for item in v
                ]
            else:
                out[k] = v
        return out

    # ── Inject (restore) ─────────────────────────────────────────────────

    def inject(self, text: str) -> str:
        """Replace all <SECRET_REF:id> tokens with raw secret values.

        Use ONLY when the raw secret is needed for an authorized operation
        (e.g., replaying an authenticated HTTP request against in-scope target).
        """
        if not text or not isinstance(text, str):
            return text or ""

        def _replace(m):
            raw = self.retrieve(m.group(1))
            return raw if raw is not None else m.group(0)

        return _REF_PATTERN.sub(_replace, text)

    def inject_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore all secret references in a dictionary."""
        if not data or not isinstance(data, dict):
            return data or {}
        out = {}
        for k, v in data.items():
            if isinstance(v, str):
                out[k] = self.inject(v)
            elif isinstance(v, dict):
                out[k] = self.inject_dict(v)
            elif isinstance(v, list):
                out[k] = [
                    self.inject(item) if isinstance(item, str)
                    else self.inject_dict(item) if isinstance(item, dict)
                    else item
                    for item in v
                ]
            else:
                out[k] = v
        return out

    # ── Housekeeping ─────────────────────────────────────────────────────

    def _evict_expired(self) -> int:
        """Remove expired entries. Returns count evicted."""
        now = time.monotonic()
        expired_ids = [
            eid for eid, e in self._entries.items()
            if e.expires_at > 0 and now > e.expires_at
        ]
        for eid in expired_ids:
            entry = self._entries.pop(eid, None)
            if entry:
                self._by_fingerprint.pop(entry.fingerprint, None)
        return len(expired_ids)

    def clear(self) -> None:
        """Wipe all secrets from the vault."""
        with self._vlock:
            self._entries.clear()
            self._by_fingerprint.clear()

    @property
    def size(self) -> int:
        with self._vlock:
            return len(self._entries)

    def stats(self) -> Dict[str, Any]:
        with self._vlock:
            categories: Dict[str, int] = {}
            for e in self._entries.values():
                categories[e.category.value] = categories.get(e.category.value, 0) + 1
            return {
                "total_entries": len(self._entries),
                "categories": categories,
                "expired": sum(1 for e in self._entries.values() if e.expired),
            }

    def has_ref(self, ref_or_id: str) -> bool:
        m = _REF_PATTERN.search(ref_or_id)
        ref_id = m.group(1) if m else ref_or_id
        with self._vlock:
            entry = self._entries.get(ref_id)
            return entry is not None and not entry.expired


# ── Sensitive key classification ─────────────────────────────────────────

_SENSITIVE_KEYS: Set[str] = {
    "password", "passwd", "pwd", "pass",
    "authorization", "auth", "auth_header",
    "cookie", "set_cookie", "session", "session_id", "sid",
    "token", "access_token", "refresh_token", "id_token",
    "bearer", "bearer_token",
    "api_key", "apikey", "secret_key", "secret",
    "csrf", "csrf_token", "xsrf_token", "_token",
    "authenticity_token",
    "x_api_key", "x_auth_token",
    "private_key", "client_secret",
    "jwt", "jws",
    "oauth_code", "code", "grant",
    "aws_secret_access_key", "aws_session_token",
}


def _categorize_key(key: str) -> SecretCategory:
    """Map a dictionary key name to a secret category."""
    k = key.lower()
    if any(p in k for p in ("password", "passwd", "pwd")):
        return SecretCategory.PASSWORD
    if any(p in k for p in ("authorization", "bearer", "auth")):
        return SecretCategory.AUTHORIZATION
    if any(p in k for p in ("cookie", "session", "sid")):
        return SecretCategory.SESSION_COOKIE
    if "jwt" in k or "jws" in k:
        return SecretCategory.JWT
    if any(p in k for p in ("api_key", "apikey", "secret_key", "secret")):
        return SecretCategory.API_KEY
    if any(p in k for p in ("csrf", "xsrf", "_token", "authenticity")):
        return SecretCategory.CSRF_TOKEN
    if any(p in k for p in ("oauth", "code", "grant", "refresh")):
        return SecretCategory.OAUTH_CODE
    if "private_key" in k:
        return SecretCategory.PRIVATE_KEY
    return SecretCategory.OTHER


# ── Module-level helpers ─────────────────────────────────────────────────

def get_vault() -> SecretVault:
    return SecretVault.get()


def redact_secrets(text: str) -> str:
    """Convenience: redact all secrets in text using the global vault."""
    return get_vault().redact(text)


def redact_secrets_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience: redact secrets in a dict using the global vault."""
    return get_vault().redact_dict(data)


def inject_secrets(text: str) -> str:
    """Convenience: restore secret refs. Requires explicit authorization."""
    return get_vault().inject(text)
