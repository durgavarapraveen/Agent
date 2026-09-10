from __future__ import annotations

import re
from typing import Any, Dict, List

_FALLBACK = [
    (re.compile(r'(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*'), 'Bearer [REDACTED]'),
    (re.compile(r'\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}'), '[REDACTED_JWT]'),
    (re.compile(r'(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?token|refresh[_\-]?token)"?\s*[:=]\s*"?[^"\s,&}]{4,}'), r'\1=[REDACTED]'),
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b'), '[REDACTED_STRIPE]'),
    (re.compile(r'\b\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b'), '[REDACTED_CARD]'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
]


def _fallback_mask(text: str) -> str:
    for rx, repl in _FALLBACK:
        text = rx.sub(repl, text)
    return text


def redact_for_llm(text: Any) -> Any:
    if not isinstance(text, str) or not text:
        return text
    # P0.5: vault-based redaction first (stores secrets, returns refs)
    try:
        from core.security.secret_vault import redact_secrets
        text = redact_secrets(text)
    except Exception as e:
        raise SystemError(f"Policy enforcement failed: {e}") from e
    # Legacy pattern masking on anything the vault didn't catch
    try:
        from core.reporting.reporting import mask_sensitive_data
        return mask_sensitive_data(text, enabled=True)
    except Exception:
        return _fallback_mask(text)


def redact_messages(messages: List[Dict]) -> List[Dict]:
    out = []
    for m in messages or []:
        if isinstance(m, dict) and isinstance(m.get("content"), str):
            m = {**m, "content": redact_for_llm(m["content"])}
        out.append(m)
    return out
