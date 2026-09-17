from __future__ import annotations

import base64
import logging
import urllib.parse
from typing import List

from core.payloads.schema import Payload

logger = logging.getLogger(__name__)


def _url(p: str) -> str:
    return urllib.parse.quote(p, safe="")


def _double_url(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def _hex_entities(p: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in p)


def _dec_entities(p: str) -> str:
    return "".join(f"&#{ord(c)};" for c in p)


def _unicode_esc(p: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in p)


def _b64(p: str) -> str:
    return base64.b64encode(p.encode()).decode()


def _case_alt(p: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))


# name -> (transform, encoding_tag)
_ENCODERS = {
    "url": (_url, "url"),
    "double_url": (_double_url, "double_url"),
    "hex_entities": (_hex_entities, "hex"),
    "dec_entities": (_dec_entities, "hex"),
    "unicode": (_unicode_esc, "unicode"),
    "base64": (_b64, "base64"),
    "case_alt": (_case_alt, "none"),
}

# Known WAF-specific bypass strategies (encoder subsets that tend to slip through).
_WAF_STRATEGY = {
    "cloudflare": ["url", "double_url", "unicode", "case_alt"],
    "modsecurity": ["hex_entities", "dec_entities", "case_alt"],
    "aws_waf": ["double_url", "unicode", "base64"],
}


class MutationEngine:
    """Runtime payload variant generation via encoding/obfuscation."""

    def mutate(self, payload: Payload, max_variants: int = 5,
               strategies: List[str] = None) -> List[Payload]:
        """Generate encoded/obfuscated variants of a base payload.

        Variants inherit the base's metadata but get their own payload_id
        (derived from mutated text) and an evasion tag for the transform used.
        """
        names = strategies or list(_ENCODERS.keys())
        out: List[Payload] = []
        seen = {payload.payload_text}
        for name in names:
            if len(out) >= max_variants:
                break
            fn, enc_tag = _ENCODERS[name]
            try:
                text = fn(payload.payload_text)
            except Exception as e:
                logger.debug("mutation %s failed: %s", name, e)
                continue
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(Payload(
                vuln_class=payload.vuln_class,
                payload_text=text,
                subclass=payload.subclass,
                context=payload.context,
                encoding=enc_tag,
                evasion_tags=list(payload.evasion_tags) + [f"mut:{name}"],
                source=payload.source,
                effectiveness_score=payload.effectiveness_score * 0.9,
                waf_bypass_for=payload.waf_bypass_for,
                confirm_patterns=payload.confirm_patterns,
                severity=payload.severity,
            ))
        return out

    def waf_adapt(self, payload: Payload, waf_type: str,
                  blocked_response: str = "") -> List[Payload]:
        """Given a WAF block, generate bypass variants using that WAF's
        known-good encoders. Falls back to the full mutation set."""
        strategies = _WAF_STRATEGY.get((waf_type or "").lower())
        variants = self.mutate(payload, max_variants=len(strategies) if strategies else 5,
                               strategies=strategies)
        for v in variants:
            if waf_type and waf_type.lower() not in v.waf_bypass_for:
                v.waf_bypass_for = list(v.waf_bypass_for) + [waf_type.lower()]
        return variants
