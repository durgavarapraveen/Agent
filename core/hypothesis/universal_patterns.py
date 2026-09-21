"""Universal vulnerability patterns (Tester.txt §4) — the 8 signatures an
experienced pentester applies to ANY technology instead of memorizing attacks.

Two reusable outputs:
  1. `checklist_text(...)` — a per-surface checklist injected into the dynamic
     hypothesis prompt so the LLM instantiates patterns systematically (cheap,
     JUNIOR tier).
  2. `deterministic_hypotheses(...)` — concrete, no-LLM probes for the patterns
     that don't need a model (info disclosure / insecure storage: /.git, /.env,
     source maps, backups), emitted as `DynamicHypothesis` the engine runs as-is.

Generalizes to any tech because patterns are behavioural, not payload-specific.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin

from core.orchestration.test_plan import TestFamily


@dataclass(frozen=True)
class Pattern:
    id: str
    name: str
    signature: str          # what the flaw looks like
    appears_in: str         # where it shows up
    how_to_test: str        # how a pentester probes it
    families: frozenset     # TestFamily set this pattern belongs to


UNIVERSAL_PATTERNS: List[Pattern] = [
    Pattern("unvalidated_input", "Unvalidated input",
            "user input used in a query/command/markup without validation",
            "search, upload handlers, comments, API params, report generators",
            "inject ' \" < > ; , SQL/`UNION SELECT`, <script>, ;whoami — see if reflected/executed",
            frozenset({TestFamily.INJECTION, TestFamily.API})),
    Pattern("missing_authorization", "Missing authorization",
            "object id in URL/param, no per-request permission check, backend trusts client",
            "/user/123, /orders/456, /api/users/789, file downloads, admin actions",
            "change id (+1/-1/0), access another user's id, guess admin ids — see if data returns",
            frozenset({TestFamily.AUTHZ_IDOR})),
    Pattern("insecure_crypto", "Insecure cryptography",
            "weak algo (MD5/SHA1), predictable randomness, static keys, unsigned/again-signable JWT",
            "password hashing, session tokens, JWT, token generation, encryption mode",
            "hash a value repeatedly, collect tokens for patterns, try to forge/alg-none the JWT",
            frozenset({TestFamily.CRYPTO, TestFamily.AUTH_SESSION})),
    Pattern("insecure_storage", "Insecure storage / secret exposure",
            "plaintext secrets, config/logs/backups reachable, secrets in git history",
            ".env, .git, .bak/.tmp, logs, source maps, config files",
            "request common sensitive paths and confirm secret-shaped content is served",
            frozenset({TestFamily.SECRET_DISCLOSURE, TestFamily.INFRA_CONFIG})),
    Pattern("race_condition", "Race condition (TOCTOU)",
            "check-then-act not atomic; state changes between check and use",
            "payment balance check, coupon limit, refund, points spend, file check-then-delete",
            "fire N identical requests concurrently, watch if both/all succeed",
            frozenset({TestFamily.RACE, TestFamily.BUSINESS_LOGIC})),
    Pattern("broken_logic", "Broken business logic",
            "business rules not enforced; workflows skippable; constraints unchecked",
            "checkout, refunds, shipping/address, discounts, inventory, transfers, privileges",
            "run workflow out of order, skip steps, tamper values (price/qty/role), try invalid combos",
            frozenset({TestFamily.BUSINESS_LOGIC})),
    Pattern("info_disclosure", "Information disclosure",
            "sensitive data in responses/errors, verbose stack traces, version leakage, HTML comments",
            "error pages, API extra fields, headers, robots.txt, source maps, git",
            "trigger errors, diff API responses, read headers/comments, fetch .map/.git/robots",
            frozenset({TestFamily.SECRET_DISCLOSURE, TestFamily.INFRA_CONFIG})),
    Pattern("third_party_trust", "Third-party trust / secret handling",
            "hardcoded API keys, unverified callbacks/webhooks, over-permissive OAuth redirect",
            "payment/email/cloud keys, webhook endpoints, OAuth redirect_uri, SAML assertions",
            "search code/env for secrets, tamper callback params, test OAuth redirect_uri validation",
            frozenset({TestFamily.API, TestFamily.SECRET_DISCLOSURE, TestFamily.AUTH_SESSION})),
]

# Common sensitive paths for the deterministic info-disclosure/storage probes.
_SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/config.json",
    "/wp-config.php.bak", "/backup.zip", "/db.sql", "/robots.txt",
    "/.aws/credentials", "/server-status", "/actuator/env", "/phpinfo.php",
]


def patterns_for_families(families: Optional[List[TestFamily]] = None) -> List[Pattern]:
    """Patterns whose family set intersects the relevant families (all if None)."""
    if not families:
        return list(UNIVERSAL_PATTERNS)
    fset = set(families)
    return [p for p in UNIVERSAL_PATTERNS if p.families & fset]


def checklist_text(families: Optional[List[TestFamily]] = None) -> str:
    """Formatted pattern checklist for LLM prompt injection (systematic coverage)."""
    lines = ["Apply these universal patterns to each attack surface:"]
    for p in patterns_for_families(families):
        lines.append(f"- {p.name}: signature=[{p.signature}] test=[{p.how_to_test}]")
    return "\n".join(lines)


def deterministic_hypotheses(base_url: str,
                             families: Optional[List[TestFamily]] = None) -> List["object"]:
    """No-LLM hypotheses for info-disclosure / insecure-storage: fetch common
    sensitive paths. Returns `DynamicHypothesis` objects ready for the engine."""
    from core.intelligence.dynamic_hypothesis import DynamicHypothesis
    if families and not (set(families) & {TestFamily.SECRET_DISCLOSURE,
                                          TestFamily.INFRA_CONFIG}):
        return []
    if not base_url:
        return []
    out: List[object] = []
    for path in _SENSITIVE_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        out.append(DynamicHypothesis(
            vulnerability_class="Information Disclosure",
            description=f"Sensitive file reachable: {path}",
            confidence="low", severity="medium",
            attack_surface="info_disclosure",
            test_steps=[{"tool": "network_broker",
                         "action": {"method": "GET", "url": url},
                         "expect": "200 with secret-shaped content",
                         "extract": "body"}],
            success_criteria=f"{path} returns 200 with config/secret content",
            cwe="CWE-200",
        ))
    return out
