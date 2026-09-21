"""Directive engagement **Test Plan** + agent **tiering** — the shared taxonomy
used by the planner, the scanners, coverage and reporting.

Domain-adaptive: BUSINESS_UNDERSTANDING turns the app model into a prioritized,
per-family plan; ACTIVE_SCANNING/EXPLOITATION consume it so only *relevant* test
families run, in priority order (a blog never gets DeFi probes; a wallet does).
Skipped families are recorded as "not applicable" so UNKNOWN≠CLEAN holds.

Reusable component: import `TestFamily`, `AgentTier`, `EngagementPlan` anywhere
instead of re-deriving family lists or model tiers.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.common.schemas import TaskTier

logger = logging.getLogger(__name__)


class TestFamily(str, Enum):
    """Human pentest "teams" — the unit the plan / coverage / report share."""
    AUTH_SESSION = "auth_session"
    INJECTION = "injection"
    BUSINESS_LOGIC = "business_logic"
    AUTHZ_IDOR = "authz_idor"
    API = "api"
    INFRA_CONFIG = "infra_config"
    CLOUD = "cloud"
    SSL_TLS = "ssl_tls"
    SECRET_DISCLOSURE = "secret_disclosure"
    RATE_LIMIT = "rate_limit"
    RACE = "race"
    CRYPTO = "crypto"
    FILE_UPLOAD = "file_upload"
    WEB3 = "web3"


class AgentTier(str, Enum):
    """Skill level → model tier. Human: junior/senior/lead pentester."""
    JUNIOR = "junior"   # breadth: enum, fingerprint, heuristic pattern sweeps
    SENIOR = "senior"   # depth: complex injection, biz-logic, exploit synthesis, chaining
    LEAD = "lead"       # coordinate, prioritize, resolve, validate

    def task_tier(self) -> TaskTier:
        # Junior = cheap/fast (haiku); Senior/Lead = deep (sonnet).
        return TaskTier.SMALL if self is AgentTier.JUNIOR else TaskTier.LARGE


# UniversalProbeEngine injection-class names grouped by family (names must match
# the engine's catalog — see central_brain._run_universal_probe_engine).
FAMILY_PROBE_CLASSES: Dict[TestFamily, List[str]] = {
    TestFamily.INJECTION: ["sqli", "nosqli", "xss", "ssti", "lfi", "rce", "xxe",
                           "email_injection"],
    TestFamily.API: ["ssrf", "cors_misconfiguration", "open_redirect"],
    TestFamily.INFRA_CONFIG: ["host_header_injection", "cache_poisoning"],
    TestFamily.CRYPTO: ["prototype_pollution"],
}

# Display-only acronym casing so a derived role name reads naturally (this is
# formatting, not skill data — the skills themselves are derived at runtime from
# the probes each family actually runs, see family_scheduler).
_ROLE_ACRONYMS = {"idor": "IDOR", "api": "API", "ssl": "SSL", "tls": "TLS",
                  "web3": "Web3", "authz": "AuthZ", "csrf": "CSRF"}


def specialist_role(family: "TestFamily") -> str:
    """Human specialist role name derived from the family (no hardcoded list)."""
    words = [_ROLE_ACRONYMS.get(w, w.capitalize()) for w in family.value.split("_")]
    return " ".join(words) + " Specialist"


# Specialist probes gated by family (skip the module when family not relevant).
FAMILY_SPECIALIST: Dict[TestFamily, str] = {
    TestFamily.WEB3: "web3_probe",
    TestFamily.FILE_UPLOAD: "file_upload_probe",
    TestFamily.BUSINESS_LOGIC: "business_logic_probe",
    TestFamily.AUTHZ_IDOR: "authz_matrix",
    TestFamily.RACE: "race_probe",
}

# Core families always in scope regardless of domain (baseline priority).
# BUSINESS_LOGIC is core (every app has logic worth abusing) but low baseline;
# money domains boost it to the top. CRYPTO/RACE/WEB3/FILE_UPLOAD/CLOUD are NOT
# core — they turn on only for the right domain/tech signal (domain-adaptive).
_CORE_BASELINE: Dict[TestFamily, int] = {
    TestFamily.INJECTION: 70,
    TestFamily.AUTHZ_IDOR: 65,
    TestFamily.AUTH_SESSION: 60,
    TestFamily.API: 55,
    TestFamily.INFRA_CONFIG: 50,
    TestFamily.SSL_TLS: 45,
    TestFamily.SECRET_DISCLOSURE: 45,
    TestFamily.RATE_LIMIT: 40,
    TestFamily.BUSINESS_LOGIC: 35,
}

# Domain → per-family priority boosts (added on top of baseline). Domains come
# from AppUnderstandingEngine._DOMAIN_KEYWORDS. Payment/money/authz-heavy domains
# push business-logic + authz + race to the top (human plan: "payment first").
_DOMAIN_BOOST: Dict[str, Dict[TestFamily, int]] = {
    "ecommerce": {TestFamily.BUSINESS_LOGIC: 80, TestFamily.AUTHZ_IDOR: 30,
                  TestFamily.RACE: 25, TestFamily.RATE_LIMIT: 15},
    "finance": {TestFamily.BUSINESS_LOGIC: 85, TestFamily.AUTHZ_IDOR: 35,
                TestFamily.CRYPTO: 25, TestFamily.RACE: 25, TestFamily.RATE_LIMIT: 15},
    "banking": {TestFamily.BUSINESS_LOGIC: 85, TestFamily.AUTHZ_IDOR: 35,
                TestFamily.CRYPTO: 25, TestFamily.RACE: 25, TestFamily.RATE_LIMIT: 15},
    "insurance": {TestFamily.BUSINESS_LOGIC: 40, TestFamily.AUTHZ_IDOR: 30},
    "healthcare": {TestFamily.AUTHZ_IDOR: 40, TestFamily.SECRET_DISCLOSURE: 25,
                   TestFamily.BUSINESS_LOGIC: 20},
    "saas_admin": {TestFamily.AUTHZ_IDOR: 40, TestFamily.BUSINESS_LOGIC: 30},
    "government": {TestFamily.AUTHZ_IDOR: 35, TestFamily.SECRET_DISCLOSURE: 25},
    "social": {TestFamily.AUTHZ_IDOR: 30, TestFamily.INJECTION: 15},
    "education": {TestFamily.AUTHZ_IDOR: 25, TestFamily.BUSINESS_LOGIC: 20},
    "manufacturing": {TestFamily.AUTHZ_IDOR: 25, TestFamily.INFRA_CONFIG: 20},
    "realestate": {TestFamily.BUSINESS_LOGIC: 25, TestFamily.AUTHZ_IDOR: 25},
    "logistics": {TestFamily.BUSINESS_LOGIC: 25, TestFamily.AUTHZ_IDOR: 20},
    "generic": {},
}

# Tech/keyword signals → extra families (domain-independent enablement).
# Keep these broad: a family is only skipped when NO keyword matches, so missing a
# chain/vendor name silently drops a whole family (e.g. Juice Shop's web3 challenge).
_TECH_SIGNALS: Dict[TestFamily, tuple] = {
    TestFamily.WEB3: ("web3", "ethers", "ethereum", "eth", "metamask", "solidity",
                      "erc20", "erc-20", "erc721", "erc-721", "erc1155", "wallet",
                      "blockchain", "smart contract", "nft", "defi", "dapp",
                      "bitcoin", "btc", "polygon", "matic", "solana", "binance",
                      "bsc", "avalanche", "arbitrum", "optimism", "usdt", "usdc",
                      "token", "mint", "web3.js", "walletconnect"),
    TestFamily.CRYPTO: ("jwt", "crypto", "signature", "private key", "encrypt",
                        "hmac", "rsa", "ecdsa", "aes", "sha256", "bcrypt", "pgp",
                        "tls", "certificate", "keystore", "secret key", "nonce"),
    TestFamily.FILE_UPLOAD: ("upload", "multipart", "attachment", "avatar", "file",
                             "import", "polyglot", "svg", "xml", "zip", "csv",
                             "document", "media", "image upload", "form-data"),
    TestFamily.CLOUD: ("s3", "aws", "gcp", "azure", "bucket", "metadata", "iam",
                       "lambda", "cloudfront", "ec2", "gcs", "blob storage",
                       "kubernetes", "k8s", "container", "ecr", "169.254.169.254"),
}


@dataclass
class TestPlanItem:
    family: TestFamily
    relevant: bool = True
    priority: int = 0
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"family": self.family.value, "relevant": self.relevant,
                "priority": self.priority, "rationale": self.rationale}


@dataclass
class EngagementPlan:
    """Prioritized, domain-scoped test plan produced by BUSINESS_UNDERSTANDING."""
    domain: str = "generic"
    items: List[TestPlanItem] = field(default_factory=list)
    threat_model: Dict[str, Any] = field(default_factory=dict)

    # ── queries used by the scanners ──────────────────────────────────────
    def is_relevant(self, family: TestFamily) -> bool:
        for it in self.items:
            if it.family is family:
                return it.relevant
        return False

    def relevant_families(self) -> List[TestFamily]:
        return [it.family for it in self.ordered() if it.relevant]

    def skipped_families(self) -> List[TestFamily]:
        return [it.family for it in self.items if not it.relevant]

    def ordered(self) -> List[TestPlanItem]:
        return sorted(self.items, key=lambda i: i.priority, reverse=True)

    def probe_classes(self) -> List[str]:
        """Injection classes to run, from relevant families (deduped, ordered)."""
        seen: List[str] = []
        for fam in self.relevant_families():
            for c in FAMILY_PROBE_CLASSES.get(fam, []):
                if c not in seen:
                    seen.append(c)
        return seen

    def specialist_allowed(self, module_basename: str) -> bool:
        """True if a specialist probe module is in-scope per the plan.
        Unknown modules default to allowed (fail-open for non-gated probes)."""
        gated = {m: fam for fam, m in FAMILY_SPECIALIST.items()}
        fam = gated.get(module_basename)
        return True if fam is None else self.is_relevant(fam)

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain, "threat_model": self.threat_model,
                "items": [i.to_dict() for i in self.ordered()],
                "relevant": [f.value for f in self.relevant_families()],
                "skipped": [f.value for f in self.skipped_families()]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EngagementPlan":
        """Rebuild from the persisted dict (resume/checkpoint safety)."""
        items: List[TestPlanItem] = []
        for it in (d or {}).get("items", []):
            try:
                items.append(TestPlanItem(family=TestFamily(it["family"]),
                                          relevant=bool(it.get("relevant", True)),
                                          priority=int(it.get("priority", 0)),
                                          rationale=it.get("rationale", "")))
            except Exception:
                continue
        return cls(domain=(d or {}).get("domain", "generic"), items=items,
                   threat_model=(d or {}).get("threat_model", {}))


def _coerce_str(x: Any, key: str = "url") -> str:
    """Best-effort text from a str / dict / domain object (Endpoint, Technology)."""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return str(x.get(key, x.get("name", "")))
    return str(getattr(x, key, None) or getattr(x, "name", None) or x)


def _as_list(x: Any) -> List[Any]:
    """Normalize a list / tuple / set / dict / scalar to a flat list (ctx fields
    vary: technologies is often a dict {name: info}, endpoints a list)."""
    if x is None:
        return []
    if isinstance(x, dict):
        out: List[Any] = []
        for k, v in x.items():
            out.append(k)
            if isinstance(v, (list, tuple, set)):
                out.extend(v)
            elif v:
                out.append(v)
        return out
    if isinstance(x, (list, tuple, set)):
        return list(x)
    return [x]


def _collect_signal_text(understanding: Any, ctx: Any) -> str:
    parts: List[str] = []
    for t in _as_list(getattr(ctx, "technologies", None))[:40]:
        parts.append(_coerce_str(t, "name"))
    for e in _as_list(getattr(ctx, "endpoints", None))[:200]:
        parts.append(_coerce_str(e, "url"))
    parts.append(str(getattr(ctx, "crawled_text", "") or "")[:4000])
    if understanding is not None:
        parts.extend(getattr(understanding, "business_rules", []) or [])
        parts.append(" ".join((getattr(understanding, "data_sensitivity", {}) or {}).keys()))
    return " ".join(parts).lower()


_DOMAIN_ALIASES = (
    ("ecommerce", ("ecommerce", "e-commerce", "commerce", "retail", "shop",
                   "store", "cart", "checkout", "marketplace", "webshop")),
    ("banking", ("bank", "banking")),
    ("finance", ("finance", "financial", "fintech", "payment", "trading",
                 "brokerage", "lending")),
    ("insurance", ("insurance", "insurer", "policyholder")),
    ("healthcare", ("healthcare", "health", "patient", "medical", "clinic", "ehr")),
    ("saas_admin", ("saas", "admin panel", "tenant", "multi-tenant", "dashboard")),
    ("government", ("government", "gov", "public sector", "municipal")),
    ("social", ("social", "forum", "community", "messaging", "network")),
    ("education", ("education", "learning", "e-learning", "course", "school", "lms")),
    ("logistics", ("logistics", "shipping", "delivery", "freight", "supply chain")),
    ("realestate", ("real estate", "realestate", "property", "listing", "rental")),
    ("manufacturing", ("manufactur", "industrial", "factory", "plant")),
)


def _canonical_domain(raw: str) -> str:
    """Map an LLM's free-text business_domain (e.g. 'E-commerce (juice shop) with
    gamified security-training') to a canonical _DOMAIN_BOOST key, so verbose
    labels still receive their domain-specific family boosts (race, business_logic,
    …). Heuristic domains are already canonical and pass through unchanged."""
    d = (raw or "").lower().strip()
    if not d:
        return "generic"
    if d in _DOMAIN_BOOST:
        return d
    for canon, aliases in _DOMAIN_ALIASES:
        if any(a in d for a in aliases):
            return canon
    try:
        from core.intelligence.app_understanding import _DOMAIN_KEYWORDS
        best, best_hits = "generic", 0
        for dom, kws in _DOMAIN_KEYWORDS.items():
            hits = sum(1 for k in kws if k in d)
            if hits > best_hits:
                best, best_hits = dom, hits
        if best_hits:
            return best
    except Exception:
        pass
    return "generic"


def build_engagement_plan(understanding: Any, ctx: Any) -> EngagementPlan:
    """Map the app model + discovered signals → a prioritized, scoped plan.

    Deterministic + explainable (reuses AppUnderstanding's domain inference); no
    extra LLM call. `understanding` may be an AppUnderstanding or None."""
    # Prefer the canonical key the model chose from our taxonomy; fall back to
    # keyword canonicalization of the free-text label only when it's absent/invalid.
    dk = (getattr(understanding, "domain_key", "") or "").strip().lower()
    if dk in _DOMAIN_BOOST:
        domain = dk
    else:
        domain = _canonical_domain(
            (getattr(understanding, "business_domain", "") or "generic").lower())
    sensitivity = getattr(understanding, "data_sensitivity", {}) or {}
    signal = _collect_signal_text(understanding, ctx)

    priorities: Dict[TestFamily, int] = dict(_CORE_BASELINE)
    for fam, boost in _DOMAIN_BOOST.get(domain, {}).items():
        priorities[fam] = priorities.get(fam, 0) + boost

    # Sensitivity-driven boosts.
    if any(k in sensitivity.values() for k in ("financial", "credentials")):
        priorities[TestFamily.SECRET_DISCLOSURE] = priorities.get(TestFamily.SECRET_DISCLOSURE, 0) + 20
        priorities[TestFamily.CRYPTO] = priorities.get(TestFamily.CRYPTO, 0) + 15

    # Tech/keyword-driven family enablement (web3/crypto/upload/cloud).
    enabled_by_signal: Dict[TestFamily, str] = {}
    for fam, kws in _TECH_SIGNALS.items():
        hit = next((k for k in kws if k in signal), "")
        if hit:
            priorities[fam] = priorities.get(fam, 0) + 30
            enabled_by_signal[fam] = hit

    items: List[TestPlanItem] = []
    for fam in TestFamily:
        pr = priorities.get(fam, 0)
        relevant = pr > 0
        if fam in enabled_by_signal:
            rationale = f"signal:'{enabled_by_signal[fam]}'"
        elif fam in _DOMAIN_BOOST.get(domain, {}):
            rationale = f"domain:{domain}"
        elif fam in _CORE_BASELINE:
            rationale = "core"
        else:
            rationale = "not indicated for this app"
        items.append(TestPlanItem(family=fam, relevant=relevant,
                                  priority=pr, rationale=rationale))

    plan = EngagementPlan(domain=domain, items=items,
                          threat_model=_threat_model(understanding, domain))
    logger.info("[TestPlan] domain=%s relevant=%s skipped=%s", domain,
                [f.value for f in plan.relevant_families()],
                [f.value for f in plan.skipped_families()])
    return plan


def _threat_model(understanding: Any, domain: str) -> Dict[str, Any]:
    """Compact threat model (Phase 1 deliverable) from the app model."""
    if understanding is None:
        return {"domain": domain}
    return {
        "domain": domain,
        "assets": list((getattr(understanding, "data_sensitivity", {}) or {}).items())[:20],
        "invariants": getattr(understanding, "security_invariants", [])[:20],
        "roles": getattr(understanding, "roles", [])[:20],
        "trust_boundaries": getattr(understanding, "trust_boundaries", [])[:20],
    }
