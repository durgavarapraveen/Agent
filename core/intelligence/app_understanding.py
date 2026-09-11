"""Phase 1.5 — LLM semantic application understanding.

Turns crawled surface signals (UI text, form labels, API field names, error
messages) into a business-level model: what domain the app is (healthcare /
finance / ecommerce / …), which data is sensitive, which business rules ought
to hold, and — crucially — concrete, executable test hypotheses the experiment
scheduler can run (e.g. "patient records must be isolated by provider" →
role_escalation test).

Reuse / relationship:
  * ``TargetProfiler`` (core.intelligence.target_profiler) gives the *technical*
    profile (stack, CMS); this adds the *business/semantic* layer.
  * ``SemanticInferenceEngine`` (core.knowledge.semantic_inference) types
    individual endpoints (rest/graphql/…); this reasons about the whole app.
  * Hypotheses map to executor capabilities (business_logic, ecommerce,
    role_escalation, authorization) built in Phases 1.1–1.4.

The engine uses the LLM when available (injectable; defaults to the harness) and
always has a deterministic keyword-based fallback, so it produces useful output
— and is unit-testable — with no live LLM.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DOMAIN_KEYWORDS: Dict[str, tuple] = {
    "healthcare": ("patient", "diagnosis", "prescription", "medical", "provider",
                   "clinic", "health", "hipaa", "appointment", "doctor"),
    "finance": ("account", "transaction", "balance", "transfer", "iban", "loan",
                "credit", "bank", "wire", "statement", "portfolio"),
    "ecommerce": ("cart", "checkout", "product", "order", "coupon", "shipping",
                  "sku", "catalog", "price", "wishlist", "basket"),
    "social": ("profile", "follow", "friend", "post", "comment", "message",
               "feed", "like", "timeline"),
    "saas_admin": ("tenant", "organization", "workspace", "role", "permission",
                   "subscription", "seat", "member"),
    "education": ("course", "student", "grade", "assignment", "enroll", "lesson",
                  "quiz", "transcript"),
}

_SENSITIVE_FIELD_HINTS: Dict[str, tuple] = {
    "pii": ("email", "phone", "ssn", "dob", "birth", "address", "firstname",
            "lastname", "passport", "national_id"),
    "financial": ("card", "cvv", "iban", "account_number", "routing", "balance",
                  "salary", "amount"),
    "health": ("diagnosis", "medication", "patient", "provider", "record", "allergy"),
    "credentials": ("password", "token", "secret", "api_key", "apikey", "private_key"),
}

# Domain → (business rule, executor capability) hypotheses for the fallback.
_DOMAIN_HYPOTHESES: Dict[str, List[tuple]] = {
    "healthcare": [("Patient records must be isolated per provider/patient", "role_escalation"),
                   ("PHI must not be exposed to unauthenticated or peer users", "authorization")],
    "finance": [("Transfers must reject negative or zero amounts", "business_logic"),
                ("Account data must be isolated per owner", "role_escalation")],
    "ecommerce": [("Prices/quantities/discounts must be server-validated", "ecommerce"),
                  ("Coupons must not stack or be reusable indefinitely", "ecommerce")],
    "social": [("Users must not read or edit other users' content", "role_escalation")],
    "saas_admin": [("Tenants must be isolated; no cross-tenant access", "role_escalation"),
                   ("Non-admins must not reach admin endpoints", "role_escalation")],
    "education": [("Students must not alter grades or peers' submissions", "role_escalation")],
    "generic": [("Object access must enforce ownership (no BOLA)", "role_escalation"),
                ("State-changing endpoints must validate inputs", "business_logic")],
}


@dataclass
class TestHypothesis:
    title: str
    rationale: str
    capability: str
    target_hint: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "rationale": self.rationale,
                "capability": self.capability, "target_hint": self.target_hint}


@dataclass
class AppUnderstanding:
    business_domain: str
    domain_confidence: float
    data_sensitivity: Dict[str, str]
    business_rules: List[str]
    hypotheses: List[TestHypothesis]
    source: str  # "llm" | "heuristic"

    def to_dict(self) -> Dict[str, Any]:
        return {"business_domain": self.business_domain,
                "domain_confidence": self.domain_confidence,
                "data_sensitivity": self.data_sensitivity,
                "business_rules": self.business_rules,
                "hypotheses": [h.to_dict() for h in self.hypotheses],
                "source": self.source}


@dataclass
class AppSignals:
    ui_text: str = ""
    form_labels: List[str] = field(default_factory=list)
    api_fields: List[str] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)

    def corpus(self) -> str:
        parts = [self.ui_text, " ".join(self.form_labels), " ".join(self.api_fields),
                 " ".join(self.error_messages), " ".join(self.endpoints)]
        return " ".join(p for p in parts if p).lower()

    @classmethod
    def from_context(cls, ctx: Any) -> "AppSignals":
        def _g(name, default):
            v = getattr(ctx, name, None)
            return v if v is not None else default
        endpoints = []
        for e in _g("endpoints", []) or []:
            endpoints.append(e.get("url", "") if isinstance(e, dict) else str(e))
        api_fields: List[str] = []
        for e in _g("endpoints", []) or []:
            if isinstance(e, dict) and e.get("params"):
                api_fields.append(str(e["params"]))
        return cls(
            ui_text=str(_g("crawled_text", "") or "")[:8000],
            form_labels=list(_g("form_labels", []) or [])[:100],
            api_fields=api_fields[:100],
            error_messages=list(_g("error_messages", []) or [])[:50],
            endpoints=endpoints[:200],
        )


class AppUnderstandingEngine:

    def __init__(self, llm: Any = None):
        self._llm = llm  # object with async generate_json(...); None → lazy harness

    # ── Deterministic heuristic (fallback, always available) ─────────────────
    def _detect_domain(self, corpus: str) -> tuple:
        best, best_hits = "generic", 0
        for domain, kws in _DOMAIN_KEYWORDS.items():
            hits = sum(1 for k in kws if k in corpus)
            if hits > best_hits:
                best, best_hits = domain, hits
        confidence = min(1.0, best_hits / 4.0) if best_hits else 0.0
        return best, confidence

    def _detect_sensitivity(self, signals: AppSignals) -> Dict[str, str]:
        fields = set()
        for f in signals.api_fields + signals.form_labels:
            fields.update(str(f).lower().replace(",", " ").split())
        sensitivity: Dict[str, str] = {}
        for cls, hints in _SENSITIVE_FIELD_HINTS.items():
            for h in hints:
                for f in fields:
                    if h in f:
                        sensitivity[f] = cls
        return sensitivity

    def heuristic(self, signals: AppSignals) -> AppUnderstanding:
        corpus = signals.corpus()
        domain, conf = self._detect_domain(corpus)
        sensitivity = self._detect_sensitivity(signals)
        rules_caps = _DOMAIN_HYPOTHESES.get(domain, []) + _DOMAIN_HYPOTHESES["generic"]
        hyps = [TestHypothesis(title=rule, rationale=f"{domain} domain rule", capability=cap)
                for rule, cap in rules_caps]
        rules = [r for r, _ in rules_caps]
        return AppUnderstanding(domain, conf, sensitivity, rules, hyps, source="heuristic")

    # ── LLM path ─────────────────────────────────────────────────────────────
    def build_prompt(self, signals: AppSignals) -> str:
        return (
            "You are analyzing a web application to plan security testing. "
            "From the observed signals, classify the business domain, identify "
            "sensitive data fields, list business rules that SHOULD hold, and "
            "propose concrete test hypotheses mapped to a capability "
            "(one of: business_logic, ecommerce, role_escalation, authorization).\n\n"
            f"UI text: {signals.ui_text[:2000]}\n"
            f"Form labels: {', '.join(signals.form_labels[:60])}\n"
            f"API fields: {', '.join(signals.api_fields[:60])}\n"
            f"Error messages: {', '.join(signals.error_messages[:30])}\n"
            f"Endpoints: {', '.join(signals.endpoints[:60])}\n\n"
            "Return JSON: {business_domain, domain_confidence (0-1), "
            "data_sensitivity {field: class}, business_rules [str], "
            "hypotheses [{title, rationale, capability, target_hint}]}."
        )

    async def analyze(self, signals: AppSignals) -> AppUnderstanding:
        llm = self._llm
        if llm is None:
            try:
                from agents.llm_harness_adapter import get_llm
                llm = get_llm()
            except Exception as e:
                logger.debug("app_understanding: harness unavailable (%s); heuristic", e)
                return self.heuristic(signals)

        try:
            data = await llm.generate_json(
                self.build_prompt(signals),
                system="You classify web-app business logic for security testing.",
                mandatory_fields=["business_domain", "hypotheses"],
            )
        except Exception as e:
            logger.warning("app_understanding: LLM call failed (%s); heuristic", e)
            return self.heuristic(signals)

        parsed = self._parse_llm(data)
        if parsed is None:
            return self.heuristic(signals)
        return parsed

    def _parse_llm(self, data: Dict[str, Any]) -> Optional[AppUnderstanding]:
        if not isinstance(data, dict) or not data.get("business_domain"):
            return None
        raw_hyps = data.get("hypotheses") or []
        hyps: List[TestHypothesis] = []
        for h in raw_hyps:
            if isinstance(h, dict) and h.get("title"):
                cap = h.get("capability", "business_logic")
                if cap not in ("business_logic", "ecommerce", "role_escalation", "authorization"):
                    cap = "business_logic"
                hyps.append(TestHypothesis(
                    title=h["title"], rationale=h.get("rationale", ""),
                    capability=cap, target_hint=h.get("target_hint", "")))
        if not hyps:
            return None
        return AppUnderstanding(
            business_domain=str(data["business_domain"]),
            domain_confidence=float(data.get("domain_confidence", 0.5) or 0.5),
            data_sensitivity={str(k): str(v) for k, v in (data.get("data_sensitivity") or {}).items()},
            business_rules=[str(r) for r in (data.get("business_rules") or [])],
            hypotheses=hyps, source="llm")

    # ── Executable test specs for the experiment scheduler ───────────────────
    def to_test_specs(self, understanding: AppUnderstanding,
                      base_endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        specs: List[Dict[str, Any]] = []
        for h in understanding.hypotheses:
            specs.append({
                "capability": h.capability,
                "hypothesis": h.title,
                "rationale": h.rationale,
                "business_domain": understanding.business_domain,
                "endpoint_hint": h.target_hint,
                "target_endpoints": base_endpoints or [],
                "priority": "high" if understanding.domain_confidence >= 0.5 else "medium",
                "source": understanding.source,
            })
        return specs
