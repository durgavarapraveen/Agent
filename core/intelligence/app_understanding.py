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
                   "clinic", "health", "hipaa", "appointment", "doctor",
                   "pharmacy", "lab_result", "ehr", "fhir", "hl7"),
    "finance": ("account", "transaction", "balance", "transfer", "iban", "loan",
                "credit", "bank", "wire", "statement", "portfolio",
                "ledger", "kyc", "aml", "swift", "routing_number"),
    "ecommerce": ("cart", "checkout", "product", "order", "coupon", "shipping",
                  "sku", "catalog", "price", "wishlist", "basket",
                  "inventory", "refund", "discount", "payment"),
    "social": ("profile", "follow", "friend", "post", "comment", "message",
               "feed", "like", "timeline", "share", "notification"),
    "saas_admin": ("tenant", "organization", "workspace", "role", "permission",
                   "subscription", "seat", "member", "billing", "plan",
                   "api_key", "webhook", "integration"),
    "education": ("course", "student", "grade", "assignment", "enroll", "lesson",
                  "quiz", "transcript", "instructor", "semester", "gpa"),
    "government": ("citizen", "permit", "license", "filing", "compliance",
                   "regulation", "case", "docket", "agency", "jurisdiction",
                   "public_record", "foia", "certificate", "inspection"),
    "banking": ("deposit", "withdrawal", "atm", "mortgage", "savings",
                "checking", "beneficiary", "fund_transfer", "interest_rate",
                "overdraft", "debit", "swift", "bic", "remittance"),
    "manufacturing": ("work_order", "bom", "inventory", "supplier", "batch",
                      "quality", "inspection", "warehouse", "scada", "plc",
                      "production", "assembly", "shipment", "procurement"),
    "insurance": ("policy", "claim", "premium", "underwriting", "deductible",
                  "coverage", "adjuster", "beneficiary", "rider", "actuary"),
    "realestate": ("property", "listing", "tenant", "lease", "mortgage",
                   "appraisal", "escrow", "deed", "landlord", "rent"),
    "logistics": ("shipment", "tracking", "carrier", "freight", "route",
                  "dispatch", "warehouse", "customs", "manifest", "delivery"),
}

_SENSITIVE_FIELD_HINTS: Dict[str, tuple] = {
    "pii": ("email", "phone", "ssn", "dob", "birth", "address", "firstname",
            "lastname", "passport", "national_id", "driver_license", "tax_id"),
    "financial": ("card", "cvv", "iban", "account_number", "routing", "balance",
                  "salary", "amount", "swift", "bic", "pin", "credit_score"),
    "health": ("diagnosis", "medication", "patient", "provider", "record", "allergy",
               "lab_result", "prescription", "insurance_id", "mrn"),
    "credentials": ("password", "token", "secret", "api_key", "apikey", "private_key",
                    "session_id", "refresh_token", "oauth", "jwt", "bearer"),
    "government": ("case_number", "permit_id", "filing", "license_number",
                   "jurisdiction", "docket", "foia", "clearance"),
    "industrial": ("scada", "plc", "control_system", "firmware", "batch_id",
                   "work_order", "serial_number"),
}

# Domain → (business rule, executor capability) hypotheses for the fallback.
_DOMAIN_HYPOTHESES: Dict[str, List[tuple]] = {
    "healthcare": [
        ("Patient records must be isolated per provider/patient", "role_escalation"),
        ("PHI must not be exposed to unauthenticated or peer users", "authorization"),
        ("Prescription or lab result modification requires provider role", "role_escalation"),
        ("Audit logs for PHI access must not be tamperable", "business_logic"),
    ],
    "finance": [
        ("Transfers must reject negative or zero amounts", "business_logic"),
        ("Account data must be isolated per owner", "role_escalation"),
        ("Race condition on concurrent transfers must not create money", "business_logic"),
        ("Transfer recipient must be validated before execution", "business_logic"),
    ],
    "ecommerce": [
        ("Prices/quantities/discounts must be server-validated", "ecommerce"),
        ("Coupons must not stack or be reusable indefinitely", "ecommerce"),
        ("Negative quantity or price manipulation must be rejected", "ecommerce"),
        ("Order status transitions must be server-enforced", "business_logic"),
    ],
    "social": [
        ("Users must not read or edit other users' content", "role_escalation"),
        ("Private messages must not leak to third parties", "authorization"),
        ("Deleted content must not be retrievable via API", "business_logic"),
    ],
    "saas_admin": [
        ("Tenants must be isolated; no cross-tenant access", "role_escalation"),
        ("Non-admins must not reach admin endpoints", "role_escalation"),
        ("API keys must be scoped to the issuing tenant", "authorization"),
        ("Subscription tier must gate feature access server-side", "business_logic"),
    ],
    "education": [
        ("Students must not alter grades or peers' submissions", "role_escalation"),
        ("Exam answers must not be accessible before the exam window", "authorization"),
        ("Instructor-only endpoints must reject student tokens", "role_escalation"),
    ],
    "government": [
        ("Citizen data must be isolated per account", "role_escalation"),
        ("Case/filing status changes require authorized role", "authorization"),
        ("Public records must not expose non-public PII", "authorization"),
        ("Permit approvals must enforce workflow state transitions", "business_logic"),
    ],
    "banking": [
        ("Fund transfers must enforce daily/per-tx limits server-side", "business_logic"),
        ("Cross-account access requires explicit authorization", "role_escalation"),
        ("Beneficiary changes must require step-up authentication", "authorization"),
        ("Concurrent withdrawals must not overdraw beyond limit", "business_logic"),
    ],
    "manufacturing": [
        ("Work order modifications require supervisor role", "role_escalation"),
        ("SCADA/PLC endpoints must not be reachable from web tier", "authorization"),
        ("Quality inspection sign-off must enforce separation of duties", "business_logic"),
        ("Inventory adjustments must be auditable and role-gated", "role_escalation"),
    ],
    "insurance": [
        ("Claim amounts must be server-validated against policy limits", "business_logic"),
        ("Policyholder data must be isolated per account", "role_escalation"),
        ("Claim status transitions must follow defined workflow", "business_logic"),
    ],
    "realestate": [
        ("Lease/contract modifications require authorized party", "authorization"),
        ("Tenant financial records must not leak to other tenants", "role_escalation"),
        ("Property listing price must be server-validated", "business_logic"),
    ],
    "logistics": [
        ("Shipment rerouting requires dispatcher or admin role", "role_escalation"),
        ("Tracking data must be scoped to the shipment owner", "authorization"),
        ("Customs document modifications must be audit-logged", "business_logic"),
    ],
    "generic": [
        ("Object access must enforce ownership (no BOLA/IDOR)", "role_escalation"),
        ("State-changing endpoints must validate inputs", "business_logic"),
        ("Mass assignment must not allow privilege escalation", "authorization"),
        ("File upload must validate type, size, and content", "business_logic"),
        ("Rate limiting must prevent credential stuffing", "authorization"),
        ("JWT/session tokens must not be forgeable or replayable", "authorization"),
    ],
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
    entities: List[Dict[str, Any]] = field(default_factory=list)
    roles: List[Dict[str, Any]] = field(default_factory=list)
    ownership: List[Dict[str, Any]] = field(default_factory=list)
    state_transitions: List[Dict[str, Any]] = field(default_factory=list)
    trust_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    security_invariants: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"business_domain": self.business_domain,
                "domain_confidence": self.domain_confidence,
                "data_sensitivity": self.data_sensitivity,
                "business_rules": self.business_rules,
                "hypotheses": [h.to_dict() for h in self.hypotheses],
                "source": self.source,
                "entities": self.entities,
                "roles": self.roles,
                "ownership": self.ownership,
                "state_transitions": self.state_transitions,
                "trust_boundaries": self.trust_boundaries,
                "security_invariants": self.security_invariants}


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
            "You are a senior penetration tester analyzing a web application to plan "
            "security testing. From the observed signals, perform domain-independent "
            "security analysis:\n\n"
            "1. Classify the business domain.\n"
            "2. Identify domain ENTITIES (e.g. User, Order, Patient, Account) from "
            "   API field names, endpoints, and UI text.\n"
            "3. Infer ROLES (e.g. admin, customer, provider) and their privilege levels.\n"
            "4. Map OWNERSHIP relationships (which role owns which entity).\n"
            "5. Identify STATE TRANSITIONS (e.g. order: pending→paid→shipped).\n"
            "6. Identify TRUST BOUNDARIES (e.g. public→authenticated, user→admin).\n"
            "7. Generate SECURITY INVARIANTS that MUST hold (e.g. 'User A cannot "
            "   access User B orders').\n"
            "8. Propose concrete test HYPOTHESES mapped to a capability.\n\n"
            f"UI text: {signals.ui_text[:2000]}\n"
            f"Form labels: {', '.join(signals.form_labels[:60])}\n"
            f"API fields: {', '.join(signals.api_fields[:60])}\n"
            f"Error messages: {', '.join(signals.error_messages[:30])}\n"
            f"Endpoints: {', '.join(signals.endpoints[:60])}\n\n"
            "Return JSON:\n"
            "{\n"
            '  "business_domain": str,\n'
            '  "domain_confidence": float (0-1),\n'
            '  "entities": [{name, type, owner_role, sensitive_fields: [str]}],\n'
            '  "roles": [{name, privilege_level: int, description}],\n'
            '  "ownership": [{entity, owner_role, access_rules: str}],\n'
            '  "state_transitions": [{entity, from_state, to_state, trigger, requires_role}],\n'
            '  "trust_boundaries": [{name, from_zone, to_zone, controls: [str]}],\n'
            '  "data_sensitivity": {field: class},\n'
            '  "security_invariants": [{description, invariant_type, entities: [str]}],\n'
            '  "business_rules": [str],\n'
            '  "hypotheses": [{title, rationale, capability, target_hint}]\n'
            "}\n"
            "capability must be one of: business_logic, ecommerce, role_escalation, authorization."
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

        def _list_of_dicts(key: str) -> List[Dict[str, Any]]:
            raw = data.get(key) or []
            return [d for d in raw if isinstance(d, dict)]

        entities = _list_of_dicts("entities")
        roles = _list_of_dicts("roles")
        ownership = _list_of_dicts("ownership")
        transitions = _list_of_dicts("state_transitions")
        boundaries = _list_of_dicts("trust_boundaries")
        invariants = _list_of_dicts("security_invariants")

        # Auto-generate hypotheses from inferred invariants
        for inv in invariants:
            desc = inv.get("description", "")
            if desc and not any(h.title == desc for h in hyps):
                inv_type = inv.get("invariant_type", "")
                cap = "authorization" if "access" in desc.lower() else "role_escalation"
                if any(kw in desc.lower() for kw in ("price", "amount", "quantity", "validate")):
                    cap = "business_logic"
                hyps.append(TestHypothesis(
                    title=desc, rationale=f"Inferred security invariant ({inv_type})",
                    capability=cap))

        return AppUnderstanding(
            business_domain=str(data["business_domain"]),
            domain_confidence=float(data.get("domain_confidence", 0.5) or 0.5),
            data_sensitivity={str(k): str(v) for k, v in (data.get("data_sensitivity") or {}).items()},
            business_rules=[str(r) for r in (data.get("business_rules") or [])],
            hypotheses=hyps, source="llm",
            entities=entities, roles=roles, ownership=ownership,
            state_transitions=transitions, trust_boundaries=boundaries,
            security_invariants=invariants)

    # ── Feed inferred model into ApplicationModel singleton ──────────────────
    @staticmethod
    def populate_app_model(understanding: AppUnderstanding) -> None:
        try:
            from core.intelligence.application_model import (
                ApplicationModel, RoleInfo, Resource, SecurityInvariant,
                StateTransition, TrustBoundary,
            )
        except ImportError:
            return
        model = ApplicationModel.get()
        for r in understanding.roles:
            name = r.get("name", "")
            if not name:
                continue
            model.add_role(RoleInfo(
                role_id=name.lower().replace(" ", "_"),
                name=name,
                privilege_level=int(r.get("privilege_level", 0)),
                permissions=r.get("permissions", []),
                source="app_understanding",
            ))
        for e in understanding.entities:
            name = e.get("name", "")
            if not name:
                continue
            model.add_resource(Resource(
                resource_id=name.lower().replace(" ", "_"),
                resource_type=e.get("type", "entity"),
                name=name,
                owner_identity_id=e.get("owner_role", ""),
                sensitivity="high" if e.get("sensitive_fields") else "medium",
                source="app_understanding",
            ))
        for t in understanding.state_transitions:
            entity = t.get("entity", "unknown")
            key = f"{entity}:{t.get('from_state', '')}→{t.get('to_state', '')}"
            model.add_state_transition(StateTransition(
                from_state=t.get("from_state", ""),
                to_state=t.get("to_state", ""),
                trigger=t.get("trigger", ""),
                requires_auth=bool(t.get("requires_role")),
                source="app_understanding",
            ))
        for b in understanding.trust_boundaries:
            bid = b.get("name", "").lower().replace(" ", "_") or uuid.uuid4().hex[:8]
            model.add_trust_boundary(TrustBoundary(
                boundary_id=bid,
                name=b.get("name", ""),
                boundary_type="inferred",
                from_zone=b.get("from_zone", ""),
                to_zone=b.get("to_zone", ""),
                controls=b.get("controls", []),
                source="app_understanding",
            ))
        for inv in understanding.security_invariants:
            iid = uuid.uuid4().hex[:12]
            model.add_invariant(SecurityInvariant(
                invariant_id=iid,
                description=inv.get("description", ""),
                invariant_type=inv.get("invariant_type", "inferred"),
                endpoint_ids=inv.get("entities", []),
                source="app_understanding",
            ))
        logger.info(
            "[AppUnderstanding→AppModel] Populated: %d roles, %d resources, "
            "%d transitions, %d boundaries, %d invariants",
            len(understanding.roles), len(understanding.entities),
            len(understanding.state_transitions), len(understanding.trust_boundaries),
            len(understanding.security_invariants))

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
