"""Phase 16.2 — Model routing and deterministic fallback.

Model selection based on task class, uncertainty, latency, and cost. Structured
output validation. Non-LLM rules for authorization, safety, parsing, and final
finding confirmation. LLMs are replaceable; outages don't weaken security.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TaskClass(str, Enum):
    AUTHORIZATION = "authorization"
    SAFETY_CHECK = "safety_check"
    PARSING = "parsing"
    FINDING_CONFIRMATION = "finding_confirmation"
    HYPOTHESIS_RANKING = "hypothesis_ranking"
    PAYLOAD_GENERATION = "payload_generation"
    ANALYSIS = "analysis"
    PLANNING = "planning"
    TRIAGE = "triage"
    SUMMARIZATION = "summarization"


DETERMINISTIC_TASK_CLASSES: FrozenSet[TaskClass] = frozenset({
    TaskClass.AUTHORIZATION,
    TaskClass.SAFETY_CHECK,
    TaskClass.PARSING,
    TaskClass.FINDING_CONFIRMATION,
})


class ModelTier(str, Enum):
    LOCAL_RULE = "local_rule"
    FAST = "fast"
    BALANCED = "balanced"
    CAPABLE = "capable"
    EXPERT = "expert"


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    tier: ModelTier
    max_tokens: int = 4096
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    avg_latency_ms: float = 500.0
    supports_structured: bool = True
    available: bool = True


@dataclass
class RoutingDecision:
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    task_class: TaskClass = TaskClass.ANALYSIS
    selected_model: Optional[ModelSpec] = None
    used_deterministic: bool = False
    fallback_used: bool = False
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.decision_id,
            "task_class": self.task_class.value,
            "model": self.selected_model.model_id if self.selected_model else "deterministic",
            "deterministic": self.used_deterministic,
            "fallback": self.fallback_used,
            "reason": self.reason,
        }


@dataclass
class StructuredOutput:
    raw: str = ""
    parsed: Optional[Dict[str, Any]] = None
    valid: bool = False
    validation_errors: List[str] = field(default_factory=list)
    model_id: str = ""


DEFAULT_ROUTING_CONFIG: Dict[str, Any] = {
    "default_tier": "balanced",
    "uncertainty_threshold": 0.7,
    "max_cost_per_task": 0.10,
    "max_latency_ms": 30_000,
    "prefer_deterministic": True,
    "audit_all_decisions": True,
}


class DeterministicRule:
    """Non-LLM rule for tasks that must never depend on model availability."""

    def __init__(self, task_class: TaskClass, rule_fn: Callable[..., Any],
                 description: str = ""):
        self.task_class = task_class
        self.rule_fn = rule_fn
        self.description = description

    def execute(self, **kwargs) -> Any:
        return self.rule_fn(**kwargs)


class ModelRouter:
    """Routes tasks to models or deterministic rules. Fail-closed on outage."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_ROUTING_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._models: Dict[str, ModelSpec] = {}
        self._rules: Dict[TaskClass, DeterministicRule] = {}
        self._tier_preference: Dict[TaskClass, ModelTier] = {}
        self._audit_log: List[RoutingDecision] = []
        self._stats = {
            "total_routed": 0, "deterministic_used": 0,
            "fallback_used": 0, "model_used": 0,
        }

    def register_model(self, spec: ModelSpec) -> None:
        with self._lock:
            self._models[spec.model_id] = spec

    def unregister_model(self, model_id: str) -> bool:
        with self._lock:
            return self._models.pop(model_id, None) is not None

    def register_rule(self, rule: DeterministicRule) -> None:
        with self._lock:
            self._rules[rule.task_class] = rule

    def set_tier_preference(self, task_class: TaskClass, tier: ModelTier) -> None:
        with self._lock:
            self._tier_preference[task_class] = tier

    def mark_unavailable(self, model_id: str) -> None:
        with self._lock:
            spec = self._models.get(model_id)
            if spec:
                self._models[model_id] = ModelSpec(
                    model_id=spec.model_id, tier=spec.tier,
                    max_tokens=spec.max_tokens,
                    cost_per_1k_input=spec.cost_per_1k_input,
                    cost_per_1k_output=spec.cost_per_1k_output,
                    avg_latency_ms=spec.avg_latency_ms,
                    supports_structured=spec.supports_structured,
                    available=False,
                )

    def mark_available(self, model_id: str) -> None:
        with self._lock:
            spec = self._models.get(model_id)
            if spec:
                self._models[model_id] = ModelSpec(
                    model_id=spec.model_id, tier=spec.tier,
                    max_tokens=spec.max_tokens,
                    cost_per_1k_input=spec.cost_per_1k_input,
                    cost_per_1k_output=spec.cost_per_1k_output,
                    avg_latency_ms=spec.avg_latency_ms,
                    supports_structured=spec.supports_structured,
                    available=True,
                )

    def route(self, task_class: TaskClass, uncertainty: float = 0.0,
              require_structured: bool = False) -> RoutingDecision:
        decision = RoutingDecision(task_class=task_class)

        if self._config["prefer_deterministic"] and task_class in DETERMINISTIC_TASK_CLASSES:
            rule = self._rules.get(task_class)
            if rule:
                decision.used_deterministic = True
                decision.reason = f"Deterministic rule for {task_class.value}"
                self._record(decision)
                return decision

        preferred_tier = self._tier_preference.get(
            task_class, ModelTier(self._config["default_tier"]))

        if uncertainty > self._config["uncertainty_threshold"]:
            preferred_tier = ModelTier.EXPERT

        model = self._select_model(preferred_tier, require_structured)
        if model:
            decision.selected_model = model
            decision.reason = f"Model {model.model_id} (tier={model.tier.value})"
            self._record(decision)
            return decision

        rule = self._rules.get(task_class)
        if rule:
            decision.used_deterministic = True
            decision.fallback_used = True
            decision.reason = f"Fallback to deterministic rule (no model available)"
            self._record(decision)
            return decision

        decision.fallback_used = True
        decision.reason = "No model or rule available — fail closed"
        self._record(decision)
        return decision

    def validate_output(self, raw: str, schema: Optional[Dict[str, Any]] = None,
                        model_id: str = "") -> StructuredOutput:
        output = StructuredOutput(raw=raw, model_id=model_id)
        try:
            parsed = json.loads(raw)
            output.parsed = parsed
            output.valid = True
        except (json.JSONDecodeError, TypeError) as e:
            output.validation_errors.append(f"JSON parse error: {e}")
            return output

        if schema:
            errors = self._validate_schema(parsed, schema)
            if errors:
                output.valid = False
                output.validation_errors = errors

        return output

    def execute_deterministic(self, task_class: TaskClass, **kwargs) -> Tuple[bool, Any]:
        rule = self._rules.get(task_class)
        if not rule:
            return False, f"No deterministic rule for {task_class.value}"
        try:
            result = rule.execute(**kwargs)
            return True, result
        except Exception as e:
            return False, str(e)

    def audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return [d.to_dict() for d in self._audit_log[-limit:]]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "registered_models": len(self._models),
                "available_models": sum(1 for m in self._models.values() if m.available),
                "deterministic_rules": len(self._rules),
            }

    def _select_model(self, preferred_tier: ModelTier,
                      require_structured: bool) -> Optional[ModelSpec]:
        with self._lock:
            candidates = [
                m for m in self._models.values()
                if m.available
                and m.avg_latency_ms <= self._config["max_latency_ms"]
                and (not require_structured or m.supports_structured)
            ]
        if not candidates:
            return None

        tier_order = list(ModelTier)
        preferred_idx = tier_order.index(preferred_tier)

        exact = [c for c in candidates if c.tier == preferred_tier]
        if exact:
            return min(exact, key=lambda m: m.avg_latency_ms)

        for offset in range(1, len(tier_order)):
            for direction in [1, -1]:
                idx = preferred_idx + (offset * direction)
                if 0 <= idx < len(tier_order):
                    tier = tier_order[idx]
                    match = [c for c in candidates if c.tier == tier]
                    if match:
                        return min(match, key=lambda m: m.avg_latency_ms)
        return candidates[0] if candidates else None

    def _validate_schema(self, data: Dict[str, Any],
                         schema: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        required = schema.get("required", [])
        for key in required:
            if key not in data:
                errors.append(f"Missing required field: {key}")
        properties = schema.get("properties", {})
        for key, spec in properties.items():
            if key in data:
                expected_type = spec.get("type")
                if expected_type and not self._type_check(data[key], expected_type):
                    errors.append(f"Field '{key}' expected type {expected_type}")
        return errors

    def _type_check(self, value: Any, expected: str) -> bool:
        mapping = {
            "string": str, "integer": int, "number": (int, float),
            "boolean": bool, "array": list, "object": dict,
        }
        expected_type = mapping.get(expected)
        if expected_type is None:
            return True
        return isinstance(value, expected_type)

    def _record(self, decision: RoutingDecision) -> None:
        with self._lock:
            self._stats["total_routed"] += 1
            if decision.used_deterministic:
                self._stats["deterministic_used"] += 1
            elif decision.selected_model:
                self._stats["model_used"] += 1
            if decision.fallback_used:
                self._stats["fallback_used"] += 1
            if self._config["audit_all_decisions"]:
                self._audit_log.append(decision)
