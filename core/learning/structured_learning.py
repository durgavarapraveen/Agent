"""
Structured Learning Engine (Phase 31).

Records and retrieves lessons from experiment outcomes to improve
future hypothesis generation, payload selection, and test prioritization.

Each learning record captures: what was tested, the outcome, why it
succeeded/failed, and what to do differently next time.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LearningRecord:
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    record_type: str = ""
    target: str = ""
    test_id: str = ""
    attack_type: str = ""
    technology: str = ""
    endpoint_pattern: str = ""
    outcome: str = ""
    confidence: float = 0.0
    lesson: str = ""
    payload_effective: str = ""
    payload_ineffective: str = ""
    evasion_needed: bool = False
    waf_detected: bool = False
    follow_up_tests: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


class StructuredLearningEngine:

    def __init__(self) -> None:
        self._records: List[LearningRecord] = []
        self._by_test: Dict[str, List[LearningRecord]] = {}
        self._by_tech: Dict[str, List[LearningRecord]] = {}
        self._by_attack: Dict[str, List[LearningRecord]] = {}

    def record(self, rec: LearningRecord) -> None:
        self._records.append(rec)
        self._by_test.setdefault(rec.test_id, []).append(rec)
        if rec.technology:
            self._by_tech.setdefault(rec.technology.lower(), []).append(rec)
        if rec.attack_type:
            self._by_attack.setdefault(rec.attack_type, []).append(rec)
        logger.debug(f"LEARNING_RECORD test={rec.test_id} outcome={rec.outcome}")

    def record_experiment_outcome(self, test_id: str, attack_type: str,
                                  target: str, outcome: str,
                                  technology: str = "",
                                  payload_used: str = "",
                                  lesson: str = "",
                                  confidence: float = 0.0,
                                  follow_ups: List[str] = None) -> LearningRecord:
        rec = LearningRecord(
            record_type="experiment_outcome",
            target=target,
            test_id=test_id,
            attack_type=attack_type,
            technology=technology,
            outcome=outcome,
            confidence=confidence,
            lesson=lesson,
            payload_effective=payload_used if outcome == "CONFIRMED" else "",
            payload_ineffective=payload_used if outcome == "REJECTED" else "",
            follow_up_tests=follow_ups or [],
        )
        self.record(rec)
        return rec

    def record_waf_detection(self, target: str, technology: str = "",
                             blocking_patterns: List[str] = None) -> LearningRecord:
        rec = LearningRecord(
            record_type="waf_detection",
            target=target,
            technology=technology,
            waf_detected=True,
            evasion_needed=True,
            lesson=f"WAF detected, blocking: {blocking_patterns or []}",
            metadata={"blocking_patterns": blocking_patterns or []},
        )
        self.record(rec)
        return rec

    def get_effective_payloads(self, attack_type: str,
                               technology: str = "") -> List[str]:
        records = self._by_attack.get(attack_type, [])
        if technology:
            tech_records = self._by_tech.get(technology.lower(), [])
            records = [r for r in records if r in tech_records]
        return [r.payload_effective for r in records
                if r.payload_effective and r.outcome == "CONFIRMED"]

    def get_ineffective_payloads(self, attack_type: str,
                                  technology: str = "") -> List[str]:
        records = self._by_attack.get(attack_type, [])
        if technology:
            tech_records = self._by_tech.get(technology.lower(), [])
            records = [r for r in records if r in tech_records]
        return [r.payload_ineffective for r in records if r.payload_ineffective]

    def needs_evasion(self, target: str) -> bool:
        return any(r.waf_detected for r in self._records if r.target == target)

    def success_rate(self, test_id: str) -> float:
        records = self._by_test.get(test_id, [])
        if not records:
            return 0.0
        confirmed = sum(1 for r in records if r.outcome == "CONFIRMED")
        return confirmed / len(records)

    def suggest_priority_boost(self, test_id: str, technology: str = "") -> float:
        rate = self.success_rate(test_id)
        if rate > 0.5:
            return 0.2
        elif rate > 0.2:
            return 0.1
        tech_records = self._by_tech.get(technology.lower(), []) if technology else []
        if any(r.test_id == test_id and r.outcome == "CONFIRMED" for r in tech_records):
            return 0.15
        return 0.0

    def get_follow_up_suggestions(self, test_id: str) -> List[str]:
        records = self._by_test.get(test_id, [])
        suggestions = set()
        for r in records:
            if r.outcome == "CONFIRMED":
                suggestions.update(r.follow_up_tests)
        return list(suggestions)

    def summary(self) -> Dict[str, Any]:
        outcomes: Dict[str, int] = {}
        for r in self._records:
            outcomes[r.outcome] = outcomes.get(r.outcome, 0) + 1
        return {
            "total_records": len(self._records),
            "unique_tests": len(self._by_test),
            "unique_technologies": len(self._by_tech),
            "outcomes": outcomes,
            "waf_detections": sum(1 for r in self._records if r.waf_detected),
        }
