"""
RewardPolicy — closed-loop self-improvement over pentest strategies.

The system already records raw success/failure via ExperienceLearner. RewardPolicy
adds a *reward signal* and a persistent policy so the agent gets better across runs:

  - Every strategy/tool outcome earns a scalar reward (confirmed finding = strong
    positive; a critic-rejected false positive = negative; plain failure = mild
    negative), optionally scaled by severity and normalized by cost.
  - Rewards accumulate in data/learning/reward_policy.json across runs.
  - score() ranks strategies by reward-per-cost with a UCB-style exploration bonus,
    so under-sampled strategies still get tried (exploration) while proven ones are
    preferred (exploitation).

Consumers: DecisionGuardV2 (choosing alternative strategies) and any tool-selection
site can call preferred()/rank() to let measured yield drive the next decision.
"""

from __future__ import annotations

import json
import logging
import math
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_POLICY_FILE = Path("data/learning/reward_policy.json")

# Reward per outcome class.
_REWARDS = {
    "confirmed": 1.0,
    "exploited": 1.5,
    "uncertain": 0.0,
    "false_positive": -0.6,
    "quarantined": -0.6,
    "failure": -0.25,
}

# Severity multipliers applied to positive rewards.
_SEVERITY_MULT = {
    "CRITICAL": 1.6, "HIGH": 1.3, "MEDIUM": 1.0, "LOW": 0.7, "INFO": 0.4,
}


class RewardPolicy:
    def __init__(self, policy_file: Path = _POLICY_FILE, exploration_c: float = 1.4):
        self.policy_file = Path(policy_file)
        self.exploration_c = exploration_c
        self._lock = threading.Lock()
        # key -> stats dict
        self._policy: Dict[str, Dict[str, Any]] = {}
        self._total_pulls = 0
        self._load()

    # ------------------------------------------------------------- persistence

    @staticmethod
    def _key(strategy: str, test_type: str) -> str:
        return f"{(strategy or 'default').lower()}|{(test_type or 'any').lower()}"

    def _load(self) -> None:
        try:
            if self.policy_file.exists():
                with open(self.policy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._policy = data.get("policy", {})
                self._total_pulls = int(data.get("total_pulls", 0))
                logger.info(f"[RewardPolicy] loaded {len(self._policy)} strategy stats "
                            f"({self._total_pulls} total pulls)")
        except Exception as e:
            logger.debug(f"[RewardPolicy] load error: {e}")
            self._policy = {}

    def _persist(self) -> None:
        try:
            self.policy_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.policy_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"policy": self._policy, "total_pulls": self._total_pulls,
                           "updated_at": time.time()}, f, indent=2, default=str)
            tmp.replace(self.policy_file)
        except Exception as e:
            logger.error(f"[RewardPolicy] persist error: {e}")

    # ------------------------------------------------------------------ record

    def record_outcome(
        self,
        strategy: str,
        test_type: str,
        outcome: str,
        severity: str = "MEDIUM",
        cost_seconds: float = 0.0,
        cost_tokens: int = 0,
        reward: Optional[float] = None,
    ) -> float:
        """Record one strategy outcome and return the reward earned."""
        outcome = (outcome or "failure").lower()
        if reward is None:
            reward = _REWARDS.get(outcome, 0.0)
            if reward > 0:
                reward *= _SEVERITY_MULT.get(str(severity or "MEDIUM").upper(), 1.0)

        with self._lock:
            k = self._key(strategy, test_type)
            st = self._policy.setdefault(k, {
                "strategy": strategy, "test_type": test_type, "attempts": 0,
                "confirmed": 0, "false_positive": 0, "failure": 0, "uncertain": 0,
                "reward_sum": 0.0, "cost_seconds": 0.0, "cost_tokens": 0,
            })
            st["attempts"] += 1
            st["reward_sum"] += reward
            st["cost_seconds"] += float(cost_seconds)
            st["cost_tokens"] += int(cost_tokens)
            if outcome in ("confirmed", "exploited"):
                st["confirmed"] += 1
            elif outcome in ("false_positive", "quarantined"):
                st["false_positive"] += 1
            elif outcome == "uncertain":
                st["uncertain"] += 1
            else:
                st["failure"] += 1
            self._total_pulls += 1
            self._persist()
        return reward

    def record_finding_outcomes(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Reward strategies from a batch of critic-annotated findings.
        Each finding's producing tool/source is the strategy; its critic verdict
        (or exploited flag) is the outcome.
        """
        counts = {"confirmed": 0, "false_positive": 0, "uncertain": 0}
        for f in findings or []:
            strategy = str(f.get("tool") or f.get("source") or "unknown")
            test_type = str(f.get("type") or f.get("vuln_type") or "any")
            severity = str(f.get("severity") or "MEDIUM")

            if f.get("exploited"):
                outcome = "exploited"
            else:
                verdict = ((f.get("critic") or {}).get("verdict") or "").upper()
                if f.get("status") == "QUARANTINED" or verdict == "FALSE_POSITIVE":
                    outcome = "false_positive"
                elif verdict == "CONFIRMED" or f.get("status") == "CONFIRMED":
                    outcome = "confirmed"
                else:
                    outcome = "uncertain"

            self.record_outcome(strategy, test_type, outcome, severity=severity)
            if outcome in ("confirmed", "exploited"):
                counts["confirmed"] += 1
            elif outcome == "false_positive":
                counts["false_positive"] += 1
            else:
                counts["uncertain"] += 1
        if any(counts.values()):
            logger.info(f"[RewardPolicy] recorded finding outcomes: {counts}")
        return counts

    # ----------------------------------------------------------------- scoring

    def score(self, strategy: str, test_type: str) -> float:
        """Reward-per-cost with a UCB exploration bonus. Higher = try sooner."""
        st = self._policy.get(self._key(strategy, test_type))
        if not st or st["attempts"] == 0:
            # Unseen strategy: optimistic so it gets explored.
            return 1.0
        avg_reward = st["reward_sum"] / st["attempts"]
        # Normalize by cost (seconds) if we have it, else pure reward.
        cost = st["cost_seconds"] / st["attempts"] if st["cost_seconds"] > 0 else 1.0
        base = avg_reward / max(cost, 0.1) if st["cost_seconds"] > 0 else avg_reward
        total = max(self._total_pulls, 1)
        exploration = self.exploration_c * math.sqrt(math.log(total + 1) / st["attempts"])
        return base + exploration

    def rank(self, candidates: List[str], test_type: str) -> List[Tuple[str, float]]:
        """Return candidates sorted by descending score."""
        scored = [(c, self.score(c, test_type)) for c in candidates]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def preferred(self, test_type: str, candidates: List[str]) -> Optional[str]:
        ranked = self.rank(candidates, test_type)
        return ranked[0][0] if ranked else None

    def success_rate(self, strategy: str, test_type: str) -> float:
        st = self._policy.get(self._key(strategy, test_type))
        if not st or st["attempts"] == 0:
            return 0.0
        return st["confirmed"] / st["attempts"]

    def stats(self) -> Dict[str, Any]:
        top = sorted(
            self._policy.values(),
            key=lambda s: (s["reward_sum"] / max(s["attempts"], 1)),
            reverse=True,
        )[:10]
        return {
            "strategies_tracked": len(self._policy),
            "total_pulls": self._total_pulls,
            "top_strategies": [
                {"strategy": s["strategy"], "test_type": s["test_type"],
                 "attempts": s["attempts"], "confirmed": s["confirmed"],
                 "avg_reward": round(s["reward_sum"] / max(s["attempts"], 1), 3)}
                for s in top
            ],
        }


_POLICY: Optional[RewardPolicy] = None


def get_reward_policy() -> RewardPolicy:
    global _POLICY
    if _POLICY is None:
        _POLICY = RewardPolicy()
    return _POLICY
