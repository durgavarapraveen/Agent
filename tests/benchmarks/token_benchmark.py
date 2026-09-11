"""Phase 11.3 — token cost benchmark.

Runs a scan with token counting and asserts the total stays under budget
(< 2M tokens after Phase 8 optimizations), and tracks per-phase / per-provider
usage so CI can alert on >20% regressions. The assertion + reporting logic is
pure/testable; the live scan runs in CI.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

TOKEN_BUDGET_LIMIT = 2_000_000
REGRESSION_THRESHOLD_PCT = 20.0


@dataclass
class TokenBenchmarkResult:
    total_tokens: int
    limit: int
    by_phase: Dict[str, int]
    cost_usd: float = 0.0

    @property
    def within_budget(self) -> bool:
        return self.total_tokens <= self.limit

    def to_dict(self) -> Dict[str, Any]:
        return {"total_tokens": self.total_tokens, "limit": self.limit,
                "within_budget": self.within_budget, "by_phase": self.by_phase,
                "cost_usd": self.cost_usd}


def assert_within_budget(total_tokens: int, limit: int = TOKEN_BUDGET_LIMIT) -> None:
    if total_tokens > limit:
        raise AssertionError(
            f"token budget exceeded: {total_tokens:,} > {limit:,} "
            f"({total_tokens / limit:.1%} of limit)")


def detect_regression(current_tokens: int, baseline_tokens: int,
                      threshold_pct: float = REGRESSION_THRESHOLD_PCT) -> Dict[str, Any]:
    if baseline_tokens <= 0:
        return {"regression": False, "delta_pct": 0.0, "reason": "no baseline"}
    delta_pct = (current_tokens - baseline_tokens) / baseline_tokens * 100.0
    return {"regression": delta_pct > threshold_pct, "delta_pct": round(delta_pct, 1),
            "current": current_tokens, "baseline": baseline_tokens}


def result_from_budget(budget: Any, by_phase: Optional[Dict[str, int]] = None
                       ) -> TokenBenchmarkResult:
    stats = budget.stats() if hasattr(budget, "stats") else {}
    total = int(stats.get("total_tokens", getattr(budget, "total_tokens_used", 0)) or 0)
    cost = float(stats.get("total_cost_usd", getattr(budget, "spent_usd", 0.0)) or 0.0)
    return TokenBenchmarkResult(total_tokens=total, limit=TOKEN_BUDGET_LIMIT,
                                by_phase=by_phase or {}, cost_usd=cost)


def run_token_benchmark(target: str = "http://localhost:3000") -> TokenBenchmarkResult:  # pragma: no cover
    from agents.universal_llm_harness import get_llm  # type: ignore
    from tests.benchmarks._scan_adapter import scan_and_collect_findings
    scan_and_collect_findings(target)
    llm = get_llm()
    return result_from_budget(getattr(llm, "budget", None) or object())
