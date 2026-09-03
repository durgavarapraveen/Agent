"""
JuiceShopSolver — challenge-driven solver with oracle-verified scoring.

Strategy per unsolved challenge:
  1. Deterministic playbook entry (real HTTP exploit) if one exists.
  2. Otherwise the LLM agentic loop, driven by an objective built from the
     challenge's own name / category / description / hint.
After each pass it re-reads the Juice Shop oracle (/api/Challenges) and loops
while progress is being made (or until max iterations / budget).

Produces an honest scorecard: solved / total, broken down by category and
difficulty — the real coverage number, straight from the app.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.benchmarking.juice_shop_oracle import JuiceShopOracle, Challenge
from core.benchmarking.juice_shop_playbook import get_playbook_fn

logger = logging.getLogger(__name__)


class JuiceShopSolver:
    def __init__(
        self,
        base_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
        brain: Any = None,
        max_iterations: int = 3,
        agentic_rounds: int = 12,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_headers = auth_headers or {}
        self.brain = brain            # optional CentralBrain for the agentic path
        self.max_iterations = max_iterations
        self.agentic_rounds = agentic_rounds
        self.oracle = JuiceShopOracle(base_url, auth_headers=self.auth_headers)
        self.attempts: Dict[str, str] = {}   # challenge key -> method used

    # -------------------------------------------------------------- playbook

    async def _run_playbook(self, ch: Challenge) -> bool:
        fn = get_playbook_fn(ch.key)
        if not fn:
            return False
        try:
            ok = await fn(self.base_url, self.auth_headers)
            self.attempts[ch.key] = "playbook"
            logger.info(f"[JuiceSolver] playbook '{ch.key}': {'fired' if ok else 'no-effect'}")
            return ok
        except Exception as e:
            logger.debug(f"[JuiceSolver] playbook '{ch.key}' error: {e}")
            return False

    # --------------------------------------------------------------- agentic

    async def _run_agentic(self, ch: Challenge) -> bool:
        """
        Drive the oracle-verified ReAct loop: the agent picks real actuator actions
        (HTTP, JWT forge, encode/decode, upload), observes each response, and retries
        until the oracle confirms the challenge solved. Winning strategies are
        persisted to memory for reuse on similar challenges.
        """
        try:
            from agents.llm_harness_adapter import get_llm, initialize_llm
            from core.actuation import ObjectiveAgentLoop

            harness = get_llm()
            if harness is None:
                await initialize_llm()
                harness = get_llm()

            async def _verify() -> bool:
                for c in await self.oracle.fetch():
                    if c.key == ch.key:
                        return c.solved
                return False

            # Juice Shop plugs its /api/Challenges oracle in as the success verifier;
            # the loop itself is the general, target-agnostic exploitation engine.
            loop = ObjectiveAgentLoop(
                target=self.base_url, harness=harness, auth_headers=self.auth_headers,
                max_steps=self.agentic_rounds, verifier=_verify,
            )
            objective = (f"Solve the OWASP Juice Shop challenge '{ch.name}' "
                         f"(category {ch.category}, difficulty {ch.difficulty}/6) on the target.")
            result = await loop.run(objective, hint=ch.hint, context=ch.description)
            self.attempts[ch.key] = "agentic"
            if result.get("success"):
                self._remember(ch, result.get("history", []))
            return bool(result.get("success"))
        except Exception as e:
            logger.debug(f"[JuiceSolver] agentic '{ch.key}' error: {e}")
            return False

    def _remember(self, ch: Challenge, winning_actions: list) -> None:
        """Persist a solved strategy so future runs / similar challenges reuse it."""
        if not winning_actions:
            return
        try:
            Path("data/juice_shop").mkdir(parents=True, exist_ok=True)
            store = Path("data/juice_shop/solved_strategies.json")
            existing = {}
            if store.exists():
                existing = json.loads(store.read_text(encoding="utf-8"))
            existing[ch.key] = {
                "name": ch.name, "category": ch.category, "difficulty": ch.difficulty,
                "actions": winning_actions,
            }
            store.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")
            logger.info(f"[JuiceSolver] recorded winning strategy for '{ch.key}' "
                        f"({len(winning_actions)} steps)")
        except Exception as e:
            logger.debug(f"[JuiceSolver] remember failed: {e}")

    # ---------------------------------------------------------------- solve

    async def solve_all(self) -> Dict[str, Any]:
        challenges = await self.oracle.fetch()
        if not challenges:
            return {"error": "Juice Shop /api/Challenges not reachable — is the target up?",
                    "solved": 0, "total": 0}

        logger.info(f"[JuiceSolver] {len(challenges)} challenges; "
                    f"{sum(c.solved for c in challenges)} already solved")

        for iteration in range(1, self.max_iterations + 1):
            unsolved = [c for c in challenges if not c.solved]
            if not unsolved:
                break
            logger.info(f"[JuiceSolver] === iteration {iteration}: {len(unsolved)} unsolved ===")

            # Pass 1: deterministic playbook (fast, parallel-safe sequentially).
            for ch in unsolved:
                if get_playbook_fn(ch.key):
                    await self._run_playbook(ch)

            # Re-check after playbook.
            challenges = await self.oracle.fetch()
            unsolved = [c for c in challenges if not c.solved]

            # Pass 2: agentic for the remainder (bounded to avoid runaway cost).
            for ch in unsolved:
                if not get_playbook_fn(ch.key):
                    await self._run_agentic(ch)

            after = await self.oracle.fetch()
            progressed = sum(c.solved for c in after) - sum(c.solved for c in challenges)
            challenges = after
            logger.info(f"[JuiceSolver] iteration {iteration}: +{progressed} newly solved")
            if progressed <= 0 and iteration > 1:
                break  # no progress — stop

        return self._scorecard(challenges)

    # ------------------------------------------------------------- scorecard

    def _scorecard(self, challenges: List[Challenge]) -> Dict[str, Any]:
        summary = JuiceShopOracle.summarize(challenges)
        summary["attempts"] = self.attempts
        summary["unsolved_names"] = [c.name for c in challenges if not c.solved]
        return summary

    async def scorecard_only(self) -> Dict[str, Any]:
        """Just read current solved status without attempting anything."""
        return self._scorecard(await self.oracle.fetch())


def render_scorecard(summary: Dict[str, Any]) -> str:
    if summary.get("error"):
        return f"ERROR: {summary['error']}"
    lines = [
        "=" * 56,
        f"JUICE SHOP COVERAGE: {summary['solved']}/{summary['total']} "
        f"({summary['pct']}%)",
        "=" * 56,
        "By difficulty (stars):",
    ]
    for diff, st in summary.get("by_difficulty", {}).items():
        lines.append(f"  {diff}-star  {st['solved']:>3}/{st['total']}")
    lines.append("By category:")
    for cat, st in sorted(summary.get("by_category", {}).items(),
                          key=lambda kv: kv[1]["total"], reverse=True):
        lines.append(f"  {cat:<28} {st['solved']:>3}/{st['total']}")
    return "\n".join(lines)


def _write_report(summary: Dict[str, Any]) -> Path:
    Path("reports").mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path("reports") / f"juice_shop_scorecard_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    return path


async def _amain(argv) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="core.benchmarking.juice_shop_solver")
    p.add_argument("--target", required=True, help="Juice Shop base URL")
    p.add_argument("--score-only", action="store_true", help="just print current coverage")
    p.add_argument("--iterations", type=int, default=3)
    args = p.parse_args(argv)

    solver = JuiceShopSolver(args.target, max_iterations=args.iterations)
    if not await solver.oracle.is_reachable():
        print(f"ERROR: cannot reach {args.target}/api/Challenges — is Juice Shop running?")
        return 1

    summary = (await solver.scorecard_only()) if args.score_only else (await solver.solve_all())
    print(render_scorecard(summary))
    print(f"\nReport: {_write_report(summary)}")
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO)
    import sys
    return asyncio.run(_amain(argv if argv is not None else sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
