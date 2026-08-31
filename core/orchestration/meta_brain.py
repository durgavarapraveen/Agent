"""
MetaBrain - Multi-target parallel pentesting orchestrator.
Runs multiple CentralBrain instances concurrently with resource limits.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from core.central_brain import CentralBrain
from core.config import get_config

logger = logging.getLogger(__name__)


class MetaBrain:
    """
    Orchestrates pentesting across multiple targets simultaneously.

    Usage:
        meta = MetaBrain(["app1.com", "app2.com", "app3.com"])
        results = await meta.run_all()

    Config (.env):
        MAX_PARALLEL_TARGETS=3
    """

    def __init__(self, targets: List[str], auth_document: str = ""):
        self.targets = targets
        self.auth_document = auth_document
        config = get_config()
        self.max_parallel = config.get_int("MAX_PARALLEL_TARGETS", 3)
        self.results: Dict[str, Dict] = {}
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        self.start_time = datetime.now()

    async def run_all(self) -> Dict[str, Dict]:
        """Run pentest on all targets with concurrency limit"""
        logger.info("=" * 60)
        logger.info("META BRAIN — MULTI-TARGET PENTESTING")
        logger.info("=" * 60)
        logger.info(f"Targets: {len(self.targets)}")
        logger.info(f"Max parallel: {self.max_parallel}")
        for i, t in enumerate(self.targets, 1):
            logger.info(f"  [{i}] {t}")
        logger.info("=" * 60)

        semaphore = asyncio.Semaphore(self.max_parallel)

        async def run_one(target: str) -> Dict:
            async with semaphore:
                logger.info(f"\n>>> STARTING: {target}")
                brain = CentralBrain(target)
                try:
                    await brain.run(auth_document=self.auth_document)
                    return {
                        "status": "complete",
                        "target": target,
                        "vulnerabilities": len(brain.ctx.vulnerabilities),
                        "exploits": len(brain.ctx.exploit_results),
                        "agents_used": len(brain.ctx.agents_spawned),
                        "vulns": brain.ctx.vulnerabilities,
                        "chains": brain.ctx.attack_chains,
                    }
                except Exception as e:
                    logger.error(f"Target {target} failed: {e}")
                    return {
                        "status": "failed",
                        "target": target,
                        "error": str(e),
                    }

        # Run all targets with concurrency limit
        tasks = [run_one(t) for t in self.targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate
        for target, result in zip(self.targets, results):
            if isinstance(result, Exception):
                self.results[target] = {
                    "status": "error", "error": str(result)
                }
            else:
                self.results[target] = result

        # Summary report
        await self._generate_batch_report()
        return self.results

    async def _generate_batch_report(self):
        """Generate combined report across all targets"""
        duration = (datetime.now() - self.start_time).total_seconds()

        total_vulns = sum(
            r.get("vulnerabilities", 0)
            for r in self.results.values()
        )
        total_exploits = sum(
            r.get("exploits", 0)
            for r in self.results.values()
        )
        completed = sum(
            1 for r in self.results.values() if r.get("status") == "complete"
        )
        failed = sum(
            1 for r in self.results.values() if r.get("status") != "complete"
        )

        report = {
            "metadata": {
                "title": "Multi-Target Penetration Test Report",
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": duration,
                "targets_total": len(self.targets),
                "targets_completed": completed,
                "targets_failed": failed,
                "total_vulnerabilities": total_vulns,
                "total_exploits": total_exploits,
            },
            "targets": self.results,
        }

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.report_dir / f"multi_pentest_{ts}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)

        logger.info(f"\n{'=' * 60}")
        logger.info("MULTI-TARGET SUMMARY")
        logger.info(f"{'=' * 60}")
        logger.info(f"Duration: {duration:.0f}s")
        logger.info(f"Targets: {completed}/{len(self.targets)} completed")
        logger.info(f"Vulnerabilities: {total_vulns}")
        logger.info(f"Exploits: {total_exploits}")

        for target, result in self.results.items():
            status = result.get("status", "?")
            vulns = result.get("vulnerabilities", 0)
            icon = "✓" if status == "complete" else "✗"
            logger.info(f"  {icon} {target}: {vulns} vulns ({status})")

        logger.info(f"Report: {path}")