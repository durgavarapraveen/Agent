
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from core.orchestration.central_brain import CentralBrain
from core.common.config import get_config
from core.observability.correlation import CorrelationContext
from core.security.tenant_isolation import TenantContext
from core.validation.readiness_gate import AutonomousReadinessGate, ReadinessStatus

logger = logging.getLogger(__name__)


class MetaBrain:

    def __init__(self, targets: List[str], auth_document: str = ""):
        self.targets = targets
        self.auth_document = auth_document
        config = get_config()
        self.max_parallel = config.get_int("MAX_PARALLEL_TARGETS", 3)
        self.results: Dict[str, Dict] = {}
        from core.common.reports_config import reports_dir as _rd
        self.report_dir = _rd()
        self.report_dir.mkdir(exist_ok=True)
        self.start_time = datetime.now()

    async def run_all(self) -> Dict[str, Dict]:
        logger.info("=" * 60)
        logger.info("META BRAIN — MULTI-TARGET PENTESTING")
        logger.info("=" * 60)
        logger.info(f"Targets: {len(self.targets)}")
        logger.info(f"Max parallel: {self.max_parallel}")
        for i, t in enumerate(self.targets, 1):
            logger.info(f"  [{i}] {t}")
        logger.info("=" * 60)

        # Pre-flight readiness check across all targets
        try:
            gate = AutonomousReadinessGate()
            eval_result = gate.evaluate_all()
            logger.info(f"[MetaBrain] Pre-flight readiness status: {eval_result.status.value} (score={eval_result.readiness_score:.1f}%)")
        except Exception as _ge:
            logger.debug(f"[MetaBrain] Readiness gate check skipped: {_ge}")

        semaphore = asyncio.Semaphore(self.max_parallel)

        async def run_one(target: str) -> Dict:
            async with semaphore:
                logger.info(f"\n>>> STARTING: {target}")
                tenant_id = target.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_")
                with TenantContext(tenant_id=tenant_id):
                    with CorrelationContext():
                        brain = CentralBrain(target)
                        try:
                            if hasattr(brain, "run"):
                                await brain.run(auth_document=self.auth_document)
                            else:
                                await brain.run_main_loop(auth_document=self.auth_document)
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
            if isinstance(result, BaseException):
                self.results[target] = {
                    "status": "error", "error": str(result)
                }
            else:
                self.results[target] = result

        # Summary report
        await self._generate_batch_report()
        return self.results

    async def _generate_batch_report(self):
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
