
import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TargetResult:
    target: str
    status: str = "pending"
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    exploit_count: int = 0
    report_path: str = ""
    error: str = ""


class CampaignManager:

    def __init__(self, targets: List[str], tier: str = "POC",
                 max_parallel: int = 3, auth_file: str = None,
                 phases: list = None, credentials: dict = None,
                 report_dir: str = None):
        from core.common.reports_config import reports_enabled, reports_dir as _rd
        self._reports_enabled = reports_enabled()
        if report_dir is None:
            report_dir = str(_rd())
        self.targets = [t.strip() for t in targets if t.strip()]
        self.tier = tier
        self.max_parallel = max_parallel
        self.auth_file = auth_file
        self.phases = phases
        self.credentials = credentials
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, TargetResult] = {}
        self.start_time = 0.0
        self.campaign_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        for t in self.targets:
            self.results[t] = TargetResult(target=t)

    async def _scan_target(self, target: str, semaphore: asyncio.Semaphore):
        async with semaphore:
            result = self.results[target]
            result.status = "running"
            result.start_time = time.time()
            self._write_progress()

            logger.info(f"[Campaign] Starting scan: {target}")

            try:
                from core.orchestration.central_brain import CentralBrain

                brain = CentralBrain(target=target, tier=self.tier)

                if self.credentials and isinstance(self.credentials, (list, dict)):
                    creds = self.credentials if isinstance(self.credentials, list) else [self.credentials]
                    brain.ctx.harvested_creds.extend(creds)

                phases_to_run = self.phases or ["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"]

                await brain.run_main_loop(
                    auth_document=self.auth_file,
                    phases=phases_to_run,
                )

                result.status = "completed"
                result.vuln_count = len(brain.ctx.vulnerabilities)
                result.exploit_count = len(brain.ctx.exploit_results)

                for v in brain.ctx.vulnerabilities:
                    sev = (v.get("severity") or "").upper()
                    if sev == "CRITICAL":
                        result.critical_count += 1
                    elif sev == "HIGH":
                        result.high_count += 1

                # Find the latest report file for this target
                report_files = sorted(
                    self.report_dir.glob(f"pentest_*.json"),
                    key=lambda p: p.stat().st_mtime, reverse=True
                )
                if report_files:
                    result.report_path = str(report_files[0])

                logger.info(f"[Campaign] Completed: {target} — "
                           f"{result.vuln_count} vulns, {result.exploit_count} exploits")

            except Exception as e:
                result.status = "failed"
                result.error = str(e)[:500]
                logger.error(f"[Campaign] Failed: {target} — {e}")

            result.end_time = time.time()
            result.duration_seconds = result.end_time - result.start_time
            self._write_progress()

    async def run(self) -> Dict:
        self.start_time = time.time()
        logger.info(f"\n{'='*60}")
        logger.info(f"CAMPAIGN START: {len(self.targets)} targets, "
                    f"max {self.max_parallel} parallel, tier={self.tier}")
        logger.info(f"{'='*60}\n")

        semaphore = asyncio.Semaphore(self.max_parallel)

        tasks = [self._scan_target(t, semaphore) for t in self.targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        total_time = time.time() - self.start_time

        report = self._generate_campaign_report(total_time)
        self._save_campaign_report(report)

        completed = len([r for r in self.results.values() if r.status == "completed"])
        failed = len([r for r in self.results.values() if r.status == "failed"])
        total_vulns = sum(r.vuln_count for r in self.results.values())

        logger.info(f"\n{'='*60}")
        logger.info(f"CAMPAIGN COMPLETE: {completed} succeeded, {failed} failed, "
                    f"{total_vulns} total vulns, {total_time:.0f}s elapsed")
        logger.info(f"{'='*60}\n")

        return report

    def _generate_campaign_report(self, total_time: float) -> Dict:
        all_vulns = []
        for result in self.results.values():
            if result.report_path and Path(result.report_path).exists():
                try:
                    report_data = json.loads(Path(result.report_path).read_text(encoding="utf-8"))
                    for v in report_data.get("vulnerabilities", []):
                        v["campaign_target"] = result.target
                        all_vulns.append(v)
                except Exception:
                    pass

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in all_vulns:
            sev = (v.get("severity") or "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Cross-target analysis: common findings
        vuln_titles = {}
        for v in all_vulns:
            title = v.get("title", "")
            if title:
                if title not in vuln_titles:
                    vuln_titles[title] = []
                vuln_titles[title].append(v.get("campaign_target", ""))
        common_vulns = [
            {"title": title, "targets": list(set(targets)), "count": len(targets)}
            for title, targets in vuln_titles.items()
            if len(set(targets)) > 1
        ]
        common_vulns.sort(key=lambda x: x["count"], reverse=True)

        report = {
            "campaign_id": self.campaign_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": total_time,
            "tier": self.tier,
            "summary": {
                "total_targets": len(self.targets),
                "completed": len([r for r in self.results.values() if r.status == "completed"]),
                "failed": len([r for r in self.results.values() if r.status == "failed"]),
                "total_vulnerabilities": len(all_vulns),
                "severity_counts": severity_counts,
                "total_exploits": sum(r.exploit_count for r in self.results.values()),
            },
            "targets": [
                {
                    "target": r.target,
                    "status": r.status,
                    "duration_seconds": round(r.duration_seconds, 1),
                    "vulnerabilities": r.vuln_count,
                    "criticals": r.critical_count,
                    "highs": r.high_count,
                    "exploits": r.exploit_count,
                    "report_path": r.report_path,
                    "error": r.error,
                }
                for r in self.results.values()
            ],
            "cross_target_analysis": {
                "common_vulnerabilities": common_vulns[:20],
                "most_vulnerable_target": max(
                    self.results.values(), key=lambda r: r.vuln_count
                ).target if self.results else "",
            },
            "all_vulnerabilities": all_vulns,
        }

        return report

    def _save_campaign_report(self, report: Dict):
        path = self.report_dir / f"campaign_{self.campaign_id}.json"
        try:
            path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            logger.info(f"[Campaign] Report saved to {path}")
        except Exception as e:
            logger.error(f"[Campaign] Failed to save report: {e}")

    def _write_progress(self):
        progress = {
            "campaign_id": self.campaign_id,
            "total_targets": len(self.targets),
            "completed": len([r for r in self.results.values() if r.status == "completed"]),
            "running": len([r for r in self.results.values() if r.status == "running"]),
            "failed": len([r for r in self.results.values() if r.status == "failed"]),
            "pending": len([r for r in self.results.values() if r.status == "pending"]),
            "targets": {
                t: {"status": r.status, "vulns": r.vuln_count, "duration": round(r.duration_seconds, 1)}
                for t, r in self.results.items()
            },
            "timestamp": datetime.now().isoformat(),
        }
        try:
            path = self.report_dir / "campaign_progress.json"
            path.write_text(json.dumps(progress, indent=2), encoding="utf-8")
        except Exception:
            pass
