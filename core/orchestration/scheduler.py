
import asyncio
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# Path is resolved at scheduler runtime via reports_config.
from core.common.reports_config import reports_dir as _rd
SCHEDULES_FILE = _rd() / "scan_schedules.json"


@dataclass
class ScanSchedule:
    schedule_id: str
    target: str
    tier: str = "POC"
    interval_hours: int = 24
    enabled: bool = True
    phases: List[str] = field(default_factory=lambda: ["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"])
    created_at: str = ""
    last_run: str = ""
    next_run: str = ""
    last_report: str = ""
    run_count: int = 0
    last_delta: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.next_run:
            self.next_run = datetime.now().isoformat()


class ScanScheduler:

    def __init__(self):
        self.schedules: Dict[str, ScanSchedule] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._load_schedules()

    def _load_schedules(self):
        if SCHEDULES_FILE.exists():
            try:
                data = json.loads(SCHEDULES_FILE.read_text(encoding="utf-8"))
                for sid, sdata in data.items():
                    self.schedules[sid] = ScanSchedule(**sdata)
                logger.info(f"[Scheduler] Loaded {len(self.schedules)} schedules")
            except Exception as e:
                logger.warning(f"[Scheduler] Failed to load schedules: {e}")

    def _save_schedules(self):
        try:
            SCHEDULES_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {sid: asdict(s) for sid, s in self.schedules.items()}
            SCHEDULES_FILE.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except Exception as e:
            logger.warning(f"[Scheduler] Failed to save schedules: {e}")

    def add_schedule(self, target: str, interval_hours: int = 24,
                     tier: str = "POC", phases: list | None = None) -> ScanSchedule:
        import hashlib
        schedule_id = hashlib.md5(f"{target}:{time.time()}".encode()).hexdigest()[:12]

        schedule = ScanSchedule(
            schedule_id=schedule_id,
            target=target,
            tier=tier,
            interval_hours=interval_hours,
            phases=phases or ["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"],
        )
        self.schedules[schedule_id] = schedule
        self._save_schedules()
        logger.info(f"[Scheduler] Added schedule {schedule_id}: {target} every {interval_hours}h")
        return schedule

    def remove_schedule(self, schedule_id: str) -> bool:
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            self._save_schedules()
            return True
        return False

    def update_schedule(self, schedule_id: str, **kwargs) -> Optional[ScanSchedule]:
        if schedule_id not in self.schedules:
            return None
        schedule = self.schedules[schedule_id]
        for key, value in kwargs.items():
            if hasattr(schedule, key):
                setattr(schedule, key, value)
        self._save_schedules()
        return schedule

    def list_schedules(self) -> List[Dict]:
        return [asdict(s) for s in self.schedules.values()]

    def _compute_delta(self, current_report: Dict, previous_report: Dict) -> Dict:
        curr_vulns = {v.get("title", ""): v for v in current_report.get("vulnerabilities", [])}
        prev_vulns = {v.get("title", ""): v for v in previous_report.get("vulnerabilities", [])}

        curr_titles = set(curr_vulns.keys())
        prev_titles = set(prev_vulns.keys())

        new_vulns = []
        for title in curr_titles - prev_titles:
            v = curr_vulns[title]
            new_vulns.append({
                "title": title,
                "severity": v.get("severity", "INFO"),
                "type": v.get("type", ""),
            })

        fixed_vulns = []
        for title in prev_titles - curr_titles:
            v = prev_vulns[title]
            fixed_vulns.append({
                "title": title,
                "severity": v.get("severity", "INFO"),
                "type": v.get("type", ""),
            })

        unchanged = curr_titles & prev_titles

        # Severity changes
        severity_changes = []
        for title in unchanged:
            curr_sev = curr_vulns[title].get("severity", "")
            prev_sev = prev_vulns[title].get("severity", "")
            if curr_sev != prev_sev:
                severity_changes.append({
                    "title": title,
                    "old_severity": prev_sev,
                    "new_severity": curr_sev,
                })

        return {
            "timestamp": datetime.now().isoformat(),
            "new_vulnerabilities": new_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "unchanged_count": len(unchanged),
            "severity_changes": severity_changes,
            "summary": {
                "new": len(new_vulns),
                "fixed": len(fixed_vulns),
                "unchanged": len(unchanged),
                "severity_changed": len(severity_changes),
            },
        }

    async def _run_scheduled_scan(self, schedule: ScanSchedule):
        logger.info(f"[Scheduler] Running scheduled scan: {schedule.target}")

        try:
            # Import here to avoid circular imports
            import sys
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

            from core.orchestration.central_brain import CentralBrain

            brain = CentralBrain(target=schedule.target, tier=schedule.tier)
            await brain.run_main_loop(phases=schedule.phases)

            # Find the latest report
            from core.common.reports_config import reports_dir as _rd2
            report_dir = _rd2()
            reports = sorted(
                report_dir.glob("pentest_*.json"),
                key=lambda p: p.stat().st_mtime, reverse=True
            )

            current_report_path = str(reports[0]) if reports else ""
            schedule.last_report = current_report_path

            # Compute delta against previous report
            if current_report_path and schedule.run_count > 0:
                try:
                    current = json.loads(Path(current_report_path).read_text(encoding="utf-8"))
                    # Find previous report for this target
                    prev_reports = [
                        r for r in reports[1:]
                        if schedule.target in json.loads(r.read_text(encoding="utf-8")).get("metadata", {}).get("target", "")
                    ]
                    if prev_reports:
                        previous = json.loads(prev_reports[0].read_text(encoding="utf-8"))
                        delta = self._compute_delta(current, previous)
                        schedule.last_delta = delta

                        # Save delta report
                        delta_path = report_dir / f"delta_{schedule.schedule_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        delta_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
                        logger.info(f"[Scheduler] Delta: {delta['summary']['new']} new, "
                                   f"{delta['summary']['fixed']} fixed, "
                                   f"{delta['summary']['unchanged']} unchanged")
                except Exception as e:
                    logger.warning(f"[Scheduler] Delta computation failed: {e}")

            schedule.run_count += 1
            schedule.last_run = datetime.now().isoformat()
            schedule.next_run = (datetime.now() + timedelta(hours=schedule.interval_hours)).isoformat()
            self._save_schedules()

            logger.info(f"[Scheduler] Scan complete: {schedule.target}, next run at {schedule.next_run}")

        except Exception as e:
            logger.error(f"[Scheduler] Scheduled scan failed for {schedule.target}: {e}")
            schedule.last_run = datetime.now().isoformat()
            schedule.next_run = (datetime.now() + timedelta(hours=schedule.interval_hours)).isoformat()
            self._save_schedules()

    def _check_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        while self._running:
            now = datetime.now()
            for schedule in list(self.schedules.values()):
                if not schedule.enabled:
                    continue
                try:
                    next_run = datetime.fromisoformat(schedule.next_run)
                    if now >= next_run:
                        loop.run_until_complete(self._run_scheduled_scan(schedule))
                except Exception as e:
                    logger.error(f"[Scheduler] Error checking schedule {schedule.schedule_id}: {e}")

            time.sleep(60)  # Check every minute

        loop.close()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._check_loop, daemon=True)
        self._thread.start()
        logger.info(f"[Scheduler] Started with {len(self.schedules)} schedules")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("[Scheduler] Stopped")


# Singleton
_scheduler: Optional[ScanScheduler] = None


def get_scheduler() -> ScanScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler()
    return _scheduler
