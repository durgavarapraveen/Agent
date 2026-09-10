
import csv
import hashlib
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Set

from core.security.encryption import encrypt
from core.security.audit_logger import AuditLogger
from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)

RETAIN_SCANS_DAYS = 90
RETAIN_PII_DAYS = 365
GRACE_PERIOD_DAYS = 30


class RetentionPolicy:

    def __init__(self, reports_dir: str = None, archives_dir: str = "archives",  # noqa: ARG002
                 db_path: str = None, audit_log_path: str = "data/audit.log"):
        from core.common.reports_config import reports_enabled, reports_dir as _rd
        self._reports_enabled = reports_enabled()
        if reports_dir is None:
            reports_dir = str(_rd())
        self.reports_dir = Path(reports_dir)
        if self._reports_enabled:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.archives_dir = Path(archives_dir)
        self.archives_dir.mkdir(parents=True, exist_ok=True)
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self._legal_holds: Set[str] = set()  # scan IDs under legal hold

    def archive_scan_data(self, scan_dir: Path) -> Path:
        scan_id = scan_dir.name
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_path = self.archives_dir / f"{scan_id}_{ts}.zip"
        enc_zip_path = self.archives_dir / f"{scan_id}_{ts}.enc.zip"
        shutil.make_archive(str(zip_path.with_suffix("")), "zip", str(scan_dir))
        raw_bytes = zip_path.read_bytes()
        enc_bytes = encrypt(raw_bytes)
        enc_zip_path.write_bytes(enc_bytes)
        if zip_path.exists():
            os.remove(zip_path)
        logger.info(f"[RetentionPolicy] Encrypted archive created: {enc_zip_path}")
        return enc_zip_path

    def run_auto_cleanup(self) -> Dict[str, Any]:
        now = datetime.now()
        scans_cutoff = now - timedelta(days=RETAIN_SCANS_DAYS)
        pii_cutoff = now - timedelta(days=RETAIN_PII_DAYS)
        archive_cutoff = now - timedelta(days=GRACE_PERIOD_DAYS)

        deleted_scans = 0
        deleted_archives = 0
        deleted_pii = 0

        if self.reports_dir.exists():
            for folder in self.reports_dir.iterdir():
                if folder.is_dir():
                    scan_id = folder.name
                    if scan_id in self._legal_holds:
                        logger.info("[RetentionPolicy] Skipping %s — under legal hold", scan_id)
                        continue
                    mtime = datetime.fromtimestamp(folder.stat().st_mtime)
                    if mtime < scans_cutoff:
                        try:
                            self.archive_scan_data(folder)
                        except Exception as e:
                            logger.warning(f"[RetentionPolicy] Archive error for {folder}: {e}")
                        shutil.rmtree(folder, ignore_errors=True)
                        deleted_scans += 1

        if self.archives_dir.exists():
            for arc in self.archives_dir.glob("*.enc.zip"):
                mtime = datetime.fromtimestamp(arc.stat().st_mtime)
                if mtime < archive_cutoff:
                    try:
                        os.remove(arc)
                        deleted_archives += 1
                    except Exception:
                        pass

        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM scan_history WHERE scan_date < %s", (pii_cutoff.isoformat(),))
                    deleted_pii = cur.rowcount
                    conn.commit()
        except Exception as e:
            logger.debug(f"[RetentionPolicy] PII cleanup error: {e}")

        self.audit_logger.log_event(
            action="AUTO_CLEANUP", target="system_retention",
            details=f"Deleted {deleted_scans} scans, {deleted_archives} expired archives, {deleted_pii} PII records.",
        )
        return {"deleted_scans": deleted_scans, "deleted_archives": deleted_archives, "deleted_pii": deleted_pii}

    def delete_customer_data(self, customer_email: str) -> Dict[str, Any]:
        if not customer_email:
            return {"status": "error", "message": "Invalid customer email"}
        deleted_scans = 0
        email_clean = customer_email.strip().lower()

        if self.reports_dir.exists():
            for folder in self.reports_dir.iterdir():
                if folder.is_dir():
                    summary_file = folder / "report_summary.txt"
                    html_file = folder / "report.html"
                    match = False
                    for f in [summary_file, html_file]:
                        if f.exists() and email_clean in f.read_text(encoding="utf-8", errors="ignore").lower():
                            match = True
                            break
                    if match:
                        shutil.rmtree(folder, ignore_errors=True)
                        deleted_scans += 1

        self.audit_logger.anonymize_audit_entries(target_ip=customer_email)
        self.audit_logger.log_event(
            action="GDPR_CASCADE_DELETE", target="[REDACTED]",
            details="Cascade delete processed for customer email request.", user="gdpr_officer",
        )
        remaining = self.audit_logger.query_audit_log(target_ip=customer_email, mask_pii=False)
        return {
            "status": "success", "customer": "[REDACTED]",
            "deleted_scans": deleted_scans, "remaining_references": len(remaining),
        }

    def generate_gdpr_deletion_report(self, output_csv: str = "data/gdpr_deletion_report.csv") -> str:
        out_path = Path(output_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        log_hash = "GENESIS"
        if self.audit_logger.log_path.exists() and self.audit_logger.log_path.stat().st_size > 0:
            raw_bytes = self.audit_logger.log_path.read_bytes()
            log_hash = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
        valid, _ = self.audit_logger.verify_audit_integrity()
        headers = ["report_date", "deleted_scans_count", "deleted_pii_count", "audit_log_sha256", "chain_integrity_verified"]
        row = [datetime.now().strftime("%Y-%m-%d"), 0, 0, log_hash, str(valid)]
        with open(out_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerow(row)
        return str(out_path)

    def set_legal_hold(self, scan_id: str) -> None:
        self._legal_holds.add(scan_id)
        self.audit_logger.log_event(
            action="LEGAL_HOLD_SET", target=scan_id,
            details=f"Legal hold placed on scan {scan_id}",
        )
        logger.info("[RetentionPolicy] Legal hold set for scan=%s", scan_id)

    def release_legal_hold(self, scan_id: str) -> None:
        self._legal_holds.discard(scan_id)
        self.audit_logger.log_event(
            action="LEGAL_HOLD_RELEASED", target=scan_id,
            details=f"Legal hold released for scan {scan_id}",
        )
        logger.info("[RetentionPolicy] Legal hold released for scan=%s", scan_id)

    def is_held(self, scan_id: str) -> bool:
        return scan_id in self._legal_holds
