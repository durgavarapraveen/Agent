"""
Phase 5 Module 5.4: Trend Analyzer Engine (core/trend_analyzer.py)

Privacy-safe scan history SQLite storage, MTTD & Remediation Rate calculators,
recurring vulnerability detection, and predictive trend analysis using scipy linregress.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from core.database import DatabaseManager

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """Performs historical trend analysis, MTTD/remediation rate computation, and predictive linregress trend analysis using PostgreSQL."""

    def __init__(self):
        self._init_db()

    def _init_db(self):
        """Create privacy-safe aggregated scan history table."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS scan_history_trend (
                            scan_id TEXT PRIMARY KEY,
                            target_name TEXT NOT NULL,
                            scan_date TIMESTAMP NOT NULL,
                            finding_counts_json TEXT NOT NULL,
                            total_risk_score REAL NOT NULL,
                            avg_confidence REAL NOT NULL
                        )
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS finding_lifecycle (
                            id SERIAL PRIMARY KEY,
                            target_name TEXT NOT NULL,
                            vuln_key TEXT NOT NULL,
                            first_seen TIMESTAMP NOT NULL,
                            last_seen TIMESTAMP NOT NULL,
                            remediated_at TIMESTAMP,
                            consecutive_scan_count INTEGER DEFAULT 1
                        )
                    """)
                    conn.commit()
        except Exception as e:
            logger.error(f"[TrendAnalyzer] DB init error: {e}")

    def record_scan_summary(
        self,
        scan_id: str,
        target_name: str,
        vulnerabilities: List[Dict[str, Any]],
        avg_confidence: float = 0.85
    ) -> Dict[str, Any]:
        """Record privacy-safe scan summary metrics (no raw PII/payloads)."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_risk = 0.0

        for v in vulnerabilities:
            sev = str(v.get("severity", "MEDIUM")).lower()
            counts[sev] = counts.get(sev, 0) + 1
            total_risk += float(v.get("risk_score", 5.0))

        counts_json = json.dumps(counts)
        ts_now = datetime.now().isoformat()

        conn = DatabaseManager.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO scan_history_trend (scan_id, target_name, scan_date, finding_counts_json, total_risk_score, avg_confidence) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                    target_name = EXCLUDED.target_name, scan_date = EXCLUDED.scan_date,
                    finding_counts_json = EXCLUDED.finding_counts_json, total_risk_score = EXCLUDED.total_risk_score,
                    avg_confidence = EXCLUDED.avg_confidence
                """, (scan_id, target_name, ts_now, counts_json, round(total_risk, 1), round(avg_confidence, 2)))
                conn.commit()
        finally:
            conn.close()

        # Update finding lifecycle for MTTD & Recurring detection
        return self._update_lifecycle(target_name, vulnerabilities)

    def _update_lifecycle(self, target_name: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Track finding discovery and remediation across scans."""
        now = datetime.now().isoformat()
        current_keys = set()
        recurring_flagged = []

        for v in vulnerabilities:
            cve = v.get("cve") or v.get("cve_id")
            endpoint = v.get("target") or v.get("location") or ""
            vtype = v.get("type") or v.get("title") or "VULN"
            vuln_key = cve if cve else f"{endpoint}:{vtype}"
            current_keys.add(vuln_key)

            conn = DatabaseManager.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT id, consecutive_scan_count FROM finding_lifecycle WHERE target_name = %s AND vuln_key = %s AND remediated_at IS NULL",
                        (target_name, vuln_key)
                    )
                    row = cursor.fetchone()
                    if row:
                        rec_id, count = row
                        new_count = count + 1
                        cursor.execute(
                            "UPDATE finding_lifecycle SET last_seen = %s, consecutive_scan_count = %s WHERE id = %s",
                            (now, new_count, rec_id)
                        )
                        if new_count >= 3:
                            recurring_flagged.append({
                                "vuln_key": vuln_key,
                                "scan_count": new_count,
                                "warning": f"This vulnerability has persisted across {new_count} scans. Please prioritize root-cause analysis."
                            })
                    else:
                        cursor.execute(
                            "INSERT INTO finding_lifecycle (target_name, vuln_key, first_seen, last_seen, consecutive_scan_count) VALUES (%s, %s, %s, %s, 1)",
                            (target_name, vuln_key, now, now)
                        )
                    conn.commit()
            finally:
                conn.close()

        # Mark missing findings as remediated
        conn = DatabaseManager.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, vuln_key FROM finding_lifecycle WHERE target_name = %s AND remediated_at IS NULL",
                    (target_name,)
                )
                for rec_id, vkey in cursor.fetchall():
                    if vkey not in current_keys:
                        cursor.execute(
                            "UPDATE finding_lifecycle SET remediated_at = %s WHERE id = %s",
                            (now, rec_id)
                        )
                conn.commit()
        finally:
            conn.close()

        return {"recurring_vulnerabilities": recurring_flagged}

    def compute_mttd_and_remediation_rate(self, target_name: str) -> Dict[str, Any]:
        """
        Compute MTTD = average(days_between_first_seen_and_remediated)
        Compute remediation_rate = (remediated_findings / total_findings_previous_scan) * 100
        """
        conn = DatabaseManager.get_connection()
        try:
            with conn.cursor() as cursor:
                # MTTD
                cursor.execute(
                    "SELECT first_seen, remediated_at FROM finding_lifecycle WHERE target_name = %s AND remediated_at IS NOT NULL",
                    (target_name,)
                )
                durations_days = []
                for f_seen, r_seen in cursor.fetchall():
                    try:
                        # Postgres timestamp handling vs string parsing might differ slightly but fromisoformat handles typical pg timestamps
                        dt_f = f_seen if isinstance(f_seen, datetime) else datetime.fromisoformat(str(f_seen))
                        dt_r = r_seen if isinstance(r_seen, datetime) else datetime.fromisoformat(str(r_seen))
                        durations_days.append(max(0.1, (dt_r - dt_f).total_seconds() / 86400.0))
                    except Exception:
                        pass
    
                mttd_days = round(sum(durations_days) / len(durations_days), 1) if durations_days else 0.0
    
                # Remediation Rate
                cursor.execute(
                    "SELECT count(*) FROM finding_lifecycle WHERE target_name = %s AND remediated_at IS NOT NULL",
                    (target_name,)
                )
                remediated_count = cursor.fetchone()[0] or 0
    
                cursor.execute(
                    "SELECT count(*) FROM finding_lifecycle WHERE target_name = %s",
                    (target_name,)
                )
                total_lifecycle_count = cursor.fetchone()[0] or 1
    
                remediation_rate = round((remediated_count / max(1, total_lifecycle_count)) * 100.0, 1)
    
                return {
                    "mttd_days": mttd_days,
                    "remediation_rate_percent": remediation_rate,
                    "remediated_count": remediated_count,
                    "total_historical_count": total_lifecycle_count
                }
        finally:
            conn.close()

    def predict_future_trends(self, target_name: str, scan_limit: int = 6) -> Dict[str, Any]:
        """
        Use scipy.stats.linregress to fit total_findings vs scan_sequence_number over last N scans.
        Generates predictive text and Matplotlib base64 trend graph.
        """
        conn = DatabaseManager.get_connection()
        scan_records = []
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT scan_id, scan_date, finding_counts_json FROM scan_history_trend WHERE target_name = %s ORDER BY scan_date ASC LIMIT %s",
                    (target_name, scan_limit)
                )
                for row in cursor.fetchall():
                    counts = json.loads(row[2])
                    total = sum(counts.values())
                    scan_records.append(total)
        finally:
            conn.close()

        if len(scan_records) < 2:
            return {
                "prediction": "Insufficient scan history (minimum 2 scans required for linear regression).",
                "slope": 0.0,
                "base64_graph": ""
            }

        import numpy as np
        from scipy import stats

        x = np.arange(1, len(scan_records) + 1)
        y = np.array(scan_records)

        slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)

        if slope > 0:
            pred_3m = int(round(slope * (len(scan_records) + 6) + intercept))
            prediction = f"If the trend continues, total findings will increase to {max(1, pred_3m)} in 3 months."
        elif slope < 0:
            weeks_to_zero = int(round(abs(y[-1] / slope))) if abs(slope) > 0.01 else 8
            prediction = f"At the current remediation pace, all critical findings will be resolved in {max(1, weeks_to_zero)} weeks."
        else:
            prediction = "Vulnerability discovery rate is stable across recent scans."

        # Matplotlib chart generation
        base64_graph = ""
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import io

            fig, ax = plt.subplots(figsize=(6, 3))
            ax.plot(x, y, "o-", label="Actual Findings", color="#12233b")

            # Fit line
            x_future = np.arange(1, len(scan_records) + 4)
            y_future = slope * x_future + intercept
            ax.plot(x_future, y_future, "--", label="Projected Trend", color="#d9531e")

            ax.set_xlabel("Scan Sequence")
            ax.set_ylabel("Total Findings")
            ax.set_title("Predictive Vulnerability Trend")
            ax.legend()
            plt.tight_layout()

            buf = io.BytesIO()
            plt.savefig(buf, format="png", dpi=100)
            plt.close(fig)
            buf.seek(0)
            base64_graph = json.dumps(buf.read().hex())  # hex/base64 representation
            import base64
            buf.seek(0)
            base64_graph = base64.b64encode(buf.read()).decode("utf-8")
        except Exception as e:
            logger.warning(f"[TrendAnalyzer] Matplotlib trend graph failed: {e}")

        return {
            "prediction": prediction,
            "slope": round(float(slope), 2),
            "r_value": round(float(r_value), 2),
            "base64_graph": base64_graph
        }
