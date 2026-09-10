from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

import psycopg2.extras

from core.findings.finding import Finding, FindingState
from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)

# Columns that map directly to findings_v2 table columns
_DIRECT_COLS = {
    "finding_id", "title", "description", "severity",
    "affected_endpoint", "state", "evidence_ids",
}


class FindingStore:

    def __init__(self, storage_path: str = "findings.json") -> None:
        # storage_path kept for backward compatibility; ignored.
        self.storage_path = storage_path

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def store(self, finding: Finding) -> None:
        d = finding.to_dict()
        extra = {k: v for k, v in d.items() if k not in _DIRECT_COLS}
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO findings_v2
                        (finding_id, title, description, severity,
                         affected_endpoint, state, evidence_ids, extra)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        title            = EXCLUDED.title,
                        description      = EXCLUDED.description,
                        severity         = EXCLUDED.severity,
                        affected_endpoint = EXCLUDED.affected_endpoint,
                        state            = EXCLUDED.state,
                        evidence_ids     = EXCLUDED.evidence_ids,
                        extra            = EXCLUDED.extra
                    """,
                    (
                        d["finding_id"],
                        d["title"],
                        d["description"],
                        d["severity"],
                        d.get("affected_endpoint", ""),
                        d["state"],
                        d.get("evidence_ids", []),
                        json.dumps(extra),
                    ),
                )
            conn.commit()

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_finding(row: dict) -> Finding:
        d = {
            "finding_id": row["finding_id"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "affected_endpoint": row.get("affected_endpoint", ""),
            "state": row.get("state", FindingState.DISCOVERED.value),
            "evidence_ids": row.get("evidence_ids") or [],
        }
        extra = row.get("extra")
        if extra:
            if isinstance(extra, str):
                extra = json.loads(extra)
            d.update(extra)
        return Finding.from_dict(d)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, finding_id: str) -> Optional[Finding]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM findings_v2 WHERE finding_id = %s",
                    (finding_id,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_finding(row)

    def list_by_state(self, state: FindingState) -> List[Finding]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM findings_v2 WHERE state = %s",
                    (state.value,),
                )
                rows = cur.fetchall()
        return [self._row_to_finding(r) for r in rows]

    def list_all(self) -> List[Finding]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM findings_v2")
                rows = cur.fetchall()
        return [self._row_to_finding(r) for r in rows]

    # ------------------------------------------------------------------
    # Bulk (P0-2): dedupe before persistence
    # ------------------------------------------------------------------

    def bulk_store(self, findings: List[Finding]) -> Dict[str, int]:
        from core.validation.dedup import fingerprint
        by_fp: Dict[str, Finding] = {}
        for f in findings or []:
            try:
                fp = fingerprint(
                    cve_id=(f.cve or ""),
                    file_path=(f.affected_endpoint or f.affected_asset or ""),
                    function_name=(f.parameter or ""),
                    package_version="",
                    target=(f.affected_asset or ""),
                    title=(f.title or ""),
                    vuln_type=(f.category or ""),
                )
            except Exception:
                fp = f.finding_id
            existing = by_fp.get(fp)
            if existing is None:
                by_fp[fp] = f
                continue
            # Merge: keep the higher-confidence record, union evidence.
            keeper = existing if existing.confidence >= f.confidence else f
            other = f if keeper is existing else existing
            merged_ev = list(dict.fromkeys((keeper.evidence_ids or []) + (other.evidence_ids or [])))
            keeper.evidence_ids = merged_ev
            if not keeper.proof and other.proof:
                keeper.proof = other.proof
            keeper.metadata.setdefault("merged_from", []).append(other.finding_id)
            by_fp[fp] = keeper

        inserted = 0
        for f in by_fp.values():
            try:
                self.store(f)
                inserted += 1
            except Exception as e:
                logger.warning(f"bulk_store insert failed for {f.finding_id}: {e}")
        return {
            "input": len(findings or []),
            "unique": len(by_fp),
            "inserted": inserted,
            "collapsed": len(findings or []) - len(by_fp),
        }
