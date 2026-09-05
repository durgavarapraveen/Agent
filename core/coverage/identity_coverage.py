"""
Identity-Aware Coverage Engine (Phase 30).

Tracks test coverage per (endpoint, identity) pair. A test against
endpoint /admin with user_role=admin is a different coverage cell than
the same test with user_role=guest. This drives authorization testing
to cover every role × endpoint combination.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class IdentityCoverageCell:
    test_id: str
    endpoint_id: str
    identity_id: str
    status: str = "NOT_TESTED"
    last_executed: Optional[datetime] = None
    evidence_ids: List[str] = field(default_factory=list)
    finding_id: Optional[str] = None
    notes: str = ""


class IdentityCoverageEngine:

    def __init__(self) -> None:
        self._cells: Dict[Tuple[str, str, str], IdentityCoverageCell] = {}
        self._identities: Dict[str, Dict[str, Any]] = {}
        self._auth_tests: Set[str] = {
            "authz_idor_01", "authz_priv_esc_01", "authz_horizontal_01",
            "authz_object_level_01", "authz_function_level_01",
            "authz_role_boundary_01", "authz_method_tampering_01",
            "authz_mass_assignment_01",
        }

    def register_identity(self, identity_id: str, role: str = "",
                          metadata: Dict[str, Any] = None) -> None:
        self._identities[identity_id] = {
            "role": role,
            "metadata": metadata or {},
        }

    def initialize_matrix(self, test_ids: List[str],
                          endpoint_ids: List[str],
                          identity_ids: List[str]) -> int:
        count = 0
        for tid in test_ids:
            needs_identity = tid in self._auth_tests
            for eid in endpoint_ids:
                if needs_identity:
                    for iid in identity_ids:
                        key = (tid, eid, iid)
                        if key not in self._cells:
                            self._cells[key] = IdentityCoverageCell(tid, eid, iid)
                            count += 1
                else:
                    key = (tid, eid, "")
                    if key not in self._cells:
                        self._cells[key] = IdentityCoverageCell(tid, eid, "")
                        count += 1
        logger.info(f"IDENTITY_COVERAGE initialized cells={count} "
                    f"identities={len(identity_ids)}")
        return count

    def mark_tested(self, test_id: str, endpoint_id: str,
                    identity_id: str, status: str,
                    evidence_ids: List[str] = None,
                    finding_id: str = "") -> None:
        key = (test_id, endpoint_id, identity_id)
        cell = self._cells.get(key)
        if not cell:
            cell = IdentityCoverageCell(test_id, endpoint_id, identity_id)
            self._cells[key] = cell
        cell.status = status
        cell.last_executed = datetime.utcnow()
        if evidence_ids:
            cell.evidence_ids.extend(evidence_ids)
        if finding_id:
            cell.finding_id = finding_id

    def get_gaps(self, test_id: str = "", endpoint_id: str = "",
                 identity_id: str = "") -> List[IdentityCoverageCell]:
        gaps = []
        for cell in self._cells.values():
            if cell.status != "NOT_TESTED":
                continue
            if test_id and cell.test_id != test_id:
                continue
            if endpoint_id and cell.endpoint_id != endpoint_id:
                continue
            if identity_id and cell.identity_id != identity_id:
                continue
            gaps.append(cell)
        return gaps

    def get_authz_gaps(self) -> List[IdentityCoverageCell]:
        return [c for c in self._cells.values()
                if c.test_id in self._auth_tests and c.status == "NOT_TESTED"]

    def coverage_percentage(self) -> float:
        if not self._cells:
            return 100.0
        tested = sum(1 for c in self._cells.values()
                     if c.status not in ("NOT_TESTED", "NOT_APPLICABLE"))
        return (tested / len(self._cells)) * 100.0

    def authz_coverage_percentage(self) -> float:
        authz_cells = [c for c in self._cells.values()
                       if c.test_id in self._auth_tests]
        if not authz_cells:
            return 100.0
        tested = sum(1 for c in authz_cells
                     if c.status not in ("NOT_TESTED", "NOT_APPLICABLE"))
        return (tested / len(authz_cells)) * 100.0

    def summary(self) -> Dict[str, Any]:
        total = len(self._cells)
        by_status: Dict[str, int] = {}
        for c in self._cells.values():
            by_status[c.status] = by_status.get(c.status, 0) + 1
        return {
            "total_cells": total,
            "by_status": by_status,
            "coverage_pct": round(self.coverage_percentage(), 1),
            "authz_coverage_pct": round(self.authz_coverage_percentage(), 1),
            "identities": len(self._identities),
        }
