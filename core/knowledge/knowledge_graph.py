from __future__ import annotations

from typing import Any, Dict, List, Optional


class KnowledgeGraph:

    def __init__(self) -> None:
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._evidence: Dict[str, Dict[str, Any]] = {}
        self._endpoints: Dict[str, Dict[str, Any]] = {}
        self._identities: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, str]] = []

    def add_finding(self, finding: Any) -> None:
        fid = getattr(finding, "finding_id", None) or finding.get("finding_id", "")
        data = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        self._findings[fid] = data

    def add_evidence(self, evidence: Any) -> None:
        eid = getattr(evidence, "evidence_id", None) or evidence.get("evidence_id", "")
        data = evidence.to_dict() if hasattr(evidence, "to_dict") else dict(evidence)
        self._evidence[eid] = data

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        eid = endpoint.get("endpoint_id", endpoint.get("url", ""))
        self._endpoints[eid] = endpoint

    def add_identity(self, identity_id: str, data: Dict[str, Any]) -> None:
        self._identities[identity_id] = data

    def connect_evidence(self, finding_id: str, evidence_id: str) -> None:
        self._edges.append({"from": finding_id, "to": evidence_id, "type": "has_evidence"})

    def connect_finding_to_endpoint(self, finding_id: str, endpoint_id: str) -> None:
        self._edges.append({"from": finding_id, "to": endpoint_id, "type": "affects"})

    def find_by_cwe(self, cwe: str) -> List[Dict[str, Any]]:
        return [f for f in self._findings.values() if f.get("cwe") == cwe]

    def find_by_endpoint(self, endpoint_id: str) -> List[Dict[str, Any]]:
        return [f for f in self._findings.values() if f.get("affected_endpoint") == endpoint_id]

    def find_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [f for f in self._findings.values() if f.get("severity", "").upper() == severity.upper()]

    def get_evidence_for_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        ev_ids = [e["to"] for e in self._edges if e["from"] == finding_id and e["type"] == "has_evidence"]
        return [self._evidence[eid] for eid in ev_ids if eid in self._evidence]

    def get_attack_paths(self) -> List[List[Dict[str, Any]]]:
        paths = []
        confirmed = [f for f in self._findings.values() if f.get("state") == "confirmed"]
        for finding in confirmed:
            fid = finding.get("finding_id", "")
            evidence = self.get_evidence_for_finding(fid)
            if evidence:
                paths.append([finding] + evidence)
        return paths
