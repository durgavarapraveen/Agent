from __future__ import annotations

from typing import Any, Dict, List, Optional
import time

class KnowledgeGraph:

    def __init__(self) -> None:
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._evidence: Dict[str, Dict[str, Any]] = {}
        self._endpoints: Dict[str, Dict[str, Any]] = {}
        self._identities: Dict[str, Dict[str, Any]] = {}
        self._assets: Dict[str, Dict[str, Any]] = {}
        self._interfaces: Dict[str, Dict[str, Any]] = {}
        self._resources: Dict[str, Dict[str, Any]] = {}
        self._roles: Dict[str, Dict[str, Any]] = {}
        self._workflows: Dict[str, Dict[str, Any]] = {}
        self._observations: Dict[str, Dict[str, Any]] = {}
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

    def add_asset(self, asset_id: str, data: Dict[str, Any]) -> None:
        self._assets[asset_id] = data
        
    def add_interface(self, interface_id: str, protocol: str, data: Dict[str, Any]) -> None:
        data['protocol'] = protocol
        self._interfaces[interface_id] = data

    def add_resource(self, resource_id: str, data: Dict[str, Any]) -> None:
        self._resources[resource_id] = data

    def add_role(self, role_id: str, data: Dict[str, Any]) -> None:
        self._roles[role_id] = data

    def add_workflow(self, workflow_id: str, data: Dict[str, Any]) -> None:
        self._workflows[workflow_id] = data

    def add_observation(self, observation_id: str, data: Dict[str, Any]) -> None:
        self._observations[observation_id] = data

    def merge_artifact(self, protocol: str, artifact: Dict[str, Any]) -> None:
        """Merge multi-protocol artifacts (HTML, REST, GraphQL, WebSocket, etc.)."""
        # Determine the type of artifact and merge it appropriately
        if protocol in ["REST", "GraphQL", "SOAP", "RPC"]:
            for endpoint in artifact.get("endpoints", []):
                self.add_endpoint(endpoint)
                # Link endpoint to interface
                interface_id = f"interface_{protocol.lower()}"
                if interface_id not in self._interfaces:
                    self.add_interface(interface_id, protocol, {})
                self.add_edge(interface_id, endpoint.get("endpoint_id", endpoint.get("url", "")), "exposes")
        elif protocol == "HTML":
            for asset in artifact.get("assets", []):
                self.add_asset(asset.get("asset_id", ""), asset)

    def add_edge(self, from_node: str, to_node: str, edge_type: str) -> None:
        self._edges.append({"from": from_node, "to": to_node, "type": edge_type})

    def connect_evidence(self, finding_id: str, evidence_id: str) -> None:
        self.add_edge(finding_id, evidence_id, "has_evidence")

    def connect_finding_to_endpoint(self, finding_id: str, endpoint_id: str) -> None:
        self.add_edge(finding_id, endpoint_id, "affects")

    def track_lineage(self, observation_id: str, test_id: str, finding_id: str) -> None:
        """Track lineage from observation to test to finding."""
        self.add_edge(observation_id, test_id, "led_to_test")
        self.add_edge(test_id, finding_id, "produced_finding")

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
