"""
Evidence and Knowledge stores - shared memory for observations.
Single source of truth for discovered information.
"""

import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from core.schemas import Evidence, KnowledgeItem, Finding

logger = logging.getLogger(__name__)


class EvidenceStore:
    """Immutable store of raw tool output"""
    
    def __init__(self):
        self.evidence: Dict[str, Evidence] = {}
    
    def store(self, evidence: Evidence) -> str:
        """Store evidence and return ID"""
        evidence_id = evidence.evidence_id
        self.evidence[evidence_id] = evidence
        logger.info(f"[EvidenceStore] Stored evidence: {evidence_id} from {evidence.source}")
        return evidence_id
    
    def get(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence by ID"""
        return self.evidence.get(evidence_id)
    
    def get_by_source(self, source: str) -> List[Evidence]:
        """Get all evidence from a source"""
        return [e for e in self.evidence.values() if e.source == source]
    
    def get_by_task(self, task_id: str) -> List[Evidence]:
        """Get all evidence from a task"""
        return [e for e in self.evidence.values() if e.task_id == task_id]
    
    def to_dict(self) -> Dict:
        """Serialize evidence store"""
        return {
            eid: {
                "source": e.source,
                "agent_id": e.agent_id,
                "task_id": e.task_id,
                "timestamp": e.timestamp.isoformat(),
                "confidence": e.confidence,
            }
            for eid, e in self.evidence.items()
        }


class KnowledgeStore:
    """Structured knowledge with versioning and relationships"""
    
    def __init__(self):
        self.knowledge: Dict[str, KnowledgeItem] = {}
        self.indexes: Dict[str, Set[str]] = {
            # entity_type -> set of knowledge_ids
            "by_type": {},
            # entity_value -> set of knowledge_ids (for dedup)
            "by_value": {},
        }
    
    def store(self, item: KnowledgeItem) -> str:
        """Store knowledge item"""
        knowledge_id = item.knowledge_id
        self.knowledge[knowledge_id] = item
        
        # Update indexes
        entity_type = item.entity_type
        if entity_type not in self.indexes["by_type"]:
            self.indexes["by_type"][entity_type] = set()
        self.indexes["by_type"][entity_type].add(knowledge_id)
        
        key = f"{entity_type}:{item.entity_value}"
        if key not in self.indexes["by_value"]:
            self.indexes["by_value"][key] = set()
        self.indexes["by_value"][key].add(knowledge_id)
        
        logger.info(f"[KnowledgeStore] Stored: {entity_type}={item.entity_value}")
        return knowledge_id
    
    def get(self, knowledge_id: str) -> Optional[KnowledgeItem]:
        """Retrieve knowledge by ID"""
        return self.knowledge.get(knowledge_id)
    
    def get_by_entity(self, entity_type: str, entity_value: str) -> List[KnowledgeItem]:
        """Get all knowledge for an entity"""
        key = f"{entity_type}:{entity_value}"
        ids = self.indexes["by_value"].get(key, set())
        return [self.knowledge[kid] for kid in ids if kid in self.knowledge]
    
    def get_by_type(self, entity_type: str) -> List[KnowledgeItem]:
        """Get all knowledge of a type"""
        ids = self.indexes["by_type"].get(entity_type, set())
        return [self.knowledge[kid] for kid in ids if kid in self.knowledge]
    
    def entity_exists(self, entity_type: str, entity_value: str) -> bool:
        """Check if entity already known"""
        key = f"{entity_type}:{entity_value}"
        return len(self.indexes["by_value"].get(key, set())) > 0
    
    def store_batch(self, items: List[KnowledgeItem]) -> List[str]:
        """Store multiple knowledge items"""
        stored = []
        for item in items:
            # Check for duplicates
            existing = self.get_by_entity(item.entity_type, item.entity_value)
            if existing:
                # Update existing with new evidence
                logger.info(f"[KnowledgeStore] Updating existing: {item.entity_type}={item.entity_value}")
                for e in existing:
                    if item.evidence_id not in e.related_knowledge:
                        e.related_knowledge.append(item.evidence_id)
                stored.append(existing[0].knowledge_id)
            else:
                stored.append(self.store(item))
        
        return stored
    
    def summarize(self) -> Dict[str, int]:
        """Summary of stored knowledge"""
        summary = {}
        for entity_type in self.indexes["by_type"]:
            summary[entity_type] = len(self.indexes["by_type"][entity_type])
        return summary
    
    def to_dict(self) -> Dict:
        """Serialize knowledge store"""
        return {
            "summary": self.summarize(),
            "items": {
                kid: {
                    "entity_type": item.entity_type,
                    "entity_value": item.entity_value,
                    "confidence": item.confidence,
                    "source": item.source,
                }
                for kid, item in self.knowledge.items()
            }
        }


class FindingStore:
    """Store security findings"""
    
    def __init__(self):
        self.findings: Dict[str, Finding] = {}
    
    def store(self, finding: Finding) -> str:
        """Store finding"""
        finding_id = finding.finding_id
        self.findings[finding_id] = finding
        logger.info(f"[FindingStore] Stored: {finding.title} ({finding.severity.value})")
        return finding_id
    
    def get(self, finding_id: str) -> Optional[Finding]:
        """Retrieve finding"""
        return self.findings.get(finding_id)
    
    def get_all(self) -> List[Finding]:
        """Get all findings"""
        return list(self.findings.values())
    
    def get_by_severity(self, severity: str) -> List[Finding]:
        """Get findings by severity"""
        return [f for f in self.findings.values() if f.severity == severity]
    
    def get_confirmed(self) -> List[Finding]:
        """Get confirmed findings only"""
        return [f for f in self.findings.values() if f.status == "CONFIRMED"]
    
    def update_status(self, finding_id: str, new_status: str) -> None:
        """Update finding status"""
        if finding_id in self.findings:
            self.findings[finding_id].status = new_status
            self.findings[finding_id].updated_at = datetime.now()
    
    def summarize(self) -> Dict:
        """Summary of findings"""
        return {
            "total": len(self.findings),
            "by_severity": {
                severity: len(self.get_by_severity(severity))
                for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "confirmed": len(self.get_confirmed()),
        }
    
    def to_dict(self) -> Dict:
        """Serialize findings"""
        return {
            fid: {
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "confidence": f.confidence,
            }
            for fid, f in self.findings.items()
        }