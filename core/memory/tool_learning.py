from typing import Dict, List
from pydantic import BaseModel, Field
from datetime import datetime

class ToolScore(BaseModel):
    tool_name: str
    global_success_rate: float = 0.5
    target_success_rate: float = 0.5
    target_type_success_rate: float = 0.5
    recent_success_rate: float = 0.5
    average_cost: float = 1.0
    average_duration: float = 1.0
    evidence_quality: float = 1.0
    failure_history: List[str] = Field(default_factory=list)
    last_used: datetime = Field(default_factory=datetime.utcnow)

class ToolLearningEngine:
    def __init__(self):
        self.tool_scores: Dict[str, ToolScore] = {}
        # Pre-seed some default tools
        self.tool_scores["nuclei"] = ToolScore(tool_name="nuclei", global_success_rate=0.87, target_success_rate=0.62)
        self.tool_scores["dalfox"] = ToolScore(tool_name="dalfox", global_success_rate=0.85, target_success_rate=0.7)
        self.tool_scores["sqlmap"] = ToolScore(tool_name="sqlmap", global_success_rate=0.90, target_success_rate=0.8)
        
    def calculate_effective_score(self, tool_name: str, target_type: str = "web") -> float:
        score = self.tool_scores.get(tool_name)
        if not score:
            return 0.0
            
        # (target_type_success_rate * 0.5 + recent_success_rate * 0.3 + global_success_rate * 0.2) * evidence_quality / average_cost
        effective = (
            (score.target_type_success_rate * 0.5 +
             score.recent_success_rate * 0.3 +
             score.global_success_rate * 0.2) *
            score.evidence_quality /
            (score.average_cost if score.average_cost > 0 else 1.0)
        )
        return round(effective, 2)
        
    def get_top_tools(self, test_type: str) -> Dict[str, float]:
        # Simple heuristic mapping
        mapping = {
            "xss": ["dalfox", "nuclei"],
            "sql_injection": ["sqlmap", "nuclei"]
        }
        relevant = mapping.get(test_type.split(".")[0], list(self.tool_scores.keys()))
        
        results = {}
        for t in relevant:
            if t in self.tool_scores:
                results[t] = self.calculate_effective_score(t)
                
        # Sort desc
        return dict(sorted(results.items(), key=lambda item: item[1], reverse=True))
