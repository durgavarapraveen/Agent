import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ToolHealth:
    """Track tool reliability (used by ToolRouter for scoring)"""
    
    def __init__(self, db_path="data/db/tool_health.db"):
        self.db = self._init_db(db_path)
    
    async def get_score(self, tool_id: str, target_type: str = "generic") -> float:
        """
        0.0-1.0 score based on:
        - Success rate (70%)
        - Speed (20%)
        - False positive rate (10%)
        """
        
        stats = self.db.query_one("""
            SELECT 
                COUNT(*) as total_runs,
                SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes,
                AVG(time_sec) as avg_time,
                SUM(false_positives) as total_fps
            FROM tool_health
            WHERE tool_id = ? AND target_type = ?
            AND timestamp > ?
        """, (tool_id, target_type, datetime.now() - timedelta(days=30)))
        
        if not stats or stats.total_runs == 0:
            return 0.5  # Default medium score
        
        success_rate = stats.successes / stats.total_runs
        speed_score = max(0, 1 - (stats.avg_time / 300))  # 300s baseline
        fp_score = 1 - (stats.total_fps / max(1, stats.total_runs))
        
        score = success_rate * 0.7 + speed_score * 0.2 + fp_score * 0.1
        return min(1.0, score)
    
    async def record_execution(self, tool_id: str, target_type: str,
                              success: bool, time_sec: float, fp_count: int = 0):
        """After tool runs, record stats"""
        self.db.execute("""
            INSERT INTO tool_health (tool_id, target_type, success, time_sec, false_positives, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tool_id, target_type, success, time_sec, fp_count, datetime.now()))
