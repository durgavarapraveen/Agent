import json
import time
import logging
from typing import Optional
from core.database import DatabaseManager
from core.schemas import ToolResult

logger = logging.getLogger(__name__)

class ToolResultCache:
    """Avoid re-running identical tool calls using PostgreSQL"""
    
    def __init__(self):
        self._init_db()
    
    def _init_db(self):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS tool_cache (
                        cache_key TEXT PRIMARY KEY,
                        result TEXT NOT NULL,
                        cached_at DOUBLE PRECISION NOT NULL
                    )
                """)
                conn.commit()

    async def get(self, cache_key: str) -> Optional[ToolResult]:
        """Check cache"""
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT result, cached_at FROM tool_cache WHERE cache_key = %s",
                    (cache_key,)
                )
                row = cur.fetchone()
        
        if not row:
            return None
            
        result_json, cached_at = row
        
        # Check expiration (1 hour default)
        age = time.time() - cached_at
        if age > 3600:
            return None
        
        logger.debug(f"Cache HIT for {cache_key}")
        # Parse into ToolResult
        try:
            data = json.loads(result_json)
            return ToolResult(**data)
        except Exception as e:
            logger.error(f"Failed to parse cached ToolResult: {e}")
            return None
    
    async def set(self, cache_key: str, result: ToolResult):
        """Store result in cache"""
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tool_cache (cache_key, result, cached_at) 
                    VALUES (%s, %s, %s) 
                    ON CONFLICT (cache_key) DO UPDATE SET 
                        result = EXCLUDED.result,
                        cached_at = EXCLUDED.cached_at
                    """,
                    (cache_key, result.model_dump_json(), time.time())
                )
                conn.commit()
        logger.debug(f"Cached result for {cache_key}")