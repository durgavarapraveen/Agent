import logging
import asyncio
import uuid
import json
from typing import List, Dict, Any

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)

class VectorMemoryWorker:
    """Handles asynchronous batch embedding and PGVector insertions."""
    
    def __init__(self, dimension: int = 1536):
        self.dimension = dimension
        self.queue = asyncio.Queue()
        self.batch_size = 50
        self.flush_interval = 5.0 # seconds
        self._worker_task = None
        self.setup_schema()

    def setup_schema(self):
        """Initializes the pgvector schema and HNSW index."""
        schema_sql = f"""
        CREATE TABLE IF NOT EXISTS memory_embeddings (
            memory_id UUID PRIMARY KEY,
            content TEXT NOT NULL,
            metadata JSONB,
            embedding vector({self.dimension}),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # HNSW Index requires vector extension and specifies operators (cosine distance: vector_cosine_ops)
        index_sql = """
        CREATE INDEX IF NOT EXISTS memory_embeddings_hnsw_idx 
        ON memory_embeddings 
        USING hnsw (embedding vector_cosine_ops) 
        WITH (m = 16, ef_construction = 64);
        """
        
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(schema_sql)
                cur.execute(index_sql)
                conn.commit()
        logger.info(f"Vector memory schema initialized (HNSW index, dim={self.dimension})")

    async def start(self):
        """Start the background worker."""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker_loop())
            logger.info("Vector memory background worker started")

    async def stop(self):
        """Stop the background worker."""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
            logger.info("Vector memory background worker stopped")

    async def add_memory(self, content: str, metadata: Dict[str, Any] = None):
        """Queue a memory for embedding and storage."""
        await self.queue.put({
            "memory_id": str(uuid.uuid4()),
            "content": content,
            "metadata": metadata or {}
        })

    async def _worker_loop(self):
        """Background loop to process batches."""
        while True:
            batch = []
            try:
                # Wait for at least one item
                item = await self.queue.get()
                batch.append(item)
                
                # Try to fill the batch up to batch_size within flush_interval
                end_time = asyncio.get_event_loop().time() + self.flush_interval
                while len(batch) < self.batch_size:
                    timeout = end_time - asyncio.get_event_loop().time()
                    if timeout <= 0:
                        break
                    try:
                        item = await asyncio.wait_for(self.queue.get(), timeout)
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break
                
                if batch:
                    await self._process_batch(batch)
                    
                for _ in batch:
                    self.queue.task_done()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in vector memory worker loop: {e}")
                await asyncio.sleep(5) # backoff

    async def _process_batch(self, batch: List[Dict[str, Any]]):
        """Fetch embeddings and store in pgvector."""
        start_time = asyncio.get_event_loop().time()
        contents = [item["content"] for item in batch]
        
        try:
            # TODO: Integrate real embedding client here (e.g. OpenAI)
            # MOCK EMBEDDINGS for now
            import random
            vectors = [[random.random() for _ in range(self.dimension)] for _ in contents]
            
            # Bulk insert
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    for item, vector in zip(batch, vectors):
                        cur.execute(
                            '''
                            INSERT INTO memory_embeddings (memory_id, content, metadata, embedding)
                            VALUES (%s, %s, %s, %s)
                            ''',
                            (item["memory_id"], item["content"], json.dumps(item["metadata"]), vector)
                        )
                    conn.commit()
            
            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            logger.info(f"[METRIC] batch_embedding_insert_ms: {duration_ms:.2f}ms | size: {len(batch)}")
            
        except Exception as e:
            logger.error(f"[METRIC] batch_embedding_error: {e}")

    def similarity_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Find similar memories using HNSW cosine distance (<=>)."""
        import time
        start_time = time.time()
        
        # TODO: Get real embedding for the query
        import random
        query_vector = [random.random() for _ in range(self.dimension)]
        
        results = []
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        '''
                        SELECT memory_id, content, metadata, 1 - (embedding <=> %s::vector) as similarity
                        FROM memory_embeddings
                        ORDER BY embedding <=> %s::vector
                        LIMIT %s
                        ''',
                        (query_vector, query_vector, top_k)
                    )
                    for row in cur.fetchall():
                        results.append({
                            "memory_id": row[0],
                            "content": row[1],
                            "metadata": row[2],
                            "similarity": row[3]
                        })
                        
            duration_ms = (time.time() - start_time) * 1000
            logger.info(f"[METRIC] pg_similarity_search_ms: {duration_ms:.2f}ms | results: {len(results)}")
        except Exception as e:
            logger.error(f"[METRIC] pg_similarity_search_error: {e}")
            
        return results

# Singleton access
vector_memory = VectorMemoryWorker()
