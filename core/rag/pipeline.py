"""
SecurityRAGPipeline — the single entry point for the RAG system.
Handles: knowledge seeding, document/URL/search ingestion, embedding,
vector storage in pgvector, retrieval, and LLM context injection.
"""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.memory.database import DatabaseManager
from core.rag.embedder import Embedder
from core.rag.ingestion import (
    chunk_text, content_hash, extract_text_from_file,
    fetch_url_text, search_and_extract,
)
from core.rag.knowledge_seeder import get_all_knowledge

logger = logging.getLogger(__name__)

_pipeline: Optional["SecurityRAGPipeline"] = None


def get_rag() -> Optional["SecurityRAGPipeline"]:
    return _pipeline


class SecurityRAGPipeline:
    """
    Unified RAG pipeline for cybersecurity knowledge.

    Usage:
        rag = SecurityRAGPipeline()
        await rag.initialize()           # creates tables, seeds knowledge
        await rag.ingest_file("cwe.pdf") # add your own docs
        await rag.ingest_url("https://owasp.org/...")
        await rag.search_and_ingest("SSRF bypass techniques 2024")

        # Auto-injected into every DeepSeek call via the harness hook:
        context = await rag.retrieve("SQL injection login bypass", top_k=5)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.embedder = Embedder(api_key=api_key)
        self._initialized = False

    async def initialize(self):
        """Create pgvector tables and seed cybersecurity knowledge."""
        if self._initialized:
            return
        self._init_schema()
        seeded = self._count_documents(source_type="seed")
        if seeded == 0:
            await self._seed_knowledge()
            logger.info("[RAG] Cybersecurity knowledge base seeded")
        else:
            logger.info(f"[RAG] Knowledge base already has {seeded} seed docs, skipping")
        self._initialized = True
        global _pipeline
        _pipeline = self

    def _init_schema(self):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS rag_documents (
                        doc_id TEXT PRIMARY KEY,
                        content TEXT NOT NULL,
                        metadata JSONB DEFAULT '{}',
                        source_type TEXT DEFAULT 'manual',
                        source_ref TEXT DEFAULT '',
                        content_hash TEXT DEFAULT '',
                        embedding vector(1536),
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS rag_documents_hnsw_idx
                    ON rag_documents
                    USING hnsw (embedding vector_cosine_ops)
                    WITH (m = 16, ef_construction = 64)
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS rag_documents_source_idx
                    ON rag_documents (source_type)
                """)
                # Unique index closes the SELECT-then-INSERT race in
                # `_store_chunk`. Two concurrent ingests of the same content
                # would previously both pass the existence check and both
                # INSERT — the unique constraint now serializes them.
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS rag_documents_hash_uidx
                    ON rag_documents (content_hash)
                    WHERE content_hash <> ''
                """)
                conn.commit()
        logger.info("[RAG] Schema initialized")

    def _count_documents(self, source_type: Optional[str] = None) -> int:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    if source_type:
                        cur.execute("SELECT COUNT(*) FROM rag_documents WHERE source_type = %s", (source_type,))
                    else:
                        cur.execute("SELECT COUNT(*) FROM rag_documents")
                    return cur.fetchone()[0]
        except Exception:
            return 0

    async def _seed_knowledge(self):
        """Seed the built-in cybersecurity knowledge corpus."""
        knowledge = get_all_knowledge()
        for entry in knowledge:
            text = f"[{entry['category'].upper()}] {entry['title']}\n\n{entry['content']}"
            await self._store_chunk(
                content=text,
                metadata={"category": entry["category"], "title": entry["title"]},
                source_type="seed",
                source_ref="built_in_knowledge",
            )

    async def _store_chunk(self, content: str, metadata: Dict[str, Any],
                           source_type: str, source_ref: str) -> str:
        """Embed and store a single chunk, deduplicating by content hash.

        Race-safe: relies on the unique index on `content_hash` (see schema).
        We still short-circuit with a fast existence check to avoid running an
        embedding call for content we already have; the actual dedup is
        enforced at INSERT time via `ON CONFLICT (content_hash) DO NOTHING`.
        """
        c_hash = content_hash(content)

        # Fast path: skip if identical content already stored. Race with a
        # concurrent ingest is safe — the ON CONFLICT below is the real gate.
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM rag_documents WHERE content_hash = %s LIMIT 1", (c_hash,))
                    if cur.fetchone():
                        return ""
        except Exception:
            pass

        doc_id = f"rag_{uuid.uuid4().hex[:12]}"
        embedding = await self.embedder.embed(content)

        # Refuse to persist the deterministic hash-bag fallback into the shared
        # vector index — mixing them with real semantic embeddings degrades
        # retrieval for every subsequent query. The embedder marks fallback
        # vectors via `LOCAL_MARKER_VALUE`; the pipeline skips those and logs
        # once so operators know to configure an embedding provider.
        from core.rag.embedder import EmbeddingClient
        if EmbeddingClient.is_local_embedding(embedding):
            if not getattr(self, "_warned_local_embed", False):
                logger.warning(
                    "[RAG] Embedding provider unavailable — refusing to persist "
                    "hash-bag fallback into vector index. Configure EMBEDDING_API_URL / "
                    "EMBEDDING_API_KEY to enable semantic retrieval."
                )
                self._warned_local_embed = True
            return ""

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO rag_documents (doc_id, content, metadata, source_type, source_ref, content_hash, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (content_hash) WHERE content_hash <> '' DO NOTHING
                """, (doc_id, content, json.dumps(metadata), source_type, source_ref, c_hash, embedding))
                conn.commit()
                # If the ON CONFLICT branch fired we didn't insert; report as
                # empty so callers can distinguish new from duplicate.
                return doc_id if cur.rowcount else ""

    # ── Public ingestion methods ──

    async def ingest_file(self, file_path: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Ingest a local file (PDF, txt, md, html, json, csv)."""
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}", "chunks": 0}

        text = extract_text_from_file(file_path)
        if not text.strip():
            return {"error": "No text extracted", "chunks": 0}

        chunks = chunk_text(text)
        stored = 0
        meta = metadata or {}
        meta["filename"] = path.name
        for i, chunk in enumerate(chunks):
            chunk_meta = {**meta, "chunk_index": i, "total_chunks": len(chunks)}
            doc_id = await self._store_chunk(
                content=chunk,
                metadata=chunk_meta,
                source_type="file",
                source_ref=str(path.name),
            )
            if doc_id:
                stored += 1

        logger.info(f"[RAG] Ingested file {path.name}: {stored}/{len(chunks)} new chunks")
        return {"file": path.name, "chunks": len(chunks), "new_chunks": stored}

    async def ingest_text(self, text: str, title: str = "manual",
                          metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Ingest raw text (notes, paste content)."""
        chunks = chunk_text(text)
        stored = 0
        meta = metadata or {}
        meta["title"] = title
        for i, chunk in enumerate(chunks):
            chunk_meta = {**meta, "chunk_index": i}
            doc_id = await self._store_chunk(
                content=chunk,
                metadata=chunk_meta,
                source_type="text",
                source_ref=title,
            )
            if doc_id:
                stored += 1
        return {"title": title, "chunks": len(chunks), "new_chunks": stored}

    async def ingest_url(self, url: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Fetch a URL and ingest its content."""
        try:
            text = await fetch_url_text(url)
        except Exception as e:
            return {"error": str(e), "url": url, "chunks": 0}

        if not text.strip():
            return {"error": "No text extracted from URL", "url": url, "chunks": 0}

        chunks = chunk_text(text)
        stored = 0
        meta = metadata or {}
        meta["url"] = url
        for i, chunk in enumerate(chunks):
            chunk_meta = {**meta, "chunk_index": i}
            doc_id = await self._store_chunk(
                content=chunk,
                metadata=chunk_meta,
                source_type="url",
                source_ref=url,
            )
            if doc_id:
                stored += 1

        logger.info(f"[RAG] Ingested URL {url}: {stored}/{len(chunks)} new chunks")
        return {"url": url, "chunks": len(chunks), "new_chunks": stored}

    async def search_and_ingest(self, query: str, max_results: int = 3) -> Dict[str, Any]:
        """Search the web, fetch results, and ingest them."""
        pages = await search_and_extract(query, max_results=max_results)
        total_chunks = 0
        total_new = 0
        sources = []
        for page in pages:
            if not page.get("text", "").strip():
                continue
            chunks = chunk_text(page["text"])
            stored = 0
            for i, chunk in enumerate(chunks):
                meta = {
                    "url": page.get("url", ""),
                    "title": page.get("title", ""),
                    "search_query": query,
                    "chunk_index": i,
                }
                doc_id = await self._store_chunk(
                    content=chunk,
                    metadata=meta,
                    source_type="web_search",
                    source_ref=page.get("url", query),
                )
                if doc_id:
                    stored += 1
            total_chunks += len(chunks)
            total_new += stored
            sources.append(page.get("url", ""))

        logger.info(f"[RAG] Web search '{query}': {total_new}/{total_chunks} new chunks from {len(sources)} pages")
        return {"query": query, "pages_fetched": len(pages), "chunks": total_chunks,
                "new_chunks": total_new, "sources": sources}

    async def ingest_scan_findings(self, findings: List[Dict[str, Any]], target: str = "") -> int:
        """Ingest anonymized scan findings into the knowledge base for future reference."""
        stored = 0
        for finding in findings:
            title = finding.get("title", "Unknown Finding")
            severity = finding.get("severity", "MEDIUM")
            category = finding.get("category", finding.get("type", "unknown"))
            evidence = finding.get("evidence", finding.get("details", ""))
            location = finding.get("location", finding.get("endpoint", ""))

            text = (
                f"[FINDING] {title}\n"
                f"Severity: {severity} | Category: {category}\n"
                f"Location pattern: {_anonymize_location(location)}\n"
                f"Evidence: {str(evidence)[:500]}\n"
                f"Detection method: automated scanner"
            )
            meta = {
                "category": category,
                "severity": severity,
                "title": title,
                "target_hash": content_hash(target) if target else "",
            }
            doc_id = await self._store_chunk(
                content=text,
                metadata=meta,
                source_type="scan_finding",
                source_ref=f"scan_{content_hash(target)[:8]}",
            )
            if doc_id:
                stored += 1
        return stored

    # ── Retrieval ──

    async def retrieve(self, query: str, top_k: int = 5,
                       category_filter: Optional[str] = None,
                       min_similarity: float = 0.05) -> List[Dict[str, Any]]:
        """Retrieve relevant knowledge chunks for a query."""
        query_embedding = await self.embedder.embed(query)
        results = []
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    if category_filter:
                        cur.execute("""
                            SELECT doc_id, content, metadata,
                                   1 - (embedding <=> %s::vector) AS similarity
                            FROM rag_documents
                            WHERE metadata->>'category' = %s
                            ORDER BY embedding <=> %s::vector
                            LIMIT %s
                        """, (query_embedding, category_filter, query_embedding, top_k))
                    else:
                        cur.execute("""
                            SELECT doc_id, content, metadata,
                                   1 - (embedding <=> %s::vector) AS similarity
                            FROM rag_documents
                            ORDER BY embedding <=> %s::vector
                            LIMIT %s
                        """, (query_embedding, query_embedding, top_k))

                    for row in cur.fetchall():
                        sim = float(row[3])
                        if sim >= min_similarity:
                            results.append({
                                "doc_id": row[0],
                                "content": row[1],
                                "metadata": row[2] if isinstance(row[2], dict) else json.loads(row[2] or "{}"),
                                "similarity": round(sim, 4),
                            })
        except Exception as e:
            logger.error(f"[RAG] Retrieval error: {e}")
        return results

    def build_system_context(self, retrieved_docs: List[Dict[str, Any]],
                             base_system_prompt: Optional[str] = None) -> str:
        """Build an augmented system prompt with retrieved knowledge."""
        if not retrieved_docs:
            return base_system_prompt or ""

        knowledge_block = "\n\n".join(
            f"--- Knowledge (relevance: {doc['similarity']:.0%}) ---\n{doc['content']}"
            for doc in retrieved_docs[:5]
        )

        rag_prefix = (
            "You are a cybersecurity expert assistant with deep knowledge of vulnerability "
            "assessment, penetration testing, and security research. You have access to the "
            "following relevant security knowledge from your knowledge base:\n\n"
            f"{knowledge_block}\n\n"
            "Use this knowledge to inform your analysis and recommendations. "
            "Prioritize techniques and payloads from the knowledge base when relevant.\n\n"
        )

        if base_system_prompt:
            return rag_prefix + base_system_prompt
        return rag_prefix

    # ── Document listing ──

    def list_documents(self, source_type: Optional[str] = None,
                       limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List all documents with content preview."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    if source_type:
                        cur.execute("""
                            SELECT doc_id, content, metadata, source_type, source_ref,
                                   created_at, LENGTH(content) as content_len
                            FROM rag_documents
                            WHERE source_type = %s
                            ORDER BY created_at DESC
                            LIMIT %s OFFSET %s
                        """, (source_type, limit, offset))
                    else:
                        cur.execute("""
                            SELECT doc_id, content, metadata, source_type, source_ref,
                                   created_at, LENGTH(content) as content_len
                            FROM rag_documents
                            ORDER BY created_at DESC
                            LIMIT %s OFFSET %s
                        """, (limit, offset))

                    docs = []
                    for row in cur.fetchall():
                        meta = row[2] if isinstance(row[2], dict) else json.loads(row[2] or "{}")
                        docs.append({
                            "doc_id": row[0],
                            "content": row[1],
                            "content_preview": row[1][:300] if row[1] else "",
                            "metadata": meta,
                            "source_type": row[3],
                            "source_ref": row[4],
                            "created_at": row[5].isoformat() if row[5] else None,
                            "content_length": row[6],
                        })
                    return docs
        except Exception as e:
            logger.error(f"[RAG] List documents error: {e}")
            return []

    # ── Stats ──

    def stats(self) -> Dict[str, Any]:
        """Return RAG knowledge base statistics."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM rag_documents")
                    total = cur.fetchone()[0]
                    cur.execute("""
                        SELECT source_type, COUNT(*)
                        FROM rag_documents
                        GROUP BY source_type
                    """)
                    by_source = {row[0]: row[1] for row in cur.fetchall()}
                    cur.execute("""
                        SELECT metadata->>'category' AS cat, COUNT(*)
                        FROM rag_documents
                        WHERE metadata->>'category' IS NOT NULL
                        GROUP BY cat
                        ORDER BY COUNT(*) DESC
                    """)
                    by_category = {row[0]: row[1] for row in cur.fetchall()}
            return {
                "total_documents": total,
                "by_source": by_source,
                "by_category": by_category,
                "initialized": self._initialized,
            }
        except Exception as e:
            return {"error": str(e), "initialized": self._initialized}

    async def delete_by_source(self, source_type: str, source_ref: Optional[str] = None) -> int:
        """Delete documents by source type/ref."""
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                if source_ref:
                    cur.execute("DELETE FROM rag_documents WHERE source_type=%s AND source_ref=%s",
                                (source_type, source_ref))
                else:
                    cur.execute("DELETE FROM rag_documents WHERE source_type=%s", (source_type,))
                deleted = cur.rowcount
                conn.commit()
        return deleted

    async def close(self):
        await self.embedder.close()


def _anonymize_location(location: str) -> str:
    """Replace specific IDs/tokens in locations with generic patterns."""
    import re
    anon = re.sub(r"/\d+", "/{id}", str(location))
    anon = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                  "{uuid}", anon, flags=re.IGNORECASE)
    return anon
