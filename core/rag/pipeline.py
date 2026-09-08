"""
SecurityRAGPipeline — the single entry point for the RAG system.

Handles: knowledge seeding, document/URL/search ingestion, embedding,
vector storage in pgvector, retrieval, re-ranking, HyDE query rewriting,
parent-child chunk retrieval, and LLM context injection.

Upgrades wired in this file:
  1. Two-stage retrieval + cross-encoder re-rank (core/rag/reranker.py)
  2. True semantic local embeddings via MiniLM (core/rag/local_embedder.py)
  3. Semantic dedup on ingest (cosine sim >= SEMANTIC_DUP_THRESHOLD)
  4. HyDE query transformation (core/rag/hyde.py)
  5. Parent-child chunks: small children indexed, big parents returned
"""

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.memory.database import DatabaseManager
from core.rag.embedder import DIMENSION, Embedder, EmbedResult
from core.rag.hyde import transform_query as hyde_transform
from core.rag.ingestion import (
    chunk_parent_child, chunk_text, content_hash, extract_text_from_file,
    fetch_url_text, search_and_extract,
)
from core.rag.knowledge_seeder import get_all_knowledge
from core.rag.local_embedder import LOCAL_DIMENSION
from core.rag.reranker import get_reranker

logger = logging.getLogger(__name__)

# A candidate whose cosine sim vs. an existing row is above this threshold
# is treated as a semantic duplicate and NOT stored — keeps the top_k slots
# in the LLM prompt diverse instead of returning 5 near-copies.
SEMANTIC_DUP_THRESHOLD = float(os.getenv("RAG_SEMANTIC_DUP", "0.98"))

# Stage-1 fan-out: how many candidates pgvector returns before the reranker
# whittles them down to the caller's top_k. 4x is a solid default.
RERANK_FANOUT = int(os.getenv("RAG_RERANK_FANOUT", "20"))

_pipeline: Optional["SecurityRAGPipeline"] = None


def get_rag() -> Optional["SecurityRAGPipeline"]:
    return _pipeline


class SecurityRAGPipeline:
    """
    Unified RAG pipeline for cybersecurity knowledge.

    Usage:
        rag = SecurityRAGPipeline()
        await rag.initialize()
        await rag.ingest_file("cwe.pdf")
        docs = await rag.retrieve("SQL injection login bypass", top_k=5)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.embedder = Embedder(api_key=api_key)
        self.reranker = get_reranker()
        self._initialized = False
        self._warned_hash = False

    async def initialize(self):
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

    # ── Schema ─────────────────────────────────────────────────────────

    def _init_schema(self):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                # RAG needs pgvector. Try to create it; if the server can't
                # (no superuser or missing extension package) fail loudly
                # with a clear message instead of a cryptic CREATE TABLE error.
                try:
                    cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
                    conn.commit()
                except Exception as e:
                    raise RuntimeError(
                        "pgvector extension unavailable on this Postgres server. "
                        "Use the `pgvector/pgvector:pg15` image or `apt install "
                        "postgresql-15-pgvector`, then re-run."
                    ) from e
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS rag_documents (
                        doc_id TEXT PRIMARY KEY,
                        content TEXT NOT NULL,
                        parent_id TEXT DEFAULT '',
                        parent_content TEXT DEFAULT '',
                        metadata JSONB DEFAULT '{{}}',
                        source_type TEXT DEFAULT 'manual',
                        source_ref TEXT DEFAULT '',
                        content_hash TEXT DEFAULT '',
                        embedding vector({DIMENSION}),
                        embedding_local vector({LOCAL_DIMENSION}),
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                # Additive migration for pre-existing installs.
                for stmt in (
                    "ALTER TABLE rag_documents ADD COLUMN IF NOT EXISTS parent_id TEXT DEFAULT ''",
                    "ALTER TABLE rag_documents ADD COLUMN IF NOT EXISTS parent_content TEXT DEFAULT ''",
                    f"ALTER TABLE rag_documents ADD COLUMN IF NOT EXISTS embedding_local vector({LOCAL_DIMENSION})",
                ):
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        logger.debug(f"[RAG] schema migration note: {e}")

                cur.execute("""
                    CREATE INDEX IF NOT EXISTS rag_documents_hnsw_idx
                    ON rag_documents
                    USING hnsw (embedding vector_cosine_ops)
                    WITH (m = 16, ef_construction = 64)
                """)
                # Local (MiniLM) index — separate space, separate column.
                try:
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS rag_documents_hnsw_local_idx
                        ON rag_documents
                        USING hnsw (embedding_local vector_cosine_ops)
                        WITH (m = 16, ef_construction = 64)
                    """)
                except Exception as e:
                    logger.debug(f"[RAG] local hnsw index note: {e}")

                cur.execute("""
                    CREATE INDEX IF NOT EXISTS rag_documents_source_idx
                    ON rag_documents (source_type)
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS rag_documents_parent_idx
                    ON rag_documents (parent_id)
                """)
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
        knowledge = get_all_knowledge()
        for entry in knowledge:
            text = f"[{entry['category'].upper()}] {entry['title']}\n\n{entry['content']}"
            await self.ingest_text(text, title=entry["title"],
                                   metadata={"category": entry["category"], "title": entry["title"]},
                                   source_type="seed", source_ref="built_in_knowledge")

    # ── Ingest: parent-child chunks ────────────────────────────────────

    async def _store_chunk(self, content: str, metadata: Dict[str, Any],
                            source_type: str, source_ref: str,
                            parent_id: str = "", parent_content: str = "") -> str:
        """Embed one child chunk, dedup (exact + semantic), then insert.

        Never persists a hash-bag fallback vector — the row would poison the
        HNSW index. Semantic dup: if any existing row has cosine sim >=
        SEMANTIC_DUP_THRESHOLD to this chunk in the same embedding space, we
        skip. Ensures diverse top_k results.
        """
        c_hash = content_hash(content)

        # Exact-text dedup (cheap; embedding-free).
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM rag_documents WHERE content_hash = %s LIMIT 1", (c_hash,))
                    if cur.fetchone():
                        return ""
        except Exception:
            pass

        emb = await self.embedder.embed(content)

        if emb.is_hash:
            if not self._warned_hash:
                logger.warning(
                    "[RAG] Neither embedding API nor sentence-transformers is "
                    "available — refusing to persist hash-bag vectors. Install "
                    "'sentence-transformers' or set EMBEDDING_API_URL/KEY."
                )
                self._warned_hash = True
            return ""

        # Semantic dedup: is this content nearly identical to something we
        # already have in the same embedding space?
        if await self._is_semantic_duplicate(emb):
            return ""

        doc_id = f"rag_{uuid.uuid4().hex[:12]}"
        emb_full = emb.vector if emb.dim == DIMENSION else None
        emb_local = emb.vector if emb.dim == LOCAL_DIMENSION else None

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO rag_documents
                        (doc_id, content, parent_id, parent_content, metadata,
                         source_type, source_ref, content_hash,
                         embedding, embedding_local)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (content_hash) WHERE content_hash <> '' DO NOTHING
                """, (doc_id, content, parent_id, parent_content,
                      json.dumps(metadata), source_type, source_ref, c_hash,
                      emb_full, emb_local))
                conn.commit()
                return doc_id if cur.rowcount else ""

    async def _is_semantic_duplicate(self, emb: EmbedResult) -> bool:
        """Query the appropriate vector column for near-duplicates.

        Never fatal — a failed dedup check just falls through to insert.
        """
        try:
            col = "embedding" if emb.dim == DIMENSION else "embedding_local"
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(f"""
                        SELECT 1 - ({col} <=> %s::vector) AS sim
                        FROM rag_documents
                        WHERE {col} IS NOT NULL
                        ORDER BY {col} <=> %s::vector
                        LIMIT 1
                    """, (emb.vector, emb.vector))
                    row = cur.fetchone()
                    if row and float(row[0]) >= SEMANTIC_DUP_THRESHOLD:
                        return True
        except Exception as e:
            logger.debug(f"[RAG] semantic dedup check skipped: {e}")
        return False

    async def _ingest_parent_child(self, text: str, source_type: str,
                                     source_ref: str, base_meta: Dict[str, Any]) -> int:
        """Split into parent/child, store every child pointing at its parent."""
        pieces = chunk_parent_child(text)
        stored = 0
        # Assign a stable parent_id per unique parent within this ingest so
        # the parent-content dedup at retrieval time is O(1).
        parent_ids: Dict[int, str] = {}
        for piece in pieces:
            pi = piece["parent_idx"]
            if pi not in parent_ids:
                parent_ids[pi] = f"par_{uuid.uuid4().hex[:12]}"
            meta = {**base_meta,
                    "parent_idx": pi,
                    "child_idx": piece["child_idx"]}
            doc_id = await self._store_chunk(
                content=piece["content"],
                metadata=meta,
                source_type=source_type,
                source_ref=source_ref,
                parent_id=parent_ids[pi],
                parent_content=piece["parent_content"],
            )
            if doc_id:
                stored += 1
        return stored

    # ── Public ingestion methods ──────────────────────────────────────

    async def ingest_file(self, file_path: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}", "chunks": 0}
        text = extract_text_from_file(file_path)
        if not text.strip():
            return {"error": "No text extracted", "chunks": 0}
        meta = {**(metadata or {}), "filename": path.name}
        stored = await self._ingest_parent_child(text, "file", str(path.name), meta)
        logger.info(f"[RAG] Ingested file {path.name}: {stored} new child chunks")
        return {"file": path.name, "new_chunks": stored}

    async def ingest_text(self, text: str, title: str = "manual",
                          metadata: Optional[Dict] = None,
                          source_type: str = "text",
                          source_ref: str = "") -> Dict[str, Any]:
        meta = {**(metadata or {}), "title": title}
        ref = source_ref or title
        stored = await self._ingest_parent_child(text, source_type, ref, meta)
        return {"title": title, "new_chunks": stored}

    async def ingest_url(self, url: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        try:
            text = await fetch_url_text(url)
        except Exception as e:
            return {"error": str(e), "url": url, "chunks": 0}
        if not text.strip():
            return {"error": "No text extracted from URL", "url": url, "chunks": 0}
        meta = {**(metadata or {}), "url": url}
        stored = await self._ingest_parent_child(text, "url", url, meta)
        logger.info(f"[RAG] Ingested URL {url}: {stored} new child chunks")
        return {"url": url, "new_chunks": stored}

    async def search_and_ingest(self, query: str, max_results: int = 3) -> Dict[str, Any]:
        pages = await search_and_extract(query, max_results=max_results)
        total_new = 0
        sources = []
        for page in pages:
            if not page.get("text", "").strip():
                continue
            meta = {"url": page.get("url", ""), "title": page.get("title", ""),
                    "search_query": query}
            n = await self._ingest_parent_child(page["text"], "web_search",
                                                  page.get("url", query), meta)
            total_new += n
            sources.append(page.get("url", ""))
        logger.info(f"[RAG] Web search '{query}': {total_new} new chunks from {len(sources)} pages")
        return {"query": query, "pages_fetched": len(pages),
                "new_chunks": total_new, "sources": sources}

    async def ingest_scan_findings(self, findings: List[Dict[str, Any]], target: str = "") -> int:
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
            meta = {"category": category, "severity": severity, "title": title,
                    "target_hash": content_hash(target) if target else ""}
            n = await self._ingest_parent_child(
                text, "scan_finding",
                f"scan_{content_hash(target)[:8]}" if target else "scan",
                meta,
            )
            stored += n
        return stored

    # ── Retrieval: HyDE + vector search + rerank + parent collapse ─────

    async def retrieve(self, query: str, top_k: int = 5,
                       category_filter: Optional[str] = None,
                       min_similarity: float = 0.05,
                       use_hyde: bool = True,
                       use_rerank: bool = True) -> List[Dict[str, Any]]:
        """Retrieve relevant knowledge chunks for a query.

        Pipeline:
          1. HyDE — rewrite query as a hypothetical answer (optional)
          2. Embed the rewritten query
          3. pgvector top-N (fan-out = RERANK_FANOUT) in the matching space
          4. Collapse to unique parents (keep best-scoring child per parent)
          5. Cross-encoder rerank to top_k
        """
        search_text = query
        if use_hyde:
            try:
                search_text = await hyde_transform(query)
            except Exception as e:
                logger.debug(f"[RAG] HyDE skipped: {e}")

        qemb = await self.embedder.embed(search_text)
        if qemb.is_hash:
            # Hash-space queries are useless — fall through with empty results.
            return []

        fanout = max(top_k, RERANK_FANOUT) if use_rerank else top_k
        col = "embedding" if qemb.dim == DIMENSION else "embedding_local"

        raw = []
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    if category_filter:
                        cur.execute(f"""
                            SELECT doc_id, content, parent_id, parent_content, metadata,
                                   1 - ({col} <=> %s::vector) AS similarity
                            FROM rag_documents
                            WHERE {col} IS NOT NULL
                              AND metadata->>'category' = %s
                            ORDER BY {col} <=> %s::vector
                            LIMIT %s
                        """, (qemb.vector, category_filter, qemb.vector, fanout))
                    else:
                        cur.execute(f"""
                            SELECT doc_id, content, parent_id, parent_content, metadata,
                                   1 - ({col} <=> %s::vector) AS similarity
                            FROM rag_documents
                            WHERE {col} IS NOT NULL
                            ORDER BY {col} <=> %s::vector
                            LIMIT %s
                        """, (qemb.vector, qemb.vector, fanout))

                    for row in cur.fetchall():
                        sim = float(row[5])
                        if sim < min_similarity:
                            continue
                        meta = row[4] if isinstance(row[4], dict) else json.loads(row[4] or "{}")
                        raw.append({
                            "doc_id": row[0],
                            "content": row[1],
                            "parent_id": row[2] or "",
                            "parent_content": row[3] or "",
                            "metadata": meta,
                            "similarity": round(sim, 4),
                        })
        except Exception as e:
            logger.error(f"[RAG] Retrieval error: {e}")
            return []

        # Collapse to unique parents — keep the best-scoring child per parent
        # so we return diverse parents instead of many children of one doc.
        collapsed = self._collapse_by_parent(raw)

        if use_rerank and len(collapsed) > top_k:
            try:
                # Rerank on the PARENT content (bigger, richer signal) but
                # keep child scoring metadata for observability.
                for d in collapsed:
                    d["_child_content"] = d["content"]
                    if d.get("parent_content"):
                        d["content"] = d["parent_content"]
                collapsed = await self.reranker.rerank(query, collapsed, top_k=top_k)
            except Exception as e:
                logger.debug(f"[RAG] rerank skipped: {e}")
                collapsed = collapsed[:top_k]
        else:
            collapsed = collapsed[:top_k]
            # Still promote parent_content if available so LLM sees full context.
            for d in collapsed:
                if d.get("parent_content"):
                    d["_child_content"] = d["content"]
                    d["content"] = d["parent_content"]

        return collapsed

    def _collapse_by_parent(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep the single highest-scoring child per parent_id (or per doc_id
        for rows with no parent), preserving retrieval order among the winners."""
        best: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            key = r.get("parent_id") or r.get("doc_id")
            cur = best.get(key)
            if cur is None or r["similarity"] > cur["similarity"]:
                best[key] = r
        return sorted(best.values(), key=lambda r: r["similarity"], reverse=True)

    def build_system_context(self, retrieved_docs: List[Dict[str, Any]],
                              base_system_prompt: Optional[str] = None) -> str:
        if not retrieved_docs:
            return base_system_prompt or ""

        def _score(d):
            return d.get("rerank_score", d.get("similarity", 0.0))

        knowledge_block = "\n\n".join(
            f"--- Knowledge (score: {_score(doc):.3f}) ---\n{doc['content']}"
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

    # ── Document listing ──────────────────────────────────────────────

    def list_documents(self, source_type: Optional[str] = None,
                       limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
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

    # ── Stats ──────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM rag_documents")
                    total = cur.fetchone()[0]
                    cur.execute("SELECT source_type, COUNT(*) FROM rag_documents GROUP BY source_type")
                    by_source = {row[0]: row[1] for row in cur.fetchall()}
                    cur.execute("""
                        SELECT metadata->>'category' AS cat, COUNT(*)
                        FROM rag_documents
                        WHERE metadata->>'category' IS NOT NULL
                        GROUP BY cat
                        ORDER BY COUNT(*) DESC
                    """)
                    by_category = {row[0]: row[1] for row in cur.fetchall()}
                    cur.execute("SELECT COUNT(*) FROM rag_documents WHERE embedding IS NOT NULL")
                    api_vecs = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM rag_documents WHERE embedding_local IS NOT NULL")
                    local_vecs = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(DISTINCT parent_id) FROM rag_documents WHERE parent_id <> ''")
                    parents = cur.fetchone()[0]
            return {
                "total_documents": total,
                "unique_parents": parents,
                "vectors_api": api_vecs,
                "vectors_local_semantic": local_vecs,
                "by_source": by_source,
                "by_category": by_category,
                "initialized": self._initialized,
                "semantic_dup_threshold": SEMANTIC_DUP_THRESHOLD,
                "rerank_fanout": RERANK_FANOUT,
            }
        except Exception as e:
            return {"error": str(e), "initialized": self._initialized}

    async def delete_by_source(self, source_type: str, source_ref: Optional[str] = None) -> int:
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
    import re
    anon = re.sub(r"/\d+", "/{id}", str(location))
    anon = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                  "{uuid}", anon, flags=re.IGNORECASE)
    return anon
