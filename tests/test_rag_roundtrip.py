from __future__ import annotations

import asyncio
import os

import pytest


def _pg_reachable() -> bool:
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            user=os.getenv("POSTGRES_USER", "ci_user"),
            password=os.getenv("POSTGRES_PASSWORD", "ci_pw"),
            dbname=os.getenv("POSTGRES_DB", "ci_db"),
            connect_timeout=2,
        )
        conn.close()
        return True
    except Exception:
        return False


def _semantic_embedder_available() -> bool:
    if os.getenv("EMBEDDING_API_URL") and os.getenv("EMBEDDING_API_KEY"):
        return True
    try:
        from core.rag.local_embedder import LocalSemanticEmbedder
        return LocalSemanticEmbedder.available()
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(not _pg_reachable(),
                       reason="Postgres not reachable"),
    pytest.mark.skipif(not _semantic_embedder_available(),
                       reason="No embedding provider (API or sentence-transformers)"),
]


def test_rag_ingest_and_retrieve() -> None:
    from core.rag.pipeline import SecurityRAGPipeline

    async def _run() -> None:
        rag = SecurityRAGPipeline()
        await rag.initialize()

        doc = (
            "[TEST-KB-ENTRY] SQL injection via login form on POST /login. "
            "Payload example: username=admin' OR '1'='1 -- and password=anything. "
            "Vulnerable to authentication bypass when input goes into a "
            "concatenated WHERE clause without prepared statements."
        )
        result = await rag.ingest_text(
            doc, title="pytest-smoke-sqli-login",
            source_type="text", source_ref="pytest-smoke",
        )
        assert result.get("new_chunks", 0) >= 1

        # HyDE and rerank are best-effort; disable so this test measures
        # ONLY the round-trip and doesn't require an LLM key.
        docs = await rag.retrieve(
            "authentication bypass SQL injection login",
            top_k=3, use_hyde=False, use_rerank=False,
        )
        assert docs, "retrieve returned no docs"
        assert any("pytest-smoke" in (d.get("metadata", {}) or {}).get("title", "")
                   or "authentication bypass" in (d.get("content") or "").lower()
                   or "SQL injection" in (d.get("content") or "")
                   for d in docs), \
            f"round-trip missed the ingested doc; got {[d.get('doc_id') for d in docs]}"

        # Cleanup so repeat runs don't accumulate.
        await rag.delete_by_source("text", "pytest-smoke")
        await rag.close()

    asyncio.run(_run())
