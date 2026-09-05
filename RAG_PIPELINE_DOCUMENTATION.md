# RAG Pipeline — Complete Technical Documentation

> Retrieval-Augmented Generation (RAG) system for the AntiGravity Autonomous Pentesting Agent.
> This document covers every technique, algorithm, data flow, and integration point in detail.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [What is RAG and Why We Use It](#2-what-is-rag-and-why-we-use-it)
3. [File Structure](#3-file-structure)
4. [Database Layer — pgvector](#4-database-layer--pgvector)
5. [Embedding System](#5-embedding-system)
6. [Document Ingestion Pipeline](#6-document-ingestion-pipeline)
7. [Text Chunking Strategy](#7-text-chunking-strategy)
8. [Content Deduplication](#8-content-deduplication)
9. [Knowledge Seeder](#9-knowledge-seeder)
10. [Web Search Integration](#10-web-search-integration)
11. [Retrieval — Vector Similarity Search](#11-retrieval--vector-similarity-search)
12. [LLM Context Injection](#12-llm-context-injection)
13. [Scan Finding Ingestion](#13-scan-finding-ingestion)
14. [REST API Endpoints](#14-rest-api-endpoints)
15. [Frontend UI — Knowledge Base Page](#15-frontend-ui--knowledge-base-page)
16. [Data Flow Diagrams](#16-data-flow-diagrams)
17. [Configuration and Environment](#17-configuration-and-environment)
18. [Dependencies](#18-dependencies)
19. [Known Limitations and Future Work](#19-known-limitations-and-future-work)

---

## 1. Architecture Overview

The RAG pipeline augments every DeepSeek LLM call with relevant cybersecurity knowledge retrieved from a PostgreSQL vector database. Instead of fine-tuning the model (expensive, static), we inject retrieved context into the system prompt at inference time (cheap, dynamic).

```
User uploads file/URL/notes
        │
        ▼
┌─────────────────────┐
│  Ingestion Pipeline  │  Extract text → Chunk → Deduplicate → Embed → Store
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  PostgreSQL + pgvec  │  rag_documents table with vector(1536) column
│  HNSW Index          │  Approximate nearest neighbor search
└────────┬────────────┘
         │
         ▼ (at query time)
┌─────────────────────┐
│  Retrieval Engine    │  Embed query → Cosine similarity search → Top-K results
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Context Builder     │  Format retrieved docs → Prepend to system prompt
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  DeepSeek API Call   │  System prompt = RAG context + original prompt
└─────────────────────┘
```

**Key principle**: The LLM never sees the vector database directly. We retrieve relevant text chunks, format them as natural language, and prepend them to the system prompt. The LLM thinks it "knows" this information.

---

## 2. What is RAG and Why We Use It

### The Problem
LLMs like DeepSeek have general knowledge but lack:
- Specific vulnerability payloads for each attack class
- Custom WAF bypass techniques you've discovered
- Knowledge from security research papers you've read
- Lessons learned from your own previous scans

### The RAG Solution
Instead of fine-tuning (which requires retraining the model), RAG:
1. **Stores** your knowledge as vector embeddings in a database
2. **Retrieves** the most relevant pieces when the LLM needs them
3. **Injects** that knowledge into the prompt so the LLM can use it

### Why This Matters for Pentesting
When the agent encounters a login form, the RAG system retrieves:
- SQL injection bypass techniques specific to the detected WAF
- Authentication bypass methods from OWASP
- Your custom notes about similar targets
- Findings from previous scans on similar technology stacks

This makes every LLM call significantly more targeted and effective.

---

## 3. File Structure

```
core/rag/
├── __init__.py           # Re-exports SecurityRAGPipeline and get_rag
├── pipeline.py           # Main pipeline class — singleton, orchestrates everything
├── embedder.py           # Embedding abstraction (DeepSeek API + local fallback)
├── ingestion.py          # Text extraction, chunking, URL fetching, web search
└── knowledge_seeder.py   # 24 built-in cybersecurity knowledge entries

Integration points:
├── agents/universal_llm_harness.py    # _inject_rag_context() — hooks into every LLM call
├── agents/llm_harness_adapter.py      # Initializes RAG on startup
├── core/orchestration/central_brain.py # Ingests confirmed findings post-scan
├── ui/api/server.py                   # 10 REST API endpoints for RAG
├── ui/web/src/pages/KnowledgeBase.jsx # React UI page with 6 tabs
└── ui/web/src/api.js                  # Frontend API client methods
```

---

## 4. Database Layer — pgvector

### What is pgvector?
pgvector is a PostgreSQL extension that adds vector data types and similarity search operators. It allows storing high-dimensional vectors (embeddings) alongside regular data and performing fast nearest-neighbor searches.

### Schema

```sql
CREATE TABLE rag_documents (
    doc_id       TEXT PRIMARY KEY,         -- Format: "rag_{uuid_hex_12chars}"
    content      TEXT NOT NULL,            -- The actual text content
    metadata     JSONB DEFAULT '{}',       -- Flexible metadata (category, title, url, etc.)
    source_type  TEXT DEFAULT 'manual',    -- One of: seed, file, url, text, web_search, scan_finding
    source_ref   TEXT DEFAULT '',          -- Original source reference (filename, URL, etc.)
    content_hash TEXT DEFAULT '',          -- SHA-256 first 32 chars for deduplication
    embedding    vector(1536),            -- The vector embedding (1536 dimensions)
    created_at   TIMESTAMPTZ DEFAULT NOW() -- Timestamp
);
```

### Indexes

| Index | Type | Purpose |
|-------|------|---------|
| `rag_documents_hnsw_idx` | HNSW (vector_cosine_ops) | Fast approximate nearest neighbor search on embeddings |
| `rag_documents_source_idx` | B-tree on `source_type` | Fast filtering by source type |
| `rag_documents_hash_idx` | B-tree on `content_hash` | Fast deduplication lookups |

### HNSW Index Parameters
- **m = 16**: Number of bi-directional links per node (higher = more accurate but more memory)
- **ef_construction = 64**: Size of dynamic candidate list during index build (higher = slower build but better recall)
- **Distance metric**: `vector_cosine_ops` — cosine distance, which measures angle between vectors (ideal for text similarity)

### Why HNSW over IVFFlat?
- **HNSW**: No training step, better recall at same speed, works well with frequent inserts
- **IVFFlat**: Requires periodic retraining (`REINDEX`), better for static datasets
- For a knowledge base that grows dynamically (user uploads, scan findings), HNSW is the right choice

### Connection Details
```
Host:     localhost
Database: pentesting_db
User:     pentesting_user
Password: pentesting_password
```

Managed via `core.memory.database.DatabaseManager` (connection pooling singleton).

---

## 5. Embedding System

**File**: `core/rag/embedder.py`

### What are Embeddings?
Embeddings convert text into fixed-length numerical vectors where semantically similar texts produce vectors that are close together in the vector space. "SQL injection bypass" and "SQLi WAF evasion" would have similar embeddings, while "CSS styling" would be far away.

### Two-Tier Embedding Strategy

#### Tier 1: DeepSeek Embedding API (Primary)
```python
POST https://api.deepseek.com/v1/embeddings
{
    "model": "deepseek-embedding",
    "input": "<text truncated to 8000 chars>"
}
```
- **Dimension**: 1536 (matches OpenAI's ada-002 for compatibility)
- **Model**: `deepseek-embedding`
- **Input limit**: Text truncated to 8,000 characters before sending
- **Auth**: Bearer token via `DEEPSEEK_API_KEY`
- **Pros**: High-quality semantic embeddings, understands cybersecurity terminology
- **Cons**: Requires API key, network latency, may not be available (currently returns 404)

#### Tier 2: Local Bag-of-Words Hash (Fallback)
When the API is unavailable, a deterministic local embedding is generated:

```python
def _local_embed(self, text: str) -> List[float]:
    vec = [0.0] * 1536
    for token in text.lower().split():
        h = int(hashlib.md5(token.encode()).hexdigest(), 16)
        idx = h % 1536          # Map token to a dimension
        sign = 1.0 if (h >> 128) % 2 == 0 else -1.0  # Random sign
        vec[idx] += sign         # Accumulate
    norm = sqrt(sum(v*v for v in vec))  # L2 normalize
    return [v / norm for v in vec]
```

**How it works**:
1. Tokenize text by whitespace, lowercase
2. For each token, compute MD5 hash
3. Use hash modulo 1536 to pick a vector dimension
4. Use high bit of hash to determine +1 or -1 direction
5. Accumulate values, then L2-normalize the entire vector

**Characteristics**:
- Deterministic: same text always produces same embedding
- No external dependencies or API calls
- Captures word overlap (bag-of-words model)
- Does NOT capture semantic similarity (e.g., "inject" ≠ "injection")
- Produces sparse vectors → lower cosine similarity scores (max ~0.19 vs ~0.90 with API)
- `min_similarity` threshold set to 0.05 to accommodate this

#### Batch Embedding
Both tiers support batch embedding (`embed_batch`). The API version sends all texts in one request and sorts results by index. The local version processes each text independently.

---

## 6. Document Ingestion Pipeline

**File**: `core/rag/ingestion.py`

The ingestion pipeline handles 5 source types:

### 6.1 File Upload
**Method**: `SecurityRAGPipeline.ingest_file(file_path, metadata)`

```
File on disk → extract_text_from_file() → chunk_text() → embed + store each chunk
```

**Supported formats**:
| Format | Extraction Method |
|--------|-------------------|
| `.pdf` | PyPDF2 → pdfplumber → PyMuPDF (cascading fallback) |
| `.txt`, `.md`, `.rst`, `.log` | Direct UTF-8 read |
| `.csv`, `.json`, `.yaml`, `.yml` | Direct UTF-8 read |
| `.html`, `.htm` | Read + strip HTML tags/scripts/styles |
| Other | Attempt UTF-8 read as plain text |

**PDF extraction cascade**:
1. Try `PyPDF2.PdfReader` — most common, handles standard PDFs
2. Try `pdfplumber` — better for complex layouts and tables
3. Try `fitz` (PyMuPDF) — handles scanned PDFs with OCR layer
4. If none installed, log warning and return empty string

**File upload via API**:
- Frontend sends `multipart/form-data` with `file` field
- Server saves to temporary file in `REPORTS_DIR`
- Calls `ingest_file()` on the temp path
- Deletes temp file after ingestion
- Original filename stored in `metadata.original_filename`

### 6.2 URL Ingestion
**Method**: `SecurityRAGPipeline.ingest_url(url, metadata)`

```
URL → fetch_url_text() → chunk_text() → embed + store each chunk
```

**fetch_url_text() details**:
- Uses `httpx.AsyncClient` with 30s timeout and redirect following
- Sets User-Agent to `Mozilla/5.0 (SecurityRAG/1.0; Knowledge Ingestion)`
- If response Content-Type contains "pdf", downloads to temp file and extracts via PDF pipeline
- Otherwise strips HTML tags, scripts, and styles from response body

### 6.3 Text/Notes Ingestion
**Method**: `SecurityRAGPipeline.ingest_text(text, title, metadata)`

```
Raw text → chunk_text() → embed + store each chunk
```

Simplest path — user pastes security notes, payloads, or findings directly. Each chunk gets `source_type="text"` and `source_ref=title`.

### 6.4 Web Search & Ingest
**Method**: `SecurityRAGPipeline.search_and_ingest(query, max_results)`

```
Query → web_search() → [URLs] → fetch each URL → chunk_text() → embed + store
```

See [Section 10](#10-web-search-integration) for search implementation details.

### 6.5 Scan Finding Ingestion
**Method**: `SecurityRAGPipeline.ingest_scan_findings(findings, target)`

Automatically ingests confirmed vulnerability findings after a scan completes. See [Section 13](#13-scan-finding-ingestion).

---

## 7. Text Chunking Strategy

**Function**: `chunk_text(text, max_chars=1500, overlap=200)`

### Why Chunk?
Embeddings work best on focused, coherent text segments. A 50-page PDF as a single embedding would be too diffuse — the vector would average out all topics. Chunking ensures each vector represents a specific piece of knowledge.

### Algorithm

```python
def chunk_text(text, max_chars=1500, overlap=200):
    paragraphs = re.split(r"\n{2,}", text.strip())  # Split on blank lines
    chunks = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 > max_chars and current:
            chunks.append(current)
            tail = current[-overlap:]  # Keep last 200 chars
            current = tail + "\n\n" + para  # Start new chunk with overlap
        else:
            current += "\n\n" + para
    if current.strip():
        chunks.append(current)
    return chunks
```

### Parameters
| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `max_chars` | 1500 | ~375 tokens — fits in embedding model input, specific enough for good retrieval |
| `overlap` | 200 | ~50 tokens — ensures concepts split across chunk boundaries are captured in both chunks |

### Boundary Strategy
- Splits on **double newlines** (paragraph boundaries) — preserves logical units
- Never splits mid-paragraph — a paragraph is the atomic unit
- If a single paragraph exceeds `max_chars`, it becomes its own chunk (no mid-sentence splitting)
- Overlap ensures that a concept mentioned at the end of chunk N is also present at the start of chunk N+1

### Example
```
Input (3200 chars, 3 paragraphs of ~1100 chars each):
  Paragraph A (1100 chars)
  Paragraph B (1100 chars)
  Paragraph C (1000 chars)

Output:
  Chunk 1: Paragraph A + Paragraph B[0:400]  (1500 chars)
  Chunk 2: ...Paragraph B[-200:] + Paragraph C (1200 chars, starts with 200-char overlap)
```

---

## 8. Content Deduplication

**Function**: `content_hash(text) → str`

### Method
```python
hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
```

- SHA-256 hash of the exact UTF-8 bytes
- Truncated to 32 hex characters (128 bits of collision resistance)
- Stored in `rag_documents.content_hash` column
- Indexed via `rag_documents_hash_idx` for fast lookups

### Dedup Check (in `_store_chunk()`)
Before storing any chunk, the pipeline:
1. Computes `content_hash(content)`
2. Queries `SELECT 1 FROM rag_documents WHERE content_hash = %s LIMIT 1`
3. If a row exists → skip (return empty string, don't store)
4. If no row → proceed with embedding and insertion

### What This Prevents
- Re-uploading the same file doesn't create duplicate chunks
- Re-ingesting the same URL doesn't duplicate content
- Re-running the knowledge seeder doesn't duplicate seed documents
- The same web search result appearing multiple times is stored once

### What This Does NOT Prevent
- Near-duplicate content with slight differences (different whitespace, typos)
- Same information expressed differently (semantic duplicates)
- For semantic dedup, you'd need to compare embeddings, which is a future enhancement

---

## 9. Knowledge Seeder

**File**: `core/rag/knowledge_seeder.py`

### Purpose
Seeds the vector database with 24 cybersecurity knowledge entries on first initialization. This ensures the RAG system has useful knowledge even before the user uploads anything.

### Categories and Coverage

| Category | Title | Key Content |
|----------|-------|-------------|
| `sqli` | SQL Injection Detection and Exploitation | CWE-89, basic payloads, boolean/time/error-based blind SQLi, common vulnerable params |
| `sqli` | Advanced SQL Injection Bypass Techniques | WAF bypass (case alternation, inline comments, double URL encoding, unicode, null bytes), second-order SQLi, NoSQL injection |
| `xss` | Cross-Site Scripting Detection and Payloads | CWE-79, reflected/stored/DOM XSS, filter bypass payloads, DOM sinks and sources |
| `csrf` | Cross-Site Request Forgery Testing | CWE-352, CSRF token checks, SameSite cookie, Referer validation |
| `idor` | Insecure Direct Object Reference Testing | CWE-639, horizontal/vertical privilege escalation, sequential ID enumeration |
| `ssrf` | Server-Side Request Forgery Detection | CWE-918, cloud metadata endpoints (AWS/GCP/Azure), IP bypass techniques, DNS rebinding |
| `xxe` | XML External Entity Injection | CWE-611, basic/blind/error-based XXE, OOB via external DTD |
| `jwt` | JWT Security Testing | CWE-345, alg:none, RS256→HS256 confusion, weak secrets, kid injection |
| `path_traversal` | Path Traversal / LFI | CWE-22, encoding bypasses, LFI to RCE via log poisoning |
| `file_upload` | Unrestricted File Upload Testing | CWE-434, extension/content-type/magic-byte bypasses, polyglot files |
| `auth` | Authentication Bypass Techniques | Default creds, credential stuffing, session fixation, OAuth misconfig, 2FA bypass |
| `cors` | CORS Misconfiguration Testing | CWE-942, reflected origin, null origin, subdomain trust |
| `info_disclosure` | Information Disclosure Detection | Stack traces, debug endpoints, backup files, header leakage |
| `business_logic` | Business Logic Vulnerability Testing | Price/quantity manipulation, race conditions, workflow bypass |
| `cmdi` | OS Command Injection | CWE-78, chaining operators, blind detection, filter bypass with ${IFS} |
| `ssti` | Server-Side Template Injection | CWE-1336, Jinja2/Twig/FreeMarker payloads, detection methodology |
| `mass_assignment` | Mass Assignment / Parameter Pollution | CWE-915, adding role/admin/balance fields to requests |
| `headers` | Security Headers Analysis | CSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy |
| `crypto` | Cryptographic Weakness Detection | Weak TLS/ciphers, password hashing, predictable tokens, ECB mode, padding oracle |
| `open_redirect` | Open Redirect Vulnerability Testing | CWE-601, redirect parameter payloads, phishing and OAuth impact |
| `rate_limiting` | Rate Limiting and Brute Force Protection | Login/OTP brute force, bypass via IP rotation and header manipulation |
| `graphql` | GraphQL Security Testing | Introspection, batch/deep nesting DoS, alias enumeration, field suggestions |
| `websocket` | WebSocket Security Testing | Missing origin validation, cross-site WebSocket hijacking |
| `prototype_pollution` | JavaScript Prototype Pollution | CWE-1321, `__proto__` payloads, RCE via child_process gadgets |
| `nosqli` | NoSQL Injection Testing | MongoDB operators ($gt, $ne, $regex, $where), URL-encoded injection |

### Seeding Process
1. On `SecurityRAGPipeline.initialize()`, check if any `source_type="seed"` documents exist
2. If count is 0, iterate all 24 entries from `get_all_knowledge()`
3. For each entry, format as: `[CATEGORY] Title\n\nContent`
4. Store with `source_type="seed"`, `source_ref="built_in_knowledge"`
5. Each entry is embedded and stored as a single chunk (content < 1500 chars)

---

## 10. Web Search Integration

**Function**: `web_search(query, max_results=5)` in `core/rag/ingestion.py`

### Two-Tier Search Strategy

#### Tier 1: `ddgs` Python Package (Primary)
```python
from ddgs import DDGS

def _search():
    with DDGS() as ddgs:
        return list(ddgs.text(query, max_results=max_results))

raw = await loop.run_in_executor(None, _search)
```

- **Package**: `ddgs` v9.16.0 (successor to `duckduckgo-search`)
- **No API key required** — uses DuckDuckGo's internal API
- **Runs in thread pool executor** (`run_in_executor`) because the package is synchronous
- **Returns**: list of `{title, href, body}` dicts
- **Mapped to**: `{title, url, snippet}` for consistency

#### Tier 2: DuckDuckGo Lite (Fallback)
```python
POST https://lite.duckduckgo.com/lite/
Content-Type: application/x-www-form-urlencoded
Body: q=<query>
```

- Only used if `ddgs` package fails (import error, rate limit, etc.)
- Parses HTML response for `<a class="result-link">` elements
- Extracts `href` and link text via regex
- Less reliable than the package but works as emergency fallback

#### Why Not DuckDuckGo HTML Endpoint?
The original implementation used `https://html.duckduckgo.com/html/` but it started returning HTTP 202 (Accepted) with no search results for programmatic requests. DuckDuckGo likely added bot detection that requires JavaScript execution. The `ddgs` package handles this properly using DuckDuckGo's internal API.

### Search-and-Extract Flow
**Function**: `search_and_extract(query, max_results=3, max_chars_per_page=5000)`

1. Call `web_search()` to get URLs
2. For each URL, call `fetch_url_text()` to download and extract text
3. Truncate each page's text to `max_chars_per_page` (5000 chars)
4. Return list of `{url, title, text, snippet}`
5. If fetch fails for a URL, fall back to using the search snippet as content

The pipeline then chunks and stores each page's text as `source_type="web_search"`.

---

## 11. Retrieval — Vector Similarity Search

**Method**: `SecurityRAGPipeline.retrieve(query, top_k=5, category_filter=None, min_similarity=0.05)`

### How Retrieval Works

1. **Embed the query**: Convert the search query to a 1536-dimensional vector using the same embedder
2. **Vector search**: pgvector finds the closest vectors using cosine distance
3. **Filter**: Remove results below the similarity threshold
4. **Return**: Top-K results with content, metadata, and similarity scores

### SQL Query (without category filter)
```sql
SELECT doc_id, content, metadata,
       1 - (embedding <=> %s::vector) AS similarity
FROM rag_documents
ORDER BY embedding <=> %s::vector
LIMIT %s
```

### Distance Metric: Cosine Distance
- `<=>` is pgvector's cosine distance operator
- Cosine distance = 1 - cosine_similarity
- We convert back: `similarity = 1 - cosine_distance`
- Range: 0.0 (completely different) to 1.0 (identical)

### HNSW Search Behavior
- The HNSW index enables **approximate** nearest neighbor search
- It doesn't scan all rows — it traverses a graph structure
- Trade-off: slightly less accurate than brute-force but orders of magnitude faster
- At our scale (<1000 docs), the speed difference is negligible, but the index is ready to scale

### Category Filtering
When `category_filter` is set (e.g., "sqli"), the query adds:
```sql
WHERE metadata->>'category' = %s
```
This uses the JSONB arrow operator to filter by the `category` field in the metadata JSON before the vector search.

### Similarity Threshold
- **Default**: 0.05 (lowered from 0.3 for local embedder compatibility)
- **With DeepSeek API embeddings**: similarities are typically 0.4-0.9 → threshold of 0.3 works well
- **With local hash embeddings**: similarities are typically 0.05-0.20 → threshold of 0.05 needed
- Results below the threshold are filtered out after retrieval

---

## 12. LLM Context Injection

### The Hook: `_inject_rag_context()`
**File**: `agents/universal_llm_harness.py`, line 1159

Every call to `UniversalLLMHarness.generate_response()` runs this method:

```python
async def _inject_rag_context(self, prompt: str, system: Optional[str]) -> Optional[str]:
    rag = get_rag()
    if rag is None:
        return system  # RAG not initialized, pass through

    docs = await rag.retrieve(prompt, top_k=3, min_similarity=0.05)
    if not docs:
        return system  # No relevant docs found

    return rag.build_system_context(docs, system)
```

### What This Means
- **Every** DeepSeek API call (planning, exploitation, analysis — all of them) automatically gets RAG-augmented context
- The user's prompt is used as the retrieval query
- Top 3 most relevant documents are retrieved
- They're prepended to the system prompt
- If RAG fails for any reason, the original system prompt is used unchanged (graceful degradation)

### Context Building: `build_system_context()`
```python
def build_system_context(self, retrieved_docs, base_system_prompt=None):
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
```

### Resulting Prompt Structure
```
SYSTEM PROMPT:
  You are a cybersecurity expert assistant...

  --- Knowledge (relevance: 39%) ---
  [SQLI] Advanced SQL Injection Bypass Techniques
  WAF bypass techniques for SQL injection: Case alternation (sElEcT)...

  --- Knowledge (relevance: 22%) ---
  [Custom] WAF Bypass Techniques for ModSecurity
  1. Double URL Encoding Bypass...

  --- Knowledge (relevance: 18%) ---
  [SQLI] SQL Injection Detection and Exploitation
  SQL Injection (CWE-89) occurs when...

  Use this knowledge to inform your analysis...

  [Original system prompt continues here]

USER PROMPT:
  Analyze this login form for SQL injection vulnerabilities...
```

### Initialization Point
**File**: `agents/llm_harness_adapter.py`

RAG initializes automatically when the LLM harness starts:
```python
async def initialize_llm():
    _harness = UniversalLLMHarness(...)
    await _harness.initialize()

    # RAG init (non-fatal if it fails)
    rag = SecurityRAGPipeline(api_key=config.get("DEEPSEEK_API_KEY"))
    await rag.initialize()
```

---

## 13. Scan Finding Ingestion

**File**: `core/orchestration/central_brain.py`, end of `run_main_loop()`

### What Happens
After a scan completes, confirmed/exploited findings are automatically ingested into the RAG knowledge base:

```python
if not stopped and self.ctx.vulnerabilities:
    confirmed = [v for v in self.ctx.vulnerabilities
                 if v.get("status") in ("CONFIRMED", "EXPLOITED")]
    if confirmed:
        count = await rag.ingest_scan_findings(confirmed, target=self.ctx.target)
```

### Finding Format
Each finding is stored as structured text:
```
[FINDING] Missing X-Frame-Options Header
Severity: LOW | Category: MISSING_HEADER
Location pattern: /api/{id}/settings
Evidence: Response headers do not include X-Frame-Options...
Detection method: automated scanner
```

### Location Anonymization
**Function**: `_anonymize_location(location)`

Before storing, specific IDs and UUIDs in location paths are replaced with generic patterns:
- `/users/12345/profile` → `/users/{id}/profile`
- `/orders/550e8400-e29b-41d4-a716-446655440000` → `/orders/{uuid}`

This makes findings useful across targets — the pattern `/api/{id}/settings` is reusable knowledge, while `/api/12345/settings` is target-specific.

### Metadata
```python
{
    "category": "MISSING_HEADER",
    "severity": "LOW",
    "title": "Missing X-Frame-Options Header",
    "target_hash": "a1b2c3d4..."  # SHA-256 of target URL (privacy)
}
```

### Why Ingest Findings?
The agent learns from its own scans. If it found an IDOR on `/api/users/{id}` during scan A, that knowledge is available during scan B. The RAG retrieval might surface: "Previously found IDOR on similar endpoint pattern — test with sequential IDs and different auth tokens."

---

## 14. REST API Endpoints

**File**: `ui/api/server.py`

All endpoints are under `/api/rag/`.

### Pydantic Models
```python
class RAGTextIngest:    text: str, title: str = "manual_note", metadata: dict = {}
class RAGURLIngest:     url: str, metadata: dict = {}
class RAGSearchIngest:  query: str, max_results: int = 3
class RAGQuery:         query: str, top_k: int = 5, category: str = ""
class RAGDelete:        source_type: str, source_ref: str = ""
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/rag/init` | Initialize RAG pipeline (create tables, seed knowledge). Idempotent — returns stats if already initialized. |
| `GET` | `/api/rag/stats` | Get document counts by source type and category. Returns 503 if not initialized. |
| `POST` | `/api/rag/ingest/file` | Ingest a local file by path (server-side). |
| `POST` | `/api/rag/ingest/uploaded` | Upload a file via multipart form-data. Saves to temp, ingests, deletes temp. |
| `POST` | `/api/rag/ingest/text` | Ingest raw text with a title. |
| `POST` | `/api/rag/ingest/url` | Fetch and ingest a web page. |
| `POST` | `/api/rag/ingest/search` | Search the web, fetch results, and ingest. |
| `POST` | `/api/rag/query` | Query the knowledge base (test what RAG retrieves). |
| `GET` | `/api/rag/documents` | List all documents with full content, metadata, and sizes. Supports `source_type` filter. |
| `DELETE` | `/api/rag/documents` | Delete all documents of a given source type. |
| `DELETE` | `/api/rag/documents/{doc_id}` | Delete a single document by ID. |

### Guard: `_get_rag()`
All endpoints (except `/init`) call `_get_rag()` which:
- Retrieves the singleton pipeline via `get_rag()`
- If `None`, raises HTTP 503 with message to initialize first

### Route Ordering
The SPA catch-all route `@app.get("/{full_path:path}")` is defined **after** all API routes. This is critical — if it were defined before, it would catch `/api/rag/*` requests and serve `index.html` instead.

---

## 15. Frontend UI — Knowledge Base Page

**File**: `ui/web/src/pages/KnowledgeBase.jsx`
**Route**: `/knowledge`
**Nav section**: Intelligence > Knowledge Base

### 6 Tabs

#### 1. Documents Tab (Default)
- Lists all documents sorted by creation date (newest first)
- Each row shows: source type badge (color-coded), title/filename/URL, size in KB, delete button
- Click to expand: shows **Metadata** (all key-value pairs as badges) and **Content** (full text in monospace pre block, scrollable, max-height 300px)
- Source type filter dropdown (All Sources, Built-in, Files, URLs, Notes, Web Searches, Scan Findings)
- Delete individual documents with the × button

#### 2. Upload Tab
- Drag & drop zone for file uploads
- Accepts: `.pdf, .txt, .md, .html, .htm, .csv, .json, .yaml, .yml, .rst, .log`
- Multiple file upload supported
- Shows success/failure flash messages with chunk counts

#### 3. URL Tab
- Text input for URL
- Fetches and ingests the page content
- Shows chunk count on success

#### 4. Search Tab
- Text input for search query
- Dropdown for max results (3, 5, or 10)
- Searches the web via DuckDuckGo, fetches top results, and ingests
- Shows list of ingested source URLs after completion

#### 5. Notes Tab
- Title input field
- Large monospace textarea for pasting security notes
- Ingests as `source_type="text"`

#### 6. Query Tab
- Test what RAG retrieves for any query
- Shows similarity scores as colored percentage badges (green >70%, yellow >40%, gray otherwise)
- Displays document content preview and metadata
- This is what DeepSeek would see before each API call

### Stats Cards (Top of Page)
Six metric cards showing: Total Documents, Uploaded Files, Web Pages, Web Searches, Manual Notes, Scan Findings

### Source Breakdown (Bottom of Page)
Table showing document counts per source type with "Clear All" buttons to bulk-delete by source.

### Frontend API Methods
```javascript
ragInit()                                    // POST /api/rag/init
ragStats()                                   // GET /api/rag/stats
ragIngestText(text, title, metadata)         // POST /api/rag/ingest/text
ragIngestUrl(url, metadata)                  // POST /api/rag/ingest/url
ragSearch(query, max_results)                // POST /api/rag/ingest/search
ragQuery(query, top_k, category)             // POST /api/rag/query
ragDelete(source_type, source_ref)           // DELETE /api/rag/documents
ragUploadFile(file, metadata)                // POST /api/rag/ingest/uploaded (multipart)
ragListDocuments(source_type, limit, offset) // GET /api/rag/documents
ragDeleteDoc(doc_id)                         // DELETE /api/rag/documents/{doc_id}
```

---

## 16. Data Flow Diagrams

### Flow 1: User Uploads a PDF

```
User drops file.pdf in UI
  → Frontend sends multipart POST to /api/rag/ingest/uploaded
  → Server saves to temp file
  → extract_text_from_file("temp.pdf")
      → PyPDF2 reads each page, concatenates text
  → chunk_text(extracted_text, max_chars=1500, overlap=200)
      → Returns ["chunk_0", "chunk_1", "chunk_2"]
  → For each chunk:
      → content_hash(chunk) → "a1b2c3d4..."
      → SELECT 1 FROM rag_documents WHERE content_hash = 'a1b2c3d4...'
      → If not found:
          → embedder.embed(chunk) → [0.012, -0.034, ..., 0.056]  (1536 floats)
          → INSERT INTO rag_documents (doc_id, content, metadata, source_type, embedding, ...)
  → Delete temp file
  → Return {"file": "original.pdf", "chunks": 3, "new_chunks": 3}
```

### Flow 2: LLM Call with RAG Injection

```
CentralBrain calls harness.generate_response("Analyze this login form for SQLi")
  → _inject_rag_context(prompt="Analyze this login form...", system="You are a pentesting agent...")
      → get_rag() → returns singleton pipeline
      → rag.retrieve("Analyze this login form for SQLi", top_k=3)
          → embedder.embed("Analyze this login form for SQLi") → query_vector
          → SELECT content, metadata, 1-(embedding <=> query_vector) AS similarity
            FROM rag_documents ORDER BY embedding <=> query_vector LIMIT 3
          → Returns: [{content: "[SQLI] SQL Injection Detection...", similarity: 0.39}, ...]
      → rag.build_system_context(docs, "You are a pentesting agent...")
          → Prepends RAG knowledge block to system prompt
  → DeepSeek API call with augmented system prompt
  → Response now informed by retrieved SQLi payloads and techniques
```

### Flow 3: Post-Scan Knowledge Accumulation

```
Scan completes on target.com
  → central_brain.run_main_loop() finishes
  → Filter vulnerabilities: status in ("CONFIRMED", "EXPLOITED")
  → rag.ingest_scan_findings(confirmed_findings, target="https://target.com")
      → For each finding:
          → Format: "[FINDING] Missing HSTS Header\nSeverity: LOW | Category: HEADERS..."
          → _anonymize_location("/users/12345/settings") → "/users/{id}/settings"
          → content_hash() → check dedup → embed → store
  → Knowledge is now available for future scans on any target
```

---

## 17. Configuration and Environment

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `DEEPSEEK_API_KEY` | API key for DeepSeek embeddings and LLM | (required for API embeddings) |
| `LLM_MAX_BUDGET_USD` | Maximum LLM spending limit | 100.0 |
| `DEEPSEEK_SMALL_MODEL` | Model for lightweight tasks | deepseek-v4-flash |
| `DEEPSEEK_LARGE_MODEL` | Model for complex reasoning | deepseek-v4-pro |

### Database
The RAG system uses the same PostgreSQL database as the rest of the application (`pentesting_db`). The `rag_documents` table is created automatically on first `initialize()` call.

### Ports
- **Backend API**: 8903 (uvicorn)
- **Frontend dev server**: 5173 (Vite, proxies `/api` to 8903)

### Singleton Pattern
`SecurityRAGPipeline` uses a module-level singleton (`_pipeline`). After `initialize()`, the instance is stored globally and retrieved via `get_rag()`. This ensures:
- Only one embedder client exists
- Only one set of database connections for RAG
- All parts of the system (harness, API, brain) use the same instance

---

## 18. Dependencies

### Python Packages

| Package | Version | Purpose |
|---------|---------|---------|
| `psycopg2-binary` | * | PostgreSQL driver |
| `pgvector` | * | pgvector Python support (registers vector type) |
| `httpx` | * | Async HTTP client (embedding API, URL fetching) |
| `ddgs` | 9.16.0 | DuckDuckGo search (web search feature) |
| `PyPDF2` | * | PDF text extraction (primary) |
| `pdfplumber` | * | PDF text extraction (fallback 1) |
| `PyMuPDF` (fitz) | * | PDF text extraction (fallback 2) |
| `fastapi` | * | REST API framework |
| `pydantic` | * | Request/response validation |
| `uvicorn` | * | ASGI server |

### PostgreSQL Extensions
```sql
CREATE EXTENSION IF NOT EXISTS vector;  -- pgvector extension
```

### Frontend
- React 18+ with Vite
- No additional libraries for the Knowledge Base page (pure React + CSS)

---

## 19. Known Limitations and Future Work

### Current Limitations

1. **Local embedder quality**: When DeepSeek embedding API is unavailable (404), the bag-of-words hash fallback produces sparse vectors with low cosine similarity (~0.19 max). Semantic understanding is lost — only exact word overlap is captured.

2. **No semantic deduplication**: Content hash dedup catches exact duplicates only. Two paragraphs expressing the same concept in different words are stored separately.

3. **Single-threaded embedding**: Chunks are embedded one at a time. Batch embedding (`embed_batch`) exists but isn't used in the ingestion path.

4. **No incremental URL re-ingestion**: Re-ingesting a URL that has updated content creates duplicate chunks (new hash) alongside old ones. No mechanism to "refresh" a URL.

5. **Flat retrieval**: No re-ranking or cross-encoder step after initial vector retrieval. Results are ranked purely by cosine similarity.

6. **No multi-modal**: Only text is embedded. Images in PDFs are ignored. Screenshots, diagrams, and network captures cannot be ingested.

### Future Enhancements

1. **Better embeddings**: Use a local embedding model (e.g., `sentence-transformers/all-MiniLM-L6-v2`) as fallback instead of bag-of-words hash. Provides semantic understanding without API dependency.

2. **Hybrid search**: Combine vector similarity with BM25 keyword search (pgvector + PostgreSQL full-text search). Covers both semantic and exact-match retrieval.

3. **Cross-encoder re-ranking**: After initial top-K retrieval, re-rank with a cross-encoder model for higher precision.

4. **Chunking improvements**: Semantic chunking (split by topic changes instead of fixed character count), or recursive character splitting with configurable separators.

5. **Metadata filtering**: Enable filtering by severity, date range, or custom tags during retrieval.

6. **RAG evaluation**: Measure retrieval quality with test queries and ground truth labels. Track precision@K and recall@K over time.

7. **Knowledge graph**: Extract entities (CVEs, tools, techniques) from documents and build a graph for structured retrieval alongside vector search.
