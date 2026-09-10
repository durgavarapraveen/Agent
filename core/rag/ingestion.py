
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

import httpx

logger = logging.getLogger(__name__)

MAX_CHUNK_CHARS = 1500
CHUNK_OVERLAP = 200

# Parent-child chunking (RAG upgrade #5).
# Children are what we EMBED and SEARCH — small, so they match tight queries.
# Parents are what we RETURN to the LLM — big, so it gets full context.
CHILD_CHUNK_CHARS = 300
CHILD_CHUNK_OVERLAP = 60
PARENT_CHUNK_CHARS = 2000
PARENT_CHUNK_OVERLAP = 200


def chunk_text(text: str, max_chars: int = MAX_CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> List[str]:
    if not text or not text.strip():
        return []
    paragraphs = re.split(r"\n{2,}", text.strip())
    chunks = []
    current = ""
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if len(current) + len(para) + 2 > max_chars and current:
            chunks.append(current.strip())
            tail = current[-overlap:] if overlap else ""
            current = tail + "\n\n" + para
        else:
            current = (current + "\n\n" + para).strip()
    if current.strip():
        chunks.append(current.strip())
    return chunks


def _sub_split(text: str, size: int, overlap: int) -> List[str]:
    if len(text) <= size:
        return [text]
    sentences = re.split(r"(?<=[.!?])\s+", text)
    out, cur = [], ""
    for s in sentences:
        if not s:
            continue
        if len(cur) + len(s) + 1 > size and cur:
            out.append(cur.strip())
            tail = cur[-overlap:] if overlap else ""
            cur = (tail + " " + s).strip()
        else:
            cur = (cur + " " + s).strip()
    if cur.strip():
        out.append(cur.strip())
    return out


def chunk_parent_child(text: str,
                       parent_size: int = PARENT_CHUNK_CHARS,
                       parent_overlap: int = PARENT_CHUNK_OVERLAP,
                       child_size: int = CHILD_CHUNK_CHARS,
                       child_overlap: int = CHILD_CHUNK_OVERLAP) -> List[Dict[str, Any]]:
    parents = chunk_text(text, max_chars=parent_size, overlap=parent_overlap)
    out: List[Dict[str, Any]] = []
    for pi, p in enumerate(parents):
        for ci, c in enumerate(_sub_split(p, child_size, child_overlap)):
            out.append({
                "parent_idx": pi,
                "child_idx": ci,
                "parent_content": p,
                "content": c,
            })
    return out


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def extract_text_from_file(file_path: str) -> str:
    path = Path(file_path)
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return _extract_pdf(path)
    elif suffix in (".txt", ".md", ".rst", ".csv", ".log", ".yaml", ".yml"):
        return path.read_text(encoding="utf-8", errors="replace")
    elif suffix == ".json":
        return path.read_text(encoding="utf-8", errors="replace")
    elif suffix in (".html", ".htm"):
        raw = path.read_text(encoding="utf-8", errors="replace")
        return _strip_html(raw)
    else:
        return path.read_text(encoding="utf-8", errors="replace")


def _extract_pdf(path: Path) -> str:
    try:
        import PyPDF2
        reader = PyPDF2.PdfReader(str(path))
        pages = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
        return "\n\n".join(pages)
    except ImportError:
        pass

    try:
        import pdfplumber
        with pdfplumber.open(str(path)) as pdf:
            return "\n\n".join(p.extract_text() or "" for p in pdf.pages)
    except ImportError:
        pass

    try:
        import fitz  # PyMuPDF
        doc = fitz.open(str(path))
        return "\n\n".join(page.get_text() for page in doc)
    except ImportError:
        pass

    logger.warning(f"No PDF library available. Install PyPDF2: pip install PyPDF2")
    return ""


def _strip_html(html: str) -> str:
    html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<[^>]+>", " ", html)
    html = re.sub(r"\s+", " ", html)
    return html.strip()


async def fetch_url_text(url: str, timeout: float = 30.0) -> str:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url, headers={
            "User-Agent": "Mozilla/5.0 (SecurityRAG/1.0; Knowledge Ingestion)",
        })
        r.raise_for_status()
        content_type = r.headers.get("content-type", "")
        if "pdf" in content_type:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
                f.write(r.content)
                tmp_path = f.name
            try:
                return _extract_pdf(Path(tmp_path))
            finally:
                os.unlink(tmp_path)
        return _strip_html(r.text)


async def web_search(query: str, max_results: int = 5) -> List[Dict[str, str]]:
    import asyncio
    results = []

    # Primary: duckduckgo-search package
    try:
        from ddgs import DDGS

        def _search():
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))

        loop = asyncio.get_event_loop()
        raw = await loop.run_in_executor(None, _search)
        for r in raw:
            results.append({
                "url": r.get("href", ""),
                "title": r.get("title", ""),
                "snippet": r.get("body", ""),
            })
    except Exception as e:
        logger.warning(f"[WebSearch] duckduckgo-search failed: {e}")

    # Fallback: DuckDuckGo Lite endpoint
    if not results:
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                r = await client.post(
                    "https://lite.duckduckgo.com/lite/",
                    data={"q": query},
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                if r.status_code == 200:
                    for m in re.finditer(
                        r'<a[^>]+href="(https?://[^"]+)"[^>]*class="result-link"[^>]*>(.*?)</a>',
                        r.text, re.DOTALL,
                    ):
                        url, title = m.group(1), _strip_html(m.group(2))
                        results.append({"url": url, "title": title, "snippet": ""})
                        if len(results) >= max_results:
                            break
        except Exception as e:
            logger.warning(f"[WebSearch] DuckDuckGo Lite fallback failed: {e}")

    return results


async def search_and_extract(query: str, max_results: int = 3, max_chars_per_page: int = 5000) -> List[Dict[str, Any]]:
    search_results = await web_search(query, max_results=max_results)
    extracted = []
    for sr in search_results:
        url = sr.get("url", "")
        if not url.startswith("http"):
            continue
        try:
            text = await fetch_url_text(url)
            text = text[:max_chars_per_page]
            extracted.append({
                "url": url,
                "title": sr.get("title", ""),
                "text": text,
                "snippet": sr.get("snippet", ""),
            })
        except Exception as e:
            logger.debug(f"[WebSearch] Failed to fetch {url}: {e}")
            extracted.append({
                "url": url,
                "title": sr.get("title", ""),
                "text": sr.get("snippet", ""),
                "snippet": sr.get("snippet", ""),
            })
    return extracted
