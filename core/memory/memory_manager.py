"""Agent memory — "memory-as-tool" so the LLM fetches state on demand instead
of us re-pasting the whole world into every turn.

WHY: Bedrock/deepseek chat-completions is stateless (each call re-sends context).
Provider-native session state (AWS Stateful Runtime / AgentCore Memory) is
OpenAI-model-only and not GA, so we rebuild the same pattern client-side with
deepseek tool-calling: facts persist in the DB (blackboard, vulnerabilities,
coverage, prior-phase summaries) and the agent pulls the relevant slice via
tools. Zero fact loss (everything stays retrievable), bounded context (no window
overflow on long scans), and it stacks with gateway prefix caching.

Backend-swappable: everything goes through AgentMemory's 5 methods, so when a
managed store (AgentCore Memory) becomes reachable for our models we swap the
backend here without touching the agent loop.

Opt-in via NEO_AGENT_MEMORY (default off) so it can be A/B'd against the current
full-dump behaviour before becoming default. See project_agent_memory_plan.
"""
from __future__ import annotations

import json
import logging
import math
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Below this many endpoints AND with no findings yet, the full dump is cheap and
# safest — don't switch to on-demand retrieval. Above it, compact + tools.
_COMPACT_ENDPOINT_THRESHOLD = int(os.getenv("NEO_AGENT_MEMORY_THRESHOLD", "20"))
_SEARCH_CANDIDATE_CAP = 400          # bound the candidate set we rank
_STATE_VIEW_PAGE = 25                # rows per state_view page


def memory_enabled() -> bool:
    """Master switch. Off = current full-dump behaviour (zero change)."""
    return (os.getenv("NEO_AGENT_MEMORY", "") or "").strip().lower() in (
        "1", "true", "yes", "on")


def _current_scan_id() -> str:
    return os.getenv("ANTIGRAVITY_SCAN_ID", "") or ""


# --------------------------------------------------------------------------- #
# Candidate loading — every source is namespaced so memory_get can round-trip.
#   bb:<id>   agent_blackboard row
#   vuln:<id> vulnerabilities row
#   cov:<id>  coverage_records row
#   mem:<id>  scan_llm_memory (prior-phase summary) row
# --------------------------------------------------------------------------- #
def _load_blackboard(scan_id: str) -> List[Dict[str, Any]]:
    try:
        from core.orchestration import blackboard
        return blackboard.recent(scan_id, limit=_SEARCH_CANDIDATE_CAP) or []
    except Exception as e:
        logger.debug(f"[AgentMemory] blackboard load failed: {e}")
        return []


def _load_vulns(scan_id: str) -> List[Dict[str, Any]]:
    try:
        from core.database.pg_store import VulnRepo
        return VulnRepo.get_by_scan(scan_id) or []
    except Exception as e:
        logger.debug(f"[AgentMemory] vuln load failed: {e}")
        return []


def _load_coverage(scan_id: str) -> List[Dict[str, Any]]:
    try:
        from core.database.pg_store import CoverageRepo
        return CoverageRepo.list_by_scan(scan_id) or []
    except Exception as e:
        logger.debug(f"[AgentMemory] coverage load failed: {e}")
        return []


def _load_prior_memory(scan_id: str) -> List[Dict[str, Any]]:
    try:
        from core.database.pg_store import LLMMemoryRepo
        return LLMMemoryRepo.get_by_scan(scan_id, limit=200) or []
    except Exception as e:
        logger.debug(f"[AgentMemory] prior-memory load failed: {e}")
        return []


def _vuln_line(v: Dict[str, Any]) -> str:
    t = v.get("vuln_type") or v.get("type") or v.get("title") or "finding"
    sev = v.get("severity") or "?"
    tgt = v.get("endpoint") or v.get("url") or v.get("target") or ""
    conf = "confirmed" if v.get("confirmed") else "unconfirmed"
    return f"[{sev}/{conf}] {t} @ {tgt}".strip()


def _bb_line(r: Dict[str, Any]) -> str:
    return f"[{r.get('kind','note')}] {r.get('title','')} {r.get('ref','')}".strip()


def _cov_line(r: Dict[str, Any]) -> str:
    return (f"{r.get('technique','')} @ {r.get('endpoint','')} "
            f"({r.get('status','')}{'/confirmed' if r.get('confirmed') else ''})").strip()


def _mem_line(r: Dict[str, Any]) -> str:
    return f"[{r.get('phase','phase')}] {(r.get('content') or '')[:160]}".strip()


def _candidates(scan_id: str) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Return (namespaced_id, searchable_text, full_row) across all sources."""
    out: List[Tuple[str, str, Dict[str, Any]]] = []
    for r in _load_vulns(scan_id):
        rid = r.get("id")
        txt = _vuln_line(r) + " " + str(r.get("description") or r.get("evidence") or "")[:300]
        out.append((f"vuln:{rid}", txt, r))
    for r in _load_blackboard(scan_id):
        rid = r.get("id")
        txt = _bb_line(r) + " " + json.dumps(r.get("data") or {}, default=str)[:300]
        out.append((f"bb:{rid}", txt, r))
    for r in _load_prior_memory(scan_id):
        out.append((f"mem:{r.get('id')}", _mem_line(r) + " " + (r.get("content") or "")[:400], r))
    for r in _load_coverage(scan_id):
        out.append((f"cov:{r.get('id')}", _cov_line(r) + " " + str(r.get("evidence") or "")[:200], r))
    return out[:_SEARCH_CANDIDATE_CAP]


# --------------------------------------------------------------------------- #
# Ranking — semantic (reuse RAG embedder) with keyword fallback. Never raises.
# --------------------------------------------------------------------------- #
def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _keyword_score(query: str, text: str) -> float:
    q = {w for w in query.lower().split() if len(w) > 2}
    if not q:
        return 0.0
    t = text.lower()
    return sum(1 for w in q if w in t) / len(q)


async def _rank(query: str, cands: List[Tuple[str, str, Dict[str, Any]]],
                k: int) -> List[Tuple[str, str, Dict[str, Any]]]:
    if not cands:
        return []
    # Try semantic first.
    try:
        from core.rag.embedder import Embedder
        emb = Embedder()
        qv = (await emb.embed(query)).vector
        docs = await emb.embed_batch([c[1] for c in cands])
        if qv and docs:
            scored = [(_cosine(qv, d.vector), c) for d, c in zip(docs, cands)]
            scored.sort(key=lambda x: x[0], reverse=True)
            return [c for _, c in scored[:k]]
    except Exception as e:
        logger.debug(f"[AgentMemory] semantic rank fell back to keyword: {e}")
    # Keyword fallback.
    scored = [(_keyword_score(query, c[1]), c) for c in cands]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for s, c in scored[:k] if s > 0] or [c for _, c in scored[:k]]


class AgentMemory:
    """Per-scan memory facade. Reuses existing DB tables + RAG embedder."""

    def __init__(self, scan_id: str = "", ctx: Any = None):
        self.scan_id = scan_id or _current_scan_id()
        self.ctx = ctx

    # -- gating ----------------------------------------------------------- #
    def should_compact(self) -> bool:
        """True once state is big enough that on-demand retrieval beats a dump."""
        try:
            n_ep = len(getattr(self.ctx, "endpoints", {}) or {})
            n_vuln = len(getattr(self.ctx, "vulnerabilities", []) or [])
            return n_ep > _COMPACT_ENDPOINT_THRESHOLD or n_vuln > 0
        except Exception:
            return False

    # -- compact index (goes into user_message in place of full lists) ---- #
    def compact_index(self) -> str:
        ctx = self.ctx
        n_ep = len(getattr(ctx, "endpoints", {}) or {})
        subs = getattr(ctx, "subdomains", []) or []
        techs = getattr(ctx, "technologies", {}) or {}
        vulns = getattr(ctx, "vulnerabilities", []) or []
        n_conf = sum(1 for v in vulns if isinstance(v, dict) and v.get("confirmed"))
        try:
            from core.database.pg_store import CoverageRepo
            cov = CoverageRepo.summary(self.scan_id) if self.scan_id else {}
        except Exception:
            cov = {}
        tech_names = ", ".join(sorted(list(techs.keys()))[:12]) if isinstance(techs, dict) else str(techs)[:200]
        lines = [
            "## Current Knowledge (index — details on demand)",
            f"- Endpoints: {n_ep}  |  Subdomains: {len(subs)}  |  Technologies: {tech_names or 'unknown'}",
            f"- Findings: {len(vulns)} ({n_conf} confirmed) — already found, DO NOT re-test; "
            "pull with state_view(section=\"findings\").",
        ]
        if cov:
            lines.append(f"- Coverage rows: {sum(cov.values()) if isinstance(cov, dict) else cov}")
        lines.append(
            "- Full lists are not pasted to save context. Use the memory tools: "
            "state_view (page endpoints/findings/coverage/auth), memory_search "
            "(find facts by meaning), memory_get (full record by id), memory_write "
            "(save a durable conclusion)."
        )
        return "\n".join(lines) + "\n\n"

    # -- tools ------------------------------------------------------------ #
    async def search(self, query: str, k: int = 8) -> str:
        if not (query or "").strip():
            return "memory_search: empty query."
        cands = _candidates(self.scan_id)
        if not cands:
            return "memory_search: no stored facts yet for this scan."
        top = await _rank(query, cands, max(1, min(int(k or 8), 25)))
        if not top:
            return f"memory_search: no matches for {query!r}."
        lines = [f"{cid}  {txt[:180]}" for cid, txt, _ in top]
        return f"memory_search hits for {query!r} (use memory_get for full records):\n" + "\n".join(lines)

    def get(self, ids: Any) -> str:
        wanted = self._parse_ids(ids)
        if not wanted:
            return "memory_get: no ids given."
        by_id = {cid: (txt, row) for cid, txt, row in _candidates(self.scan_id)}
        out = []
        for cid in wanted:
            hit = by_id.get(cid)
            if not hit:
                out.append(f"{cid}: not found")
                continue
            out.append(f"### {cid}\n" + json.dumps(hit[1], default=str)[:1500])
        return "\n\n".join(out) if out else "memory_get: nothing resolved."

    def write(self, title: str, data: Any = None, agent_id: str = "agent-memory") -> str:
        title = (title or "").strip()
        if not title:
            return "memory_write: title required."
        try:
            from core.orchestration import blackboard
            payload = data if isinstance(data, dict) else ({"note": str(data)} if data else {})
            blackboard.post(self.scan_id, agent_id, "note", title[:300], data=payload)
            return f"memory_write: saved {title[:80]!r}."
        except Exception as e:
            return f"memory_write: failed ({e})."

    def state_view(self, section: str = "all", filter: str = "", page: int = 0) -> str:
        section = (section or "all").strip().lower()
        flt = (filter or "").strip().lower()
        page = max(0, int(page or 0))

        def _page(rows: List[str]) -> str:
            total = len(rows)
            start = page * _STATE_VIEW_PAGE
            chunk = rows[start:start + _STATE_VIEW_PAGE]
            more = ""
            if start + _STATE_VIEW_PAGE < total:
                more = f"\n… {total - (start + _STATE_VIEW_PAGE)} more — call again with page={page+1}."
            head = f"({total} rows" + (f", filter={flt!r}" if flt else "") + f", page {page})"
            return head + "\n" + ("\n".join(chunk) if chunk else "(none)") + more

        parts = []
        if section in ("endpoints", "all"):
            eps = self._endpoint_lines(flt)
            parts.append("## Endpoints " + _page(eps))
        if section in ("findings", "vulns", "all"):
            vl = [_vuln_line(v) for v in _load_vulns(self.scan_id)
                  if not flt or flt in json.dumps(v, default=str).lower()]
            parts.append("## Findings " + _page(vl))
        if section in ("coverage", "cov", "all"):
            cl = [_cov_line(c) for c in _load_coverage(self.scan_id)
                  if not flt or flt in json.dumps(c, default=str).lower()]
            parts.append("## Coverage " + _page(cl))
        if section in ("auth", "all"):
            parts.append("## Auth\n" + self._auth_summary())
        return "\n\n".join(parts) if parts else f"state_view: unknown section {section!r}."

    # -- helpers ---------------------------------------------------------- #
    def _endpoint_lines(self, flt: str) -> List[str]:
        eps = getattr(self.ctx, "endpoints", {}) or {}
        lines = []
        for key, ep in (eps.items() if isinstance(eps, dict) else []):
            url = getattr(ep, "url", None) or (ep.get("url") if isinstance(ep, dict) else str(ep))
            method = getattr(ep, "method", None) or (ep.get("method") if isinstance(ep, dict) else "")
            row = f"{method or 'GET'} {url}".strip()
            if not flt or flt in row.lower():
                lines.append(row)
        return sorted(set(lines))

    def _auth_summary(self) -> str:
        ctx = self.ctx
        sessions = getattr(ctx, "auth_sessions", {}) or {}
        has_bearer = bool((getattr(ctx, "auth_headers", {}) or {}).get("Authorization"))
        out = []
        out.append(f"- Bearer loaded: {has_bearer}")
        out.append(f"- Roles/sessions: {', '.join(sorted(sessions.keys())) or 'none'}")
        return "\n".join(out)

    @staticmethod
    def _parse_ids(ids: Any) -> List[str]:
        if isinstance(ids, list):
            return [str(i).strip() for i in ids if str(i).strip()]
        if isinstance(ids, str):
            return [s.strip() for s in ids.replace(",", " ").split() if s.strip()]
        return []


# --------------------------------------------------------------------------- #
# OpenAI-function tool schemas — registered into PENTESTING_TOOLS when memory
# mode is on. Dispatch lives in AgenticExecutor._execute_tool_call.
# --------------------------------------------------------------------------- #
MEMORY_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "memory_search",
            "description": (
                "Search this scan's accumulated memory (findings, tool notes, "
                "coverage, prior-phase summaries) by meaning. Use it to recall "
                "what you already know before acting, so you don't repeat work. "
                "Returns matching record ids + one-line summaries; fetch full "
                "records with memory_get."),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What you're looking for, in natural language."},
                    "k": {"type": "integer", "description": "Max hits (default 8, max 25)."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_get",
            "description": "Fetch full records by id (from memory_search), e.g. ['vuln:12','bb:88'].",
            "parameters": {
                "type": "object",
                "properties": {
                    "ids": {"type": "array", "items": {"type": "string"},
                            "description": "Namespaced ids: vuln:<n>, bb:<n>, cov:<n>, mem:<n>."},
                },
                "required": ["ids"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_write",
            "description": (
                "Persist a durable conclusion to scan memory so later phases can "
                "recall it (survives context compaction). Use for decisions, "
                "confirmed facts, and leads to chase later."),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short one-line conclusion."},
                    "data": {"type": "object", "description": "Optional structured detail."},
                },
                "required": ["title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "state_view",
            "description": (
                "Page through the current scan state on demand instead of it being "
                "pasted into the prompt. Sections: endpoints, findings, coverage, "
                "auth, all. Optional substring filter and page number."),
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {"type": "string", "enum": ["endpoints", "findings", "coverage", "auth", "all"]},
                    "filter": {"type": "string", "description": "Optional substring filter."},
                    "page": {"type": "integer", "description": "0-based page (25 rows/page)."},
                },
                "required": ["section"],
            },
        },
    },
]
