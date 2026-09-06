"""LLM-authored security tools.

Lets the LLM define new attack sub-agents in natural language + Python code.
Every authored tool goes through a critic review (safety + soundness) before
it's marked approved. Approved tools are callable via `run_authored_tool` on
subsequent scans.

Safety:
  - Static banned-token check (same as custom_python sandbox)
  - Critic LLM must return `approve: true` — verifies scope/side-effects
  - Execution reuses the custom_python sandbox
"""
from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


AUTHOR_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "author_tool",
        "description": (
            "AUTHOR a new reusable security probe. Provide a name, description, "
            "JSON schema for its arguments, and Python code that runs the probe "
            "against the target. The code has the same sandbox as run_custom_python "
            "(httpx, asyncio; scope-guarded; no filesystem). It MUST assign to RESULT. "
            "The tool is critic-reviewed for safety and stored — you and future "
            "scans can call it via run_authored_tool(name, args)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "parameters_schema": {"type": "object", "description": "JSON-Schema for args"},
                "code": {"type": "string", "description": "Python code — receives `args` dict and `target_base`; must assign RESULT."},
            },
            "required": ["name", "description", "code"],
        },
    },
}


REVIEW_PROMPT = """You are a security-code reviewer. Return ONE strict JSON object:
{
  "approve": true|false,
  "risk_score": 0-10,
  "issues": ["<issue>", ...],
  "notes": "<one sentence>"
}

Rules:
- Reject if the code tries to write to disk, spawn subprocesses, or make
  network calls outside the authorised target host.
- Reject if the code loops without bound or sleeps > 10s.
- Reject payload that would DoS the target (>100 requests without delay).
- Approve if the code executes bounded HTTP probes against the target scope.

TOOL NAME: %NAME%
DESCRIPTION: %DESC%
PARAMS SCHEMA: %SCHEMA%
CODE:
```python
%CODE%
```"""


BANNED = ("open(", "__import__", "eval(", "exec(", "compile(", "subprocess",
          "os.system", "os.popen", "socket.socket", "importlib", "sys.exit",
          "shutil", "pathlib", "input(")


def _canonical(name: str) -> str:
    return re.sub(r"[^a-z0-9_\-]+", "_", (name or "").lower()).strip("_")[:60] or "tool"


async def _critic_review(name: str, desc: str, schema: Dict, code: str) -> Dict:
    try:
        from agents.llm_harness_adapter import get_llm
        from agents.universal_llm_harness import TaskTier
        llm = get_llm()
        if llm is None:
            return {"approve": False, "risk_score": 10,
                     "issues": ["LLM critic unavailable"], "notes": "unable to review"}
        p = (REVIEW_PROMPT
              .replace("%NAME%", name)
              .replace("%DESC%", desc[:500])
              .replace("%SCHEMA%", json.dumps(schema, default=str)[:800])
              .replace("%CODE%", code[:6000]))
        r = await llm.generate_response(prompt=p, max_tokens=500, temperature=0.1,
                                          tier=TaskTier.SMALL)
        text = (getattr(r, "content", "") or "").strip()
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return {"approve": False, "risk_score": 10,
                     "issues": ["critic returned invalid JSON"], "notes": ""}
        return json.loads(m.group(0))
    except Exception as e:
        return {"approve": False, "risk_score": 10,
                 "issues": [f"critic exception: {e}"], "notes": ""}


async def author_tool(args: Dict[str, Any], ctx) -> str:
    name = _canonical(args.get("name") or "")
    desc = str(args.get("description") or "")[:2000]
    schema = args.get("parameters_schema") or {}
    code = str(args.get("code") or "")
    if not name or not code:
        return "[ERROR] author_tool: name and code required"
    for b in BANNED:
        if b in code:
            return f"[ERROR] author_tool: banned token {b!r} in code"
    if len(code) > 8000:
        return "[ERROR] author_tool: code too large (max 8KB)"

    review = await _critic_review(name, desc, schema, code)
    approved = bool(review.get("approve"))
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO authored_tools
                      (name, description, parameters_schema, code, review_status, review_notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                      description = EXCLUDED.description,
                      parameters_schema = EXCLUDED.parameters_schema,
                      code = EXCLUDED.code,
                      review_status = EXCLUDED.review_status,
                      review_notes = EXCLUDED.review_notes
                """, (name, desc, json.dumps(schema),
                      code,
                      "approved" if approved else "rejected",
                      json.dumps(review)))
                conn.commit()
    except Exception as e:
        return f"[ERROR] author_tool persist: {e}"
    return (f"tool {name!r} {'APPROVED' if approved else 'REJECTED'} "
            f"(risk={review.get('risk_score','?')}, issues={review.get('issues','[]')}). "
            + ("Call it via run_authored_tool." if approved else ""))


async def run_authored_tool(args: Dict[str, Any], ctx, tracker=None) -> str:
    name = _canonical(args.get("name") or "")
    if not name:
        return "[ERROR] run_authored_tool: name required"
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM authored_tools WHERE name=%s AND review_status='approved'", (name,))
                tool = cur.fetchone()
        if not tool:
            return f"[ERROR] run_authored_tool: {name!r} not found or not approved"
    except Exception as e:
        return f"[ERROR] run_authored_tool DB: {e}"
    tool_args = args.get("args") or {}
    # Wrap the code so it sees `args` and `target_base`, must set RESULT
    wrapped_code = (
        f"args = {json.dumps(tool_args, default=str)}\n"
        + tool["code"]
    )
    from core.exploitation.custom_probe import run_custom_python
    return await run_custom_python(
        {"code": wrapped_code, "hypothesis": f"authored:{name}"}, ctx, tracker)


RUN_AUTHORED_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_authored_tool",
        "description": "Execute a previously-authored + approved tool by name.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "args": {"type": "object", "description": "arguments passed to the tool as dict"},
            },
            "required": ["name"],
        },
    },
}
