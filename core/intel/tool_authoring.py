"""LLM-authored security tools — P0.4 hardened pipeline.

Pipeline (P0.4):
    LLM generation
     -> AST/static validation    (tool_validator)
     -> capability analysis      (tool_validator)
     -> policy validation        (PolicyEngine)
     -> LLM critic               (advisory only — cannot authorize)
     -> isolated execution       (ExecutionController / P0.3 sandbox)
     -> runtime policy enforcement
     -> ToolRegistry

The LLM critic is advisory only. Approval/rejection is determined by the
deterministic AST + policy pipeline. The critic's opinion is logged but
never overrides a policy denial.
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
    if len(code) > 8000:
        return "[ERROR] author_tool: code too large (max 8KB)"

    # ── P0.4 pipeline: deterministic validation is the authority ─────────
    validation = None
    tool_def = None
    try:
        from core.security.tool_validator import (
            validate_authored_code, build_tool_definition,
        )
        validation = validate_authored_code(code, name=name)
        if validation.blocked:
            logger.warning("[author_tool] BLOCKED by validator: %s", validation.blocked_reason)
            _persist_tool(name, desc, schema, code, "rejected",
                          {"pipeline": "p0.4_validator",
                           "blocked_reason": validation.blocked_reason,
                           "issues": validation.issues})
            return (f"tool {name!r} REJECTED (validator: {validation.blocked_reason}). "
                    f"issues={validation.issues}")
        tool_def = build_tool_definition(name, desc, code, validation)
    except ImportError:
        logger.debug("[author_tool] tool_validator unavailable, using legacy banned-token check")
        for b in BANNED:
            if b in code:
                return f"[ERROR] author_tool: banned token {b!r} in code"

    # ── LLM critic — advisory only, never overrides validator ────────────
    review = await _critic_review(name, desc, schema, code)
    critic_approved = bool(review.get("approve"))

    # Validator is the authority; critic is advisory
    if validation is not None:
        approved = validation.valid
        review_notes = {
            "pipeline": "p0.4",
            "validator": validation.to_dict(),
            "critic_advisory": review,
            "tool_definition": tool_def.to_dict() if tool_def else None,
        }
        if not critic_approved and approved:
            logger.info("[author_tool] critic disagreed but validator approved %s", name)
            review_notes["critic_overridden"] = True
        if critic_approved and not approved:
            logger.info("[author_tool] critic approved but validator blocked %s", name)
    else:
        # Legacy path: critic is the authority (pre-P0.4 fallback)
        approved = critic_approved
        review_notes = review

    _persist_tool(name, desc, schema, code,
                  "approved" if approved else "rejected",
                  review_notes)

    status = "APPROVED" if approved else "REJECTED"
    risk = (validation.risk_level.value if validation else
            review.get("risk_score", "?"))
    caps = (sorted(c.value for c in validation.capabilities) if validation else [])
    msg = f"tool {name!r} {status} (risk={risk}"
    if caps:
        msg += f", capabilities={caps}"
    msg += f", issues={review.get('issues', []) if not validation else validation.issues})"
    if approved:
        msg += " Call it via run_authored_tool."
    return msg


def _persist_tool(name: str, desc: str, schema: Dict,
                  code: str, status: str, review_notes: Any) -> None:
    """Persist authored tool to database."""
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO authored_tools
                      (name, description, parameters_schema, code,
                       review_status, review_notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                      description = EXCLUDED.description,
                      parameters_schema = EXCLUDED.parameters_schema,
                      code = EXCLUDED.code,
                      review_status = EXCLUDED.review_status,
                      review_notes = EXCLUDED.review_notes
                """, (name, desc, json.dumps(schema), code, status,
                      json.dumps(review_notes, default=str)))
                conn.commit()
    except Exception as e:
        logger.error("[author_tool] persist error: %s", e)


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

    code = tool["code"]

    # P0.4: Re-validate at execution time — a tool approved before P0.4
    # might contain capabilities that are now blocked.
    try:
        from core.security.tool_validator import validate_authored_code
        validation = validate_authored_code(code, name=name)
        if validation.blocked:
            logger.warning("[run_authored_tool] %s blocked at runtime: %s",
                           name, validation.blocked_reason)
            return (f"[ERROR] run_authored_tool: {name!r} blocked by runtime "
                    f"validator: {validation.blocked_reason}")
        if not validation.valid:
            return (f"[ERROR] run_authored_tool: {name!r} failed runtime "
                    f"validation: {validation.issues}")
    except ImportError:
        pass
    except Exception as e:
        logger.warning("[run_authored_tool] runtime validation error: %s", e)

    tool_args = args.get("args") or {}
    wrapped_code = (
        f"args = {json.dumps(tool_args, default=str)}\n"
        + code
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
