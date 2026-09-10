from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _canonical_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_\-]+", "_", (name or "").lower()).strip("_")[:80] or "skill"


def _current_target_shape(ctx) -> Dict[str, Any]:
    techs = getattr(ctx, "technologies", {}) or {}
    tags = set()
    for _, v in techs.items():
        for t in (v if isinstance(v, list) else [v]):
            if isinstance(t, str):
                tags.add(t.lower().split(":")[0].strip())
    intel = getattr(ctx, "prior_intel", {}) or {}
    fp = (intel.get("metadata") or {}).get("fingerprint") or {}
    if fp.get("server"):
        tags.add(fp["server"].lower().split("/")[0])
    if fp.get("x_powered_by"):
        tags.add(fp["x_powered_by"].lower().split("/")[0])
    return {"tags": sorted(tags)}


def _shape_matches(skill_shape: Dict, current_shape: Dict) -> float:
    s_tags = set((skill_shape or {}).get("tags") or [])
    c_tags = set((current_shape or {}).get("tags") or [])
    if not s_tags:
        return 0.5  # unknown-shape skill — mild fit
    if not c_tags:
        return 0.5
    overlap = len(s_tags & c_tags) / max(1, len(s_tags | c_tags))
    return overlap


SKILL_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "list_skills",
            "description": (
                "List learned skills (proven probes from prior scans) that MATCH this "
                "target's tech shape. Each skill is a reusable payload template that "
                "confirmed a vulnerability previously — use them BEFORE crafting new probes."
            ),
            "parameters": {"type": "object", "properties": {}},
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_skill",
            "description": "Execute a learned skill against the target. Returns response.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "skill name from list_skills"},
                    "url": {"type": "string", "description": "override URL if skill has a template placeholder"},
                },
                "required": ["name"],
            },
        }
    },
]


def list_skills(ctx) -> str:
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        current = _current_target_shape(ctx)
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM learned_skills ORDER BY confirmed_count DESC LIMIT 100")
                rows = [dict(r) for r in cur.fetchall()]
        matched = []
        for r in rows:
            score = _shape_matches(r.get("tech_shape") or {}, current)
            if score >= 0.15:
                matched.append((score, r))
        matched.sort(key=lambda x: -x[0])
        if not matched:
            return "(no matched skills for this target shape yet)"
        lines = ["| skill | matched | uses | expects | description |",
                 "|---|---|---|---|---|"]
        for score, r in matched[:20]:
            lines.append(f"| `{r['name']}` | {int(score*100)}% | "
                         f"{r.get('confirmed_count',0)} | "
                         f"`{(r.get('expected_signature') or '')[:40]}` | "
                         f"{(r.get('description') or '')[:80]} |")
        return "\n".join(lines)
    except Exception as e:
        return f"[ERROR] list_skills: {e}"


async def run_skill(args: Dict, ctx, tracker=None) -> str:
    name = _canonical_name(args.get("name") or "")
    if not name:
        return "[ERROR] run_skill: name required"
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM learned_skills WHERE name=%s", (name,))
                skill = cur.fetchone()
        if not skill:
            return f"[ERROR] run_skill: skill {name!r} not found"
    except Exception as e:
        return f"[ERROR] run_skill DB: {e}"
    # Materialise URL — {base} → ctx.target host
    base_url = ctx.target if str(ctx.target).startswith(("http://", "https://")) else f"https://{ctx.target}"
    pu = urlparse(base_url)
    base_root = f"{pu.scheme}://{pu.netloc}"
    template = skill.get("url_template") or ""
    url = args.get("url") or template.replace("{base}", base_root)
    from core.exploitation.custom_probe import run_custom_probe
    body = skill.get("body_template") or None
    body_out = body.replace("{base}", base_root) if body else None
    resp = await run_custom_probe({
        "method": skill.get("method", "GET"),
        "url": url,
        "headers": skill.get("headers") or {},
        "body": body_out,
        "hypothesis": f"reuse skill {name}: {skill.get('description','')[:120]}",
    }, ctx, tracker)
    # Bump last_used_at
    try:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE learned_skills SET last_used_at=NOW() WHERE name=%s", (name,))
                conn.commit()
    except Exception:
        pass
    return resp


def save_skill(*, name: str, description: str, method: str, url_template: str,
                headers: Optional[Dict] = None, body_template: str = "",
                expected_signature: str = "", tech_shape: Optional[Dict] = None,
                scan_id: str = "") -> bool:
    try:
        from core.database.pg_store import DatabaseManager
        cname = _canonical_name(name)
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO learned_skills
                      (name, description, method, url_template, headers, body_template,
                       expected_signature, tech_shape, confirmed_count, last_confirmed_scan)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s)
                    ON CONFLICT (name) DO UPDATE SET
                      confirmed_count = learned_skills.confirmed_count + 1,
                      last_confirmed_scan = EXCLUDED.last_confirmed_scan,
                      description = COALESCE(NULLIF(EXCLUDED.description,''), learned_skills.description),
                      expected_signature = COALESCE(NULLIF(EXCLUDED.expected_signature,''), learned_skills.expected_signature)
                """, (cname, description, method, url_template,
                      json.dumps(headers or {}), body_template,
                      expected_signature, json.dumps(tech_shape or {}), scan_id))
                conn.commit()
        logger.info(f"[SkillLibrary] Saved skill {cname!r}")
        return True
    except Exception as e:
        logger.warning(f"[SkillLibrary] save failed: {e}")
        return False
