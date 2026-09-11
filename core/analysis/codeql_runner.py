from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_CODEQL_TIMEOUT_S = int(os.environ.get("CODEQL_TIMEOUT_S", "900"))
_CODEQL_HOME = os.environ.get("CODEQL_HOME", "/opt/codeql")


def _codeql_available() -> bool:
    return bool(shutil.which("codeql") or Path(_CODEQL_HOME, "codeql").exists())


def _codeql_bin() -> str:
    if shutil.which("codeql"):
        return "codeql"
    return str(Path(_CODEQL_HOME) / "codeql")


def _detect_language(tree: Path) -> Optional[str]:
    counts: Dict[str, int] = {}
    for f in tree.rglob("*"):
        if not f.is_file():
            continue
        s = f.suffix.lower()
        counts[s] = counts.get(s, 0) + 1
    lang_map = {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".tsx": "javascript", ".jsx": "javascript",
        ".go": "go", ".java": "java", ".rb": "ruby",
        ".c": "cpp", ".cpp": "cpp", ".h": "cpp",
        ".cs": "csharp", ".rs": "rust",
    }
    lang_counts: Dict[str, int] = {}
    for ext, n in counts.items():
        lang = lang_map.get(ext)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + n
    if not lang_counts:
        return None
    return max(lang_counts, key=lang_counts.get)


def run_codeql(tree: Path,
               language: Optional[str] = None,
               query_suite: str = "security-and-quality") -> List[Dict[str, Any]]:
    if not tree or not tree.exists():
        return []
    if not _codeql_available():
        logger.debug("[CodeQL] binary not on PATH and CODEQL_HOME unset — skipping")
        return []
    language = language or _detect_language(tree)
    if not language:
        logger.debug("[CodeQL] no supported language detected")
        return []
    bin_ = _codeql_bin()
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "db"
        sarif = Path(td) / "out.sarif"
        r = subprocess.run(
            [bin_, "database", "create", str(db),
             "--source-root", str(tree),
             "--language", language, "--overwrite"],
            capture_output=True, text=True, timeout=_CODEQL_TIMEOUT_S)
        if r.returncode != 0:
            logger.debug(f"[CodeQL] db create failed: {r.stderr[:300]}")
            return []
        suite = f"{language}-{query_suite}.qls"
        r = subprocess.run(
            [bin_, "database", "analyze", str(db), suite,
             "--format=sarif-latest", "--output", str(sarif)],
            capture_output=True, text=True, timeout=_CODEQL_TIMEOUT_S)
        if r.returncode != 0:
            logger.debug(f"[CodeQL] analyze failed: {r.stderr[:300]}")
            return []
        try:
            data = json.loads(sarif.read_text(encoding="utf-8"))
        except Exception:
            return []
    return _sarif_to_findings(data)


def _sarif_to_findings(sarif: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for run in sarif.get("runs", []) or []:
        rules = {r.get("id"): r for r in run.get("tool", {})
                 .get("driver", {}).get("rules", []) or []}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "codeql")
            level = res.get("level", "warning")
            loc0 = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = (loc0.get("artifactLocation") or {}).get("uri", "")
            line = (loc0.get("region") or {}).get("startLine", 0)
            rule = rules.get(rid, {})
            msg = (res.get("message") or {}).get("text",
                                                 rule.get("shortDescription", {}).get("text", rid))
            out.append({
                "title": f"SAST(codeql): {rid}",
                "type": "sast_codeql",
                "severity": {"error": "high", "warning": "medium",
                             "note": "low"}.get(level, "low"),
                "location": uri,
                "line": line,
                "details": msg[:2000],
                "tool": "codeql",
                "confidence": "high",
                "rule_id": rid,
            })
    return out


# ── Phase 3.5: LLM code-review feedback ────────────────────────────────

async def llm_review_finding(finding: Dict[str, Any],
                             tree: Path) -> Optional[Dict[str, Any]]:
    try:
        from agents.llm_harness_adapter import get_llm
        llm = get_llm()
    except Exception:
        return None
    if not llm:
        return None
    src_path = tree / (finding.get("location") or "")
    if not src_path.exists() or not src_path.is_file():
        return None
    try:
        source = src_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    line = int(finding.get("line") or 0)
    # Extract ±40 lines around the finding.
    lines = source.splitlines()
    lo, hi = max(0, line - 40), min(len(lines), line + 40)
    snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))
    prompt = (
        f"A static analyzer flagged this source location as potentially "
        f"vulnerable. Design an HTTP-level exploit that would trigger it "
        f"at runtime. Return JSON with fields: method, path, headers, "
        f"body, expected_response_marker.\n\n"
        f"Finding: {finding.get('title')}\n"
        f"Rule: {finding.get('rule_id')}\n"
        f"File: {finding.get('location')} line {line}\n"
        f"Snippet (with 1-based line numbers):\n```\n{snippet}\n```\n"
    )
    try:
        resp = await llm.generate_json(prompt)
        if isinstance(resp, dict) and resp.get("method") and resp.get("path"):
            return {
                "method": resp["method"],
                "path": resp["path"],
                "headers": resp.get("headers", {}),
                "body": resp.get("body"),
                "expected_marker": resp.get("expected_response_marker"),
                "origin_finding": finding.get("rule_id"),
            }
    except Exception as e:
        logger.debug(f"[LLMCodeReview] LLM call failed: {e}")
    return None
