from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Root directory for extracted per-scan sources. Falls back to /tmp when
# `SOURCE_EXTRACT_DIR` isn't set. Never write anywhere else.
_BASE = Path(os.environ.get("SOURCE_EXTRACT_DIR",
                            "/tmp/antigravity_source"))
_MAX_CLONE_MB = int(os.environ.get("SOURCE_MAX_CLONE_MB", "200"))
_CLONE_TIMEOUT_S = int(os.environ.get("SOURCE_CLONE_TIMEOUT_S", "180"))


def _safe(scan_id: str) -> str:
    return re.sub(r"[^\w.\-]", "_", (scan_id or "unscoped"))[:128]


def _scan_dir(scan_id: str) -> Path:
    p = _BASE / _safe(scan_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _run(cmd: List[str], cwd: Optional[Path] = None,
         timeout: int = 60) -> subprocess.CompletedProcess:
    logger.debug(f"[SourceExtractor] $ {' '.join(shlex.quote(c) for c in cmd)}")
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                          capture_output=True, text=True,
                          timeout=timeout, check=False)


# ── Phase 3.1: git / svn / mercurial extraction ────────────────────────

def extract_exposed_git(base_url: str, scan_id: str) -> Optional[Path]:
    from core.security.egress_firewall import assert_egress_allowed, EgressBlocked
    try:
        assert_egress_allowed(base_url, purpose="source.git")
    except EgressBlocked as e:
        logger.warning(f"[SourceExtractor] egress denied for {base_url}: {e}")
        return None

    dst = _scan_dir(scan_id) / "git_extracted"
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    dst.mkdir(parents=True, exist_ok=True)

    # Technique 1 — smart-git direct clone.
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    r = _run(["git", "clone", "--depth", "1", root, str(dst)],
             timeout=_CLONE_TIMEOUT_S)
    if r.returncode == 0 and any(dst.iterdir()):
        logger.info(f"[SourceExtractor] git clone succeeded → {dst}")
        return dst

    # Technique 2 — git-dumper (if installed).
    if shutil.which("git-dumper"):
        r = _run(["git-dumper", root, str(dst)], timeout=_CLONE_TIMEOUT_S)
        if r.returncode == 0 and any(dst.iterdir()):
            logger.info(f"[SourceExtractor] git-dumper succeeded → {dst}")
            return dst

    # Technique 3 — best-effort HTTP walk. Grab the low-hanging fruit only:
    # HEAD, config, refs/heads/*, packed-refs. Even without pack files, this
    # already reveals branch names and often points at a commit hash we can
    # then fetch individually.
    try:
        import httpx
        with httpx.Client(follow_redirects=True, timeout=10, verify=False) as c:
            for path in (".git/HEAD", ".git/config", ".git/packed-refs",
                         ".git/description", ".git/info/refs"):
                url = urljoin(root + "/", path)
                try:
                    resp = c.get(url)
                    if resp.status_code == 200:
                        (dst / path.replace("/", "__")).write_bytes(resp.content)
                except Exception:
                    continue
        if any(dst.iterdir()):
            logger.info(f"[SourceExtractor] partial .git dump → {dst}")
            return dst
    except Exception as e:
        logger.debug(f"[SourceExtractor] http walk failed: {e}")

    shutil.rmtree(dst, ignore_errors=True)
    return None


# ── Phase 3.2: sourcemap rehydration ───────────────────────────────────

def rehydrate_sourcemap(bundle_url: str, scan_id: str) -> Optional[Path]:
    from core.security.egress_firewall import assert_egress_allowed, EgressBlocked
    try:
        assert_egress_allowed(bundle_url, purpose="source.sourcemap")
    except EgressBlocked as e:
        logger.warning(f"[SourceExtractor] egress denied for {bundle_url}: {e}")
        return None
    try:
        import httpx
    except Exception:
        return None

    map_url = bundle_url + ".map" if not bundle_url.endswith(".map") else bundle_url
    dst = _scan_dir(scan_id) / "sourcemap" / _safe(urlparse(bundle_url).netloc)
    try:
        with httpx.Client(follow_redirects=True, timeout=15, verify=False) as c:
            resp = c.get(map_url)
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception as e:
        logger.debug(f"[SourceExtractor] sourcemap fetch failed: {e}")
        return None
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if not sources or not contents:
        return None
    dst.mkdir(parents=True, exist_ok=True)
    written = 0
    for src, body in zip(sources, contents):
        if not body:
            continue
        # Normalise webpack pseudo-paths like `webpack:///./src/app.ts`.
        rel = re.sub(r"^webpack:///+", "", src)
        rel = rel.lstrip("./")
        rel = re.sub(r"[?#].*$", "", rel)
        if not rel or rel.endswith("/"):
            continue
        outp = dst / rel
        outp.parent.mkdir(parents=True, exist_ok=True)
        try:
            outp.write_text(body, encoding="utf-8", errors="replace")
            written += 1
        except OSError:
            continue
    if not written:
        shutil.rmtree(dst, ignore_errors=True)
        return None
    logger.info(f"[SourceExtractor] rehydrated {written} sourcemap files → {dst}")
    return dst


# ── Phase 3.3: semgrep runner ──────────────────────────────────────────

def run_semgrep(tree: Path, rules: str = "auto",
                timeout: int = 300) -> List[Dict[str, Any]]:
    if not tree or not tree.exists() or not shutil.which("semgrep"):
        return []
    r = _run(["semgrep", "--config", rules, "--json", "--quiet",
              "--timeout", "30", str(tree)], timeout=timeout)
    if r.returncode not in (0, 1):    # 1 = findings present, 0 = clean
        logger.debug(f"[SourceExtractor] semgrep rc={r.returncode} "
                     f"stderr={r.stderr[:200]!r}")
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out: List[Dict[str, Any]] = []
    for m in data.get("results", []) or []:
        extra = m.get("extra", {}) or {}
        sev = str(extra.get("severity", "INFO")).lower()
        out.append({
            "title": f"SAST: {m.get('check_id', 'semgrep')}",
            "type": "sast_semgrep",
            "severity": {"error": "high", "warning": "medium",
                         "info": "low"}.get(sev, "low"),
            "location": m.get("path", ""),
            "line": (m.get("start") or {}).get("line", 0),
            "details": extra.get("message", "")[:2000],
            "tool": "semgrep",
            "confidence": "high",
            "rule_id": m.get("check_id"),
        })
    return out
