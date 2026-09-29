"""Active attack-surface discovery via the Kali container — deterministic, not
LLM-optional. Closes three discovery gaps:

  * run_js_crawl        — katana JS-aware crawl (finds SPA/API routes the
                          href-regex crawler misses).
  * run_content_discovery — ffuf directory brute + arjun parameter mining,
                          seeded from the target and discovered endpoints.
  * run_vhost_discovery — ffuf Host-header (vhost) bruteforce to find
                          co-hosted virtual hosts.

All shell out to tools inside the Kali container through _run_in_kali. Every
function is scope-gated and a clean no-op when the container/tool is unavailable,
so a scan never breaks on a host without Kali.
"""
from __future__ import annotations

import json
import logging
import os
import shlex
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_DIR_WORDLIST = os.getenv("RECON_DIR_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
_DNS_WORDLIST = os.getenv("RECON_VHOST_WORDLIST",
                          "/usr/share/dnsrecon/dnsrecon/data/subdomains-top1mil-5000.txt")
_MC = "200,204,301,302,307,401,403,405"


def _authorized(host: str) -> bool:
    try:
        from core.security.authorization import TargetScopeValidator
        return bool(host) and TargetScopeValidator.get().is_authorized(host)
    except Exception:
        return bool(host)


def _base_url(ctx) -> str:
    t = str(getattr(ctx, "target", "") or "")
    if not t:
        return ""
    return t if t.startswith(("http://", "https://")) else f"https://{t}"


def _kali_sh(cmd: str, timeout: int = 120):
    """Run a bash command inside the Kali container. Returns (rc, stdout, stderr).
    The command is built by us (targets shlex-quoted); shell runs container-side."""
    inner = max(10, timeout - 8)
    script = (
        "import subprocess,sys\n"
        f"try:\n"
        f"    r=subprocess.run(['bash','-lc',{cmd!r}],capture_output=True,text=True,timeout={inner})\n"
        "    sys.stdout.write(r.stdout)\n"
        "except Exception as e:\n"
        "    sys.stderr.write(str(e))\n"
    )
    try:
        from core.execution.executors.generic import _run_in_kali
        return _run_in_kali(script, timeout)
    except Exception as e:
        logger.debug("[ActiveDiscovery] kali unavailable: %s", e)
        return -1, "", str(e)


def _add_endpoints(ctx, urls: List[str], source: str) -> int:
    eps = [{"url": u, "method": "GET"} for u in urls if u]
    if not eps:
        return 0
    try:
        ctx.add_endpoints(eps, source=source)
    except Exception:
        # Fallback: some ctx versions take positional only
        try:
            ctx.add_endpoints(eps)
        except Exception:
            return 0
    return len(eps)


# ── JS-aware crawl (katana) ──────────────────────────────────────────────────
async def run_js_crawl(ctx) -> List[Dict[str, Any]]:
    import asyncio
    base = _base_url(ctx)
    host = urlparse(base).hostname or ""
    if not base or not _authorized(host):
        return []
    depth = os.getenv("RECON_KATANA_DEPTH", "2")
    cmd = (f"katana -u {shlex.quote(base)} -d {int(depth)} -jc -silent -jsonl "
           f"-timeout 8 -c 15 2>/dev/null | jq -r '.request.endpoint' 2>/dev/null | sort -u")
    rc, out, _ = await asyncio.to_thread(_kali_sh, cmd, 120)
    if rc != 0 or not out.strip():
        return []
    urls: Set[str] = set()
    for line in out.splitlines():
        u = line.strip()
        if u.startswith(("http://", "https://")) and (urlparse(u).hostname or "") and _authorized(urlparse(u).hostname):
            urls.add(u)
    n = _add_endpoints(ctx, sorted(urls), "katana_js_crawl")
    logger.info("[ActiveDiscovery] katana: %d endpoint(s) discovered", n)
    return []


# ── Content + parameter discovery (ffuf + arjun) ─────────────────────────────
async def run_content_discovery(ctx) -> List[Dict[str, Any]]:
    import asyncio
    base = _base_url(ctx)
    host = urlparse(base).hostname or ""
    if not base or not _authorized(host):
        return []

    # 1) Directory brute (ffuf, JSONL).
    cmd = (f"ffuf -u {shlex.quote(base.rstrip('/') + '/FUZZ')} -w {shlex.quote(_DIR_WORDLIST)} "
           f"-mc {_MC} -t 40 -timeout 8 -json -s 2>/dev/null")
    rc, out, _ = await asyncio.to_thread(_kali_sh, cmd, 180)
    found: Set[str] = set()
    if rc == 0 and out.strip():
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            u = row.get("url") or ""
            if u:
                found.add(u.split("?")[0])
    n_dirs = _add_endpoints(ctx, sorted(found), "ffuf_content_discovery")

    # 2) Parameter mining (arjun) on a few endpoints incl. any just discovered.
    targets = []
    seen = set()
    for u in [base] + sorted(found):
        b = u.split("?")[0]
        if b not in seen:
            seen.add(b)
            targets.append(b)
    targets = targets[:5]
    n_params = 0
    for u in targets:
        # arjun writes JSON to a file; run it then cat the file in one shell.
        outf = "/tmp/arjun_out.json"
        acmd = (f"arjun -u {shlex.quote(u)} --stable -oJ {outf} >/dev/null 2>&1; "
                f"cat {outf} 2>/dev/null; rm -f {outf} 2>/dev/null")
        rc, aout, _ = await asyncio.to_thread(_kali_sh, acmd, 120)
        if rc != 0 or not aout.strip():
            continue
        try:
            data = json.loads(aout)
        except Exception:
            continue
        # arjun -oJ maps url -> {"params": [...], "method":...}
        params: List[str] = []
        if isinstance(data, dict):
            for _url, info in data.items():
                if isinstance(info, dict):
                    params.extend(info.get("params") or [])
        if params:
            n_params += len(params)
            try:
                store = getattr(ctx, "discovered_params", None)
                if not isinstance(store, dict):
                    store = {}
                store[u] = sorted(set(params))
                setattr(ctx, "discovered_params", store)
                # also register the endpoint-with-params so probes exercise them
                _add_endpoints(ctx, [u + "?" + "=1&".join(sorted(set(params))) + "=1"],
                               "arjun_param_mining")
            except Exception:
                pass
    logger.info("[ActiveDiscovery] content discovery: %d dir(s), %d param(s) across %d endpoint(s)",
                n_dirs, n_params, len(targets))
    return []


# ── Virtual-host bruteforce (ffuf Host header) ───────────────────────────────
async def run_vhost_discovery(ctx) -> List[Dict[str, Any]]:
    import asyncio
    base = _base_url(ctx)
    host = urlparse(base).hostname or ""
    if not base or not _authorized(host):
        return []
    # Derive an apex to fuzz subdomains under (FUZZ.apex as a Host header).
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host
    # Baseline length for a random vhost (to filter default responses).
    cmd = (f"ffuf -u {shlex.quote(base)} "
           f"-H {shlex.quote('Host: FUZZ.' + apex)} -w {shlex.quote(_DNS_WORDLIST)} "
           f"-mc {_MC} -t 40 -timeout 8 -json -s -ac 2>/dev/null")
    rc, out, _ = await asyncio.to_thread(_kali_sh, cmd, 180)
    if rc != 0 or not out.strip():
        return []
    hits: Set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        fuzz = (row.get("input") or {}).get("FUZZ") or ""
        if fuzz:
            hits.add(f"{fuzz}.{apex}")
    if hits:
        try:
            ctx.add_subdomains(sorted(hits), source="vhost_bruteforce")
        except Exception:
            pass
    logger.info("[ActiveDiscovery] vhost bruteforce: %d virtual host(s)", len(hits))
    return []
