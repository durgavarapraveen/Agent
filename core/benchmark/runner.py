"""Benchmark corpus generation + scoring — generic across benchmarks.

Generation: discover challenges from a live challenge API on the target (generic
field mapping; default probe path ``/api/Challenges`` but configurable via
``NEO_CHALLENGE_API``), else fall back to a static versioned corpus file.

Scoring: map confirmed findings + coverage to challenges PER-CHALLENGE (id +
technique + endpoint hint), producing explicit statuses and negative-evidence
reasons — never collapsing a whole vuln_class to one "solved". Results persist to
``benchmark_results`` and every corpus/solve is posted to the shared
**blackboard** so all agents coordinate on what remains.
"""
from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.benchmark.corpus import (
    BenchmarkCorpus, BenchmarkResult, Challenge, infer_technique, _slug,
    _CHECKLIST_CLASSES, CONFIRMED, PARTIAL, NOT_FOUND, NOT_APPLICABLE, BLOCKED,
)

logger = logging.getLogger(__name__)

_BENCH_AGENT = "benchmark"


def _canonical_classes(d: Dict[str, Any]) -> set:
    """Canonical vuln classes for a finding OR a challenge, via the SINGLE shared
    classifier (gap_analysis) so custom finding types (API_ABUSE, jwt_kid_…) and
    OWASP challenge categories are compared in ONE vocabulary. Generic."""
    try:
        import scripts.gap_analysis as _ga
        return set(_ga.classify(d))
    except Exception:
        return set()


def _bb_post(scan_id: str, kind: str, title: str, data: Dict, ref: str = "") -> None:
    if not scan_id:
        return
    try:
        from core.orchestration import blackboard
        blackboard.post(scan_id, _BENCH_AGENT, kind, title, data, ref=ref)
    except Exception:
        pass


# ── generation: live challenge source ────────────────────────────────────────
def _challenge_api_paths() -> List[str]:
    env = (os.getenv("NEO_CHALLENGE_API", "") or "").strip()
    if env:
        return [p.strip() for p in env.split(",") if p.strip()]
    return ["/api/Challenges", "/api/challenges", "/challenges.json"]


def _base_url(target: str) -> str:
    t = (target or "").rstrip("/")
    if t and not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _coerce_challenges(items: List[Dict], source: str) -> List[Challenge]:
    out: List[Challenge] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or it.get("title") or it.get("key") or "").strip()
        cid = str(it.get("id") or it.get("key") or it.get("challenge_id") or _slug(name))
        if not name and not cid:
            continue
        category = str(it.get("category") or it.get("type") or it.get("group") or "").strip()
        desc = str(it.get("description") or it.get("hint") or "")
        try:
            diff = int(it.get("difficulty") or 0)
        except (TypeError, ValueError):
            diff = 0
        prereqs = []
        blob = (category + " " + name + " " + desc).lower()
        if any(k in blob for k in ("login", "account", "logged", "authenticated", "your ")):
            prereqs.append("authenticated_user")
        if any(k in blob for k in ("another user", "other user", "basket of", "someone else")):
            prereqs.append("second_identity")
        out.append(Challenge(
            id=str(cid), name=name or str(cid), category=category or "uncategorized",
            source=source, description=desc[:1000], difficulty=diff,
            technique=infer_technique(category, name, desc),
            prerequisites=prereqs,
            metadata={k: it.get(k) for k in ("solved", "tags", "tutorial") if k in it},
        ))
    return out


def fetch_live_challenges(target: str, timeout: int = 12) -> List[Challenge]:
    """Discover challenges from a live challenge API on the target. Generic:
    accepts a bare list, ``{"data":[...]}`` or ``{"challenges":[...]}``. Returns
    [] (not an error) when the target exposes no such API."""
    base = _base_url(target)
    if not base:
        return []
    try:
        import httpx
    except Exception:
        logger.info("[benchmark] httpx unavailable — cannot fetch live challenges")
        return []
    for path in _challenge_api_paths():
        url = base + (path if path.startswith("/") else "/" + path)
        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as c:
                r = c.get(url)
            if r.status_code != 200:
                continue
            body = r.json()
        except Exception as e:
            logger.debug("[benchmark] fetch %s failed: %s", url, e)
            continue
        items = (body.get("data") or body.get("challenges") or body.get("items")
                 if isinstance(body, dict) else body)
        if isinstance(items, list) and items:
            chs = _coerce_challenges(items, source=f"live_api:{path}")
            if chs:
                logger.info("[benchmark] discovered %d challenges from %s", len(chs), url)
                return chs
    return []


# Generic checklist technique set = the canonical class vocabulary (gap_analysis),
# so a checklist corpus scores in the same taxonomy as an API-derived one.
_CHECKLIST_TECHNIQUES = _CHECKLIST_CLASSES


def _surfaces_from_ctx(ctx) -> List[Dict[str, Any]]:
    """Return [{url, applicable, auth_state}] for the discovered attack surface,
    preferring SurfaceClassifier (per-surface applicable classes) and falling
    back to the raw endpoint inventory."""
    out: List[Dict[str, Any]] = []
    if ctx is None:
        return out
    try:
        from core.recon.surface_classifier import SurfaceClassifier
        for s in SurfaceClassifier().classify(ctx):
            out.append({"url": getattr(s, "url", ""),
                        "applicable": [c for c in (getattr(s, "applicable_classes", None) or [])],
                        "auth_state": getattr(s, "auth_state", "unknown")})
    except Exception:
        pass
    if out:
        return out
    try:
        eps = ctx.get_endpoints() if hasattr(ctx, "get_endpoints") else (getattr(ctx, "endpoints", []) or [])
        for e in eps:
            u = e if isinstance(e, str) else (e.get("url") if isinstance(e, dict) else getattr(e, "url", ""))
            if u:
                out.append({"url": u, "applicable": [], "auth_state": "unknown"})
    except Exception:
        pass
    return out


def build_checklist_corpus(target: str, suite: str, version: str = "", ctx=None,
                           surfaces: Optional[List[Dict]] = None,
                           max_challenges: int = 600) -> BenchmarkCorpus:
    """Generic corpus: technique × discovered endpoint. Works for any website."""
    version = version or datetime.now(timezone.utc).strftime("%Y%m%d")
    surfaces = surfaces if surfaces is not None else _surfaces_from_ctx(ctx)
    from urllib.parse import urlparse
    challenges: List[Challenge] = []
    seen = set()
    for s in surfaces:
        url = s.get("url", "")
        if not url:
            continue
        techniques = [_norm(t) for t in (s.get("applicable") or [])] or list(_CHECKLIST_TECHNIQUES)
        auth = s.get("auth_state", "unknown")
        for tech in techniques:
            cid = f"{tech}|{url}"
            if cid in seen:
                continue
            seen.add(cid)
            prereqs = ["authenticated_user"] if auth == "authenticated" else []
            challenges.append(Challenge(
                id=cid, name=f"{tech} @ {urlparse(url).path or url}", category=tech,
                source="checklist", technique=tech, target_hint=url, prerequisites=prereqs,
                oracle_type="evidence"))
            if len(challenges) >= max_challenges:
                return BenchmarkCorpus(suite, version, challenges)
    return BenchmarkCorpus(suite, version, challenges)


def generate_corpus(target: str, suite: str, version: str = "",
                    scan_id: str = "", ctx=None) -> BenchmarkCorpus:
    """Build (and persist) a versioned corpus for ``suite``. Source precedence:
      1. a live challenge API on the target (benchmark apps, e.g. Juice Shop);
      2. a generic checklist over the discovered attack surface (ANY website);
      3. the latest static corpus file for the suite.
    Generic throughout — nothing is Juice-Shop-specific."""
    version = version or datetime.now(timezone.utc).strftime("%Y%m%d")

    challenges = fetch_live_challenges(target)
    if challenges:
        corpus = BenchmarkCorpus(suite, version, challenges)
        corpus.save()
        _bb_post(scan_id, "note", f"Benchmark corpus generated: {suite}/{version}",
                 {"suite": suite, "version": version, "count": len(challenges), "source": "live_api"})
        return corpus

    # Generic: build from the discovered attack surface (real websites).
    corpus = build_checklist_corpus(target, suite, version, ctx=ctx)
    if corpus.challenges:
        corpus.save()
        _bb_post(scan_id, "note", f"Checklist corpus generated: {suite}/{version}",
                 {"suite": suite, "version": version, "count": len(corpus.challenges),
                  "source": "checklist"})
        return corpus

    latest = BenchmarkCorpus.latest_version(suite)
    if latest:
        c = BenchmarkCorpus.load(suite, latest)
        if c:
            logger.info("[benchmark] using static corpus %s/%s", suite, latest)
            _bb_post(scan_id, "note", f"Benchmark corpus loaded (static): {suite}/{latest}",
                     {"suite": suite, "version": latest, "count": len(c.challenges),
                      "source": "static_file"})
            return c
    logger.info("[benchmark] no source available for suite=%s (no live API, no surface, no static)", suite)
    return BenchmarkCorpus(suite, version, [])


# ── scoring ───────────────────────────────────────────────────────────────
def _norm(s: str) -> str:
    return (s or "").strip().lower().replace("-", "_").replace(" ", "_")


def _ep_path(u: str) -> str:
    """Normalized path for endpoint matching (scheme/host/query stripped)."""
    from urllib.parse import urlparse
    try:
        p = urlparse(u if "://" in u else "//" + u)
        return (p.path or u).rstrip("/").lower()
    except Exception:
        return (u or "").lower()


def _finding_index(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Index findings by CANONICAL class (via gap_analysis), so custom finding
    types (API_ABUSE, jwt_kid_injection, BIZLOGIC_…) resolve to the same
    vocabulary the challenges use. A finding can index under several classes."""
    idx: Dict[str, List[Dict]] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            f = getattr(f, "__dict__", {})
        classes = _canonical_classes(f)
        if not classes:
            vc = _norm(f.get("type") or f.get("vuln_class") or f.get("category") or "")
            classes = {vc} if vc else set()
        for c in classes:
            idx.setdefault(c, []).append(f)
    return idx


def _has_auth(ctx) -> bool:
    try:
        if getattr(ctx, "auth_sessions", None):
            return True
        if (getattr(ctx, "auth_headers", {}) or {}).get("Authorization"):
            return True
    except Exception:
        pass
    return False


def _identity_count(ctx) -> int:
    try:
        return len(getattr(ctx, "auth_sessions", {}) or {})
    except Exception:
        return 0


def _name_anchor_match(name: str, findings: List[Dict]) -> Optional[Dict]:
    """For a name/generic-only challenge (no canonical vuln class), find a CONFIRMED
    discovery finding whose route/location/title contains the challenge-name slug.
    Generic and evidence-bound: requires a real finding, so it can't fabricate a
    solve. Specificity-gated (slug >= 7 chars) to avoid short/generic false hits."""
    slug = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    tokens = [t for t in re.split(r"[^a-z0-9]+", str(name or "").lower()) if len(t) >= 5]
    if len(slug) < 7:
        return None
    for f in findings:
        if not (f.get("confirmed") or str(f.get("status", "")).upper() == "CONFIRMED"):
            continue
        # Name-anchor credits ONLY dedicated discovery findings (route/policy
        # enumeration). An unrelated CONFIRMED exploit finding can never token- or
        # slug-collide its way to a false "solved" on a class-less challenge.
        if f.get("source") != "route_disclosure_probe":
            continue
        hay = re.sub(r"[^a-z0-9]", "",
                     f"{f.get('location','')}{f.get('target','')}{f.get('title','')}".lower())
        # (a) full name slug present (slug≥7 is specific), or (b) all multi-char name
        #     tokens present (≥2 tokens, each ≥5) — handles a page whose route/title
        #     spells the name apart (e.g. "Privacy Policy" ↔ /privacy-policy).
        if slug in hay or (len(tokens) >= 2 and all(t in hay for t in tokens)):
            return f
    return None


def score_corpus(scan_id: str, corpus: BenchmarkCorpus, findings: List[Dict],
                 ctx=None, run_meta: Optional[Dict] = None) -> Dict[str, Any]:
    """Score each challenge independently → BenchmarkResult, persist to DB, and
    post confirmations to the blackboard. Returns a summary dict."""
    idx = _finding_index(findings)
    run_meta = run_meta or _build_run_meta(scan_id)
    counts: Dict[str, int] = {}
    results: List[BenchmarkResult] = []

    # Human-in-the-loop: index any answers a human already gave for this suite so
    # a human-solved challenge counts as confirmed (generic HITL, not app-specific).
    human_by_ref: Dict[str, Dict] = {}
    try:
        from core.orchestration import human_assist
        if human_assist.enabled() and scan_id:
            from core.database.pg_store import HumanRequestRepo
            for hr in HumanRequestRepo.list_by_scan(scan_id):
                if hr.get("ref"):
                    human_by_ref[hr["ref"]] = hr
    except Exception:
        human_assist = None  # type: ignore

    for ch in corpus.challenges:
        t0 = time.time()
        res = BenchmarkResult(challenge_id=ch.id, name=ch.name, category=ch.category,
                              prerequisites=ch.prerequisites, corpus_version=corpus.version,
                              run_meta=run_meta)
        ch_ref = f"bench|{corpus.suite}|{ch.id}"
        # A human already solved this offloaded challenge → count it as confirmed.
        _hr = human_by_ref.get(ch_ref)
        if _hr and _hr.get("solved"):
            res.status, res.confidence, res.reason = CONFIRMED, 1.0, "human_confirmed"
            res.evidence = [str(_hr.get("answer", ""))[:200]]
            res.duration_ms = int((time.time() - t0) * 1000)
            results.append(res); counts[res.status] = counts.get(res.status, 0) + 1
            try:
                from core.database.pg_store import BenchmarkResultRepo
                BenchmarkResultRepo.upsert(scan_id, corpus.suite, res.to_dict())
            except Exception:
                pass
            continue
        # Prerequisite gating → negative evidence (spec §19), not a false miss.
        if "second_identity" in ch.prerequisites and _identity_count(ctx) < 2:
            res.status, res.reason = NOT_APPLICABLE, "requires_second_identity"
        elif "authenticated_user" in ch.prerequisites and not _has_auth(ctx):
            res.status, res.reason = NOT_APPLICABLE, "requires_auth"
        else:
            # Challenge's canonical class set (category + name + desc + declared
            # technique), matched against findings indexed by the SAME vocabulary.
            ch_classes = _canonical_classes(
                {"category": ch.category, "name": ch.name, "description": ch.description})
            if ch.technique:
                ch_classes.add(_norm(ch.technique))
            matches = []
            for c in ch_classes:
                matches.extend(idx.get(c, []))
            # Endpoint-aware: a checklist challenge is bound to one endpoint, so a
            # finding of the right technique ON THAT endpoint = CONFIRMED, while the
            # same technique elsewhere = PARTIAL (technique present, not here).
            ep_matches = matches
            if ch.target_hint:
                hint = _ep_path(ch.target_hint)
                ep_matches = [m for m in matches
                              if hint and hint in _ep_path(str(m.get("location") or m.get("target") or ""))]
            if ep_matches:
                confirmed = [m for m in ep_matches if m.get("confirmed") or
                             str(m.get("status", "")).upper() == "CONFIRMED"]
                pick = confirmed or ep_matches
                res.confidence = max((float(m.get("confidence", 0.5) or 0.5) for m in pick), default=0.5)
                res.evidence = [str(m.get("location") or m.get("target") or "")[:200]
                                for m in pick[:3] if (m.get("location") or m.get("target"))]
                res.status = CONFIRMED if confirmed else PARTIAL
            elif matches:
                res.status, res.reason = PARTIAL, "technique found on another endpoint, not this one"
            elif not ch_classes:
                # Name/generic-only challenge (no canonical vuln class, e.g. "find the
                # hidden X page" / "publish a Y policy"): class matching can't apply, so
                # fall back to a NAME-ANCHORED match — a CONFIRMED finding whose route/
                # location/title contains the challenge-name slug. Generic (any app);
                # requires a real discovery finding, so it can't fabricate a solve.
                nm = _name_anchor_match(ch.name, findings)
                if nm:
                    res.status, res.confidence = CONFIRMED, 0.6
                    res.evidence = [str(nm.get("location") or nm.get("target") or nm.get("title") or "")[:200]]
                    res.reason = "name-anchored discovery finding"
                else:
                    res.status, res.reason = NOT_FOUND, "no matching confirmed finding"
            else:
                res.status, res.reason = NOT_FOUND, "no matching confirmed finding"
        res.duration_ms = int((time.time() - t0) * 1000)
        results.append(res)
        counts[res.status] = counts.get(res.status, 0) + 1
        try:
            from core.database.pg_store import BenchmarkResultRepo
            BenchmarkResultRepo.upsert(scan_id, corpus.suite, res.to_dict())
        except Exception:
            pass
        if res.status == CONFIRMED:
            _bb_post(scan_id, "note", f"Benchmark challenge solved: {ch.name}",
                     {"challenge_id": ch.id, "category": ch.category,
                      "technique": ch.technique, "evidence": res.evidence},
                     ref=f"bench|{corpus.suite}|{ch.id}")
        elif res.status in (NOT_FOUND, NOT_APPLICABLE) and human_assist and \
                human_assist.enabled() and ch_ref not in human_by_ref:
            # Offload what automation couldn't solve to a human (spec: keep a
            # human in the loop for non-DAST / manual / blocked challenges).
            human_assist.request(
                scan_id,
                f"Solve challenge '{ch.name}' [{ch.category}] on the target and mark "
                f"it solved (reason: {res.reason or res.status}).",
                kind="assist", ref=ch_ref,
                context={"challenge_id": ch.id, "name": ch.name, "category": ch.category,
                         "status": res.status, "reason": res.reason})

    total = len(corpus.challenges)
    confirmed = counts.get(CONFIRMED, 0)
    applicable = total - counts.get(NOT_APPLICABLE, 0)
    summary = {
        "suite": corpus.suite, "version": corpus.version,
        "total": total, "applicable": applicable, "confirmed": confirmed,
        "partial": counts.get(PARTIAL, 0), "not_found": counts.get(NOT_FOUND, 0),
        "not_applicable": counts.get(NOT_APPLICABLE, 0), "blocked": counts.get(BLOCKED, 0),
        "coverage_pct": round(100.0 * confirmed / applicable, 1) if applicable else 0.0,
        "run_meta": run_meta,
    }
    _bb_post(scan_id, "note",
             f"Benchmark scored: {confirmed}/{applicable} confirmed ({summary['coverage_pct']}%)",
             summary)
    logger.info("[benchmark] %s/%s: %s", corpus.suite, corpus.version, summary)
    return summary


def _build_run_meta(scan_id: str) -> Dict[str, Any]:
    """Reproducibility metadata (spec §25)."""
    meta: Dict[str, Any] = {
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_mode": os.getenv("NEO_SCAN_MODE", "coverage"),
        "scan_profile": os.getenv("NEO_SCAN_PROFILE", "standard"),
    }
    try:
        import json
        for src in ("patt", "nuclei"):
            p = os.path.join(os.getenv("PAYLOAD_CACHE_DIR", os.path.join("data", "payloads")),
                             f"{src}_manifest.json")
            with open(p, "r", encoding="utf-8") as f:
                meta[f"{src}_commit"] = (json.load(f) or {}).get("commit", "")
    except Exception:
        pass
    return meta
