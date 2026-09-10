from __future__ import annotations
import hashlib
from typing import Any, Dict, List
from urllib.parse import urlparse


def _key(v: Dict) -> str:
    from core.database.pg_store import _vuln_category, _host_only, _normalize_location
    title = str(v.get("title") or "").lower().strip()
    cat = _vuln_category(title) or "unknown"
    loc = v.get("location") or v.get("target") or ""
    host = _host_only(loc) or _normalize_location(loc)
    th = hashlib.sha1(title.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{cat}|{host}|{th}"


def compare_scans(scan_a: str, scan_b: str) -> Dict[str, Any]:
    from core.database.pg_store import VulnRepo, ScanRepo, DatabaseManager
    import psycopg2.extras

    va = VulnRepo.get_by_scan(scan_a) or []
    vb = VulnRepo.get_by_scan(scan_b) or []
    map_a = {_key(v): v for v in va}
    map_b = {_key(v): v for v in vb}

    new     = [map_b[k] for k in map_b if k not in map_a]
    resolved = [map_a[k] for k in map_a if k not in map_b]
    both = set(map_a) & set(map_b)
    regressed = []   # severity elevated in the newer scan
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for k in both:
        sa = (map_a[k].get("severity") or "INFO").upper()
        sb = (map_b[k].get("severity") or "INFO").upper()
        if order.get(sb, 0) > order.get(sa, 0):
            regressed.append({"before": map_a[k], "after": map_b[k]})

    def _brief(v):
        return {"title": v.get("title", ""),
                "severity": (v.get("severity") or "INFO").upper(),
                "location": v.get("location") or v.get("target", ""),
                "type": v.get("type", "")}

    try:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT scan_id, target, started_at FROM scans WHERE scan_id IN (%s, %s)",
                            (scan_a, scan_b))
                meta = {r["scan_id"]: dict(r) for r in cur.fetchall()}
    except Exception:
        meta = {}

    return {
        "baseline_scan": scan_a,
        "baseline_meta": meta.get(scan_a, {}),
        "current_scan": scan_b,
        "current_meta": meta.get(scan_b, {}),
        "summary": {
            "new": len(new), "resolved": len(resolved),
            "regressed": len(regressed),
            "unchanged": len(both) - len(regressed),
        },
        "new": [_brief(v) for v in new],
        "resolved": [_brief(v) for v in resolved],
        "regressed": [{"before": _brief(r["before"]), "after": _brief(r["after"])} for r in regressed],
    }
