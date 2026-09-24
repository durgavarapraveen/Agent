"""Attack-path evaluation harness (spec Phase 37/38/44).

The existing recall harness scores findings by vulnerability *class*. The spec's
key metric is different: the number of correctly **validated attack paths**, not
scanners run or findings counted. This harness scores a scan result against a
labeled ground truth and reports the full metric suite centred on
``validated_attack_paths``.

It reuses the pieces built this session:
- structural finding matching (endpoint path + class + parameter) rather than by
  the free-text title;
- the finding lifecycle to measure validated / exploited rates;
- the impact engine to score impact-validation accuracy;
- the forward AttackPathEngine to construct paths when the result carries none.

Everything is deterministic and offline: a ground truth plus a scan result in,
metrics out. A built-in synthetic corpus covers the spec's vulnerability classes
so the harness is runnable without a live target; pointing the scanner at a real
authorized deployment and feeding its ctx here is the integration point.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from urllib.parse import urlsplit

from core.domain.finding_lifecycle import (
    FindingLifecycle, infer_lifecycle, rank as lifecycle_rank,
)
from core.validation.recall_harness import _norm_class


def _endpoint_key(loc: str) -> str:
    """scheme://host/path (no query), lowercased. The parameter is matched as a
    separate key dimension, so the query is deliberately dropped here."""
    loc = (loc or "").split("#", 1)[0].strip()
    try:
        s = urlsplit(loc if "://" in loc else "http://" + loc)
        if not s.scheme or not s.netloc:
            return loc.lower()
        return f"{s.scheme}://{s.netloc}{s.path}".lower().rstrip("/")
    except ValueError:
        return loc.lower()


# ── ground-truth models ─────────────────────────────────────────────────
@dataclass
class ExpectedFinding:
    id: str
    vuln_class: str
    location: str = ""
    parameter: str = ""
    expected_impact: str = "LOW_IMPACT_PROVEN"
    min_lifecycle: str = "VALIDATED"

    def key(self):
        return (_norm_class(self.vuln_class),
                _endpoint_key(self.location),
                (self.parameter or "").lower())


@dataclass
class ExpectedPath:
    id: str
    technique_sequence: List[str]           # ordered vuln classes
    target_host: str = ""
    min_status: str = "hypothesized"        # hypothesized|exploited|impact_confirmed


@dataclass
class GroundTruth:
    target: str
    expected_findings: List[ExpectedFinding] = field(default_factory=list)
    expected_paths: List[ExpectedPath] = field(default_factory=list)


@dataclass
class AttackPathEvalReport:
    target: str
    # findings
    expected_findings: int = 0
    matched_findings: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    finding_recall: float = 0.0
    finding_precision: float = 0.0
    finding_f1: float = 0.0
    validated_vuln_rate: float = 0.0
    exploit_validation_rate: float = 0.0
    impact_accuracy: float = 0.0
    evidence_quality: float = 0.0
    # attack paths (the headline)
    expected_paths: int = 0
    attack_paths_discovered: int = 0
    attack_path_discovery_rate: float = 0.0
    validated_attack_paths: int = 0
    # cost (passthrough)
    cost: Dict[str, Any] = field(default_factory=dict)
    misses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        for k in ("finding_recall", "finding_precision", "finding_f1",
                  "validated_vuln_rate", "exploit_validation_rate",
                  "impact_accuracy", "evidence_quality",
                  "attack_path_discovery_rate"):
            d[k] = round(d[k], 4)
        return d


# ── matching helpers ────────────────────────────────────────────────────
def _finding_key(f: Dict[str, Any]):
    cls = _norm_class(f.get("type") or f.get("vuln_class") or f.get("vuln_type") or "")
    loc = _endpoint_key(f.get("location") or f.get("url") or f.get("target") or "")
    param = (f.get("parameter") or f.get("param") or "").lower()
    return (cls, loc, param)


def _paths_from_result(scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    paths = scan_result.get("attack_paths")
    if paths:
        return paths
    chains = scan_result.get("attack_chains")
    if isinstance(chains, dict):
        chains = list(chains.values())
    if isinstance(chains, list) and chains:
        return chains
    # Build them from findings with the forward engine.
    try:
        from core.attack_surface.attack_path_engine import AttackPathEngine
        return AttackPathEngine(scan_result.get("vulnerabilities", []) or []).generate()
    except Exception:
        return []


def _path_classes(path: Dict[str, Any]) -> List[str]:
    steps = path.get("steps") or []
    out = []
    for s in steps:
        if isinstance(s, dict):
            v = s.get("action") or s.get("type") or s.get("title") or ""
        else:
            v = str(s)
        n = _norm_class(v)
        if n:
            out.append(n)
    return out


def _is_subsequence(needle: List[str], hay: List[str]) -> bool:
    it = iter(hay)
    return all(any(n == h for h in it) for n in needle)


_STATUS_ORDER = {"hypothesized": 0, "exploited": 1, "impact_confirmed": 2}


# ── evaluation ──────────────────────────────────────────────────────────
def evaluate(scan_result: Dict[str, Any], gt: GroundTruth) -> AttackPathEvalReport:
    findings = scan_result.get("vulnerabilities", []) or []
    rep = AttackPathEvalReport(target=gt.target)
    rep.cost = scan_result.get("cost", {}) or {}

    # ── findings: match expected by canonical key ──
    found_by_key: Dict[Any, Dict[str, Any]] = {}
    for f in findings:
        found_by_key.setdefault(_finding_key(f), f)

    rep.expected_findings = len(gt.expected_findings)
    matched_expected_keys = set()
    impact_hits = 0
    for ef in gt.expected_findings:
        hit = found_by_key.get(ef.key())
        if hit is not None:
            rep.matched_findings += 1
            matched_expected_keys.add(ef.key())
            # impact accuracy: predicted vs expected impact level
            from core.verification.impact_engine import assess_impact
            pred, _ = assess_impact(hit)
            if pred.value == ef.expected_impact:
                impact_hits += 1
        else:
            rep.false_negatives += 1
            rep.misses.append(f"{ef.id}: {ef.vuln_class} @ {ef.location}")

    expected_keys = {ef.key() for ef in gt.expected_findings}
    rep.false_positives = sum(1 for k in found_by_key if k not in expected_keys)

    rep.finding_recall = (rep.matched_findings / rep.expected_findings
                          if rep.expected_findings else 0.0)
    total_found = len(found_by_key)
    rep.finding_precision = (rep.matched_findings / total_found if total_found else 0.0)
    if rep.finding_recall + rep.finding_precision:
        rep.finding_f1 = (2 * rep.finding_recall * rep.finding_precision /
                          (rep.finding_recall + rep.finding_precision))
    rep.impact_accuracy = (impact_hits / rep.matched_findings
                           if rep.matched_findings else 0.0)

    # ── lifecycle-based rates over matched findings ──
    matched_findings = [found_by_key[k] for k in matched_expected_keys]
    if matched_findings:
        val = sum(1 for f in matched_findings
                  if lifecycle_rank(infer_lifecycle(f)) >= lifecycle_rank(FindingLifecycle.VALIDATED))
        exp = sum(1 for f in matched_findings
                  if lifecycle_rank(infer_lifecycle(f)) >= lifecycle_rank(FindingLifecycle.EXPLOITED))
        ev = sum(1 for f in matched_findings if f.get("proof") or f.get("evidence"))
        rep.validated_vuln_rate = val / len(matched_findings)
        rep.exploit_validation_rate = exp / len(matched_findings)
        rep.evidence_quality = ev / len(matched_findings)

    # ── attack paths (headline) ──
    produced = _paths_from_result(scan_result)
    rep.attack_paths_discovered = len(produced)
    rep.expected_paths = len(gt.expected_paths)
    produced_classes = [( _path_classes(p), p) for p in produced]
    matched_paths = 0
    validated_paths = 0
    for ep in gt.expected_paths:
        seq = [_norm_class(c) for c in ep.technique_sequence]
        need = _STATUS_ORDER.get(ep.min_status, 0)
        best = None
        for classes, p in produced_classes:
            if _is_subsequence(seq, classes):
                best = p
                break
        if best is not None:
            matched_paths += 1
            if _STATUS_ORDER.get(str(best.get("status", "hypothesized")), 0) >= need:
                validated_paths += 1
        else:
            rep.misses.append(f"path {ep.id}: {' → '.join(ep.technique_sequence)}")
    rep.attack_path_discovery_rate = (matched_paths / rep.expected_paths
                                      if rep.expected_paths else 0.0)
    rep.validated_attack_paths = validated_paths
    return rep


# ── built-in ground-truth corpus (spec Phase 37 class coverage) ─────────
def default_ground_truths() -> List[GroundTruth]:
    """Labeled targets covering the spec's classes. The locations are template
    placeholders — replace with a real authorized deployment's URLs to run live.
    """
    base = "https://target.example"
    return [GroundTruth(
        target=base,
        expected_findings=[
            ExpectedFinding("f_sqli", "SQLI", f"{base}/api/users", "id",
                            "RESOURCE_ACCESS_PROVEN", "EXPLOITED"),
            ExpectedFinding("f_xss", "XSS", f"{base}/search", "q",
                            "LOW_IMPACT_PROVEN", "EXPLOITED"),
            ExpectedFinding("f_idor", "IDOR", f"{base}/api/orders", "order_id",
                            "RESOURCE_ACCESS_PROVEN", "VALIDATED"),
            ExpectedFinding("f_ssrf", "SSRF", f"{base}/fetch", "url",
                            "RESOURCE_ACCESS_PROVEN", "VALIDATED"),
            ExpectedFinding("f_authz", "AUTHZ", f"{base}/admin", "",
                            "PRIVILEGE_PROVEN", "VALIDATED"),
            ExpectedFinding("f_redir", "OPEN_REDIRECT", f"{base}/go", "next",
                            "NO_IMPACT_PROVEN", "SUSPECTED"),
            ExpectedFinding("f_secret", "INFO_DISCLOSURE", f"{base}/.env", "",
                            "SENSITIVE_DATA_ACCESS_PROVEN", "IMPACT_CONFIRMED"),
        ],
        expected_paths=[
            ExpectedPath("p_sqli_data", ["sqli"], target_host="target.example"),
            ExpectedPath("p_cred_privesc", ["info_disclosure", "authz"],
                         target_host="target.example"),
            ExpectedPath("p_idor_data", ["idor"], target_host="target.example"),
        ],
    )]
