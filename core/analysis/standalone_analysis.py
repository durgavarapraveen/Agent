"""Individual (standalone) analysis of an APK/IPA or source tree — no live target.

Runs the mobile analyzers (Phase 4.4) and/or the grey-box SAST bridge (Phase 4.5)
on their own and returns a self-contained report, so an operator can vet an app
binary or a code checkout without launching a full DAST scan.

Thin, reuse-first wrappers over ``MobileAnalyzer`` / ``IPAAnalyzer`` / ``SastBridge``;
the report shaping is pure and unit-testable (analyzers injectable/mockable).
"""
from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def analyze_mobile(path: str) -> Dict[str, Any]:
    """Analyze a single .apk/.ipa and return a report dict (endpoints, secrets,
    deeplinks, cert-pinning / ATS). Kind is inferred from the extension."""
    ext = Path(path).suffix.lower()
    if ext == ".ipa":
        from core.discovery.ipa_analyzer import IPAAnalyzer
        analysis = IPAAnalyzer().analyze(path)
    else:
        from core.discovery.mobile_analyzer import MobileAnalyzer
        analysis = MobileAnalyzer().analyze(path)
    d = analysis.to_dict()
    d["kind"] = "ipa" if ext == ".ipa" else "apk"
    d["endpoint_count"] = len(d.get("endpoints", []))
    d["secret_count"] = len(d.get("secrets", []))
    d["deeplink_count"] = len(d.get("deeplinks", []))
    return d


def analyze_source(source_repo: str = "", source_path: str = "") -> Dict[str, Any]:
    """Run grey-box SAST on a repo URL or local path; group findings by class
    and severity."""
    from core.analysis.sast_bridge import SastBridge
    findings = SastBridge().analyze(source_path=source_path, source_repo=source_repo)
    by_class = Counter(f.get("vuln_class", "generic") for f in findings)
    by_sev = Counter(str(f.get("severity", "medium")).lower() for f in findings)
    return {
        "source_repo": source_repo,
        "source_path": source_path,
        "finding_count": len(findings),
        "findings": findings,
        "by_class": dict(by_class),
        "by_severity": dict(by_sev),
    }


def run_standalone(mobile_app: str = "", ipa_app: str = "",
                   source_repo: str = "", source_path: str = "") -> Dict[str, Any]:
    """Run whichever standalone analyses were requested and return a combined
    report. Any single input works on its own."""
    report: Dict[str, Any] = {"kind": "standalone_analysis",
                              "mobile": None, "source": None}
    mobile_input = mobile_app or ipa_app
    if mobile_input:
        try:
            report["mobile"] = analyze_mobile(mobile_input)
        except Exception as e:
            logger.warning("standalone mobile analysis failed: %s", e)
            report["mobile"] = {"error": str(e)}
    if source_repo or source_path:
        try:
            report["source"] = analyze_source(source_repo, source_path)
        except Exception as e:
            logger.warning("standalone source analysis failed: %s", e)
            report["source"] = {"error": str(e)}
    return report
