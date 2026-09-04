"""
ASMMonitor — attack-surface snapshot + delta engine for continuous monitoring.

A snapshot is a normalized, comparable view of everything the scan discovered:
subdomains, IPs, host:port services, endpoints/URLs, technologies, security
headers, TLS posture, and finding fingerprints. Snapshots are persisted per
target under data/asm/<target>/, and each new snapshot is diffed against the
previous one to produce an ASMDelta describing what changed since last time.

This is the core of the continuous-monitoring product feature: schedule repeated
runs and surface only the deltas instead of a full report every cycle.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_ASM_ROOT = Path("data/asm")


def _slug(target: str) -> str:
    s = re.sub(r"^https?://", "", str(target or "unknown")).strip("/")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return s or "unknown"


def _finding_fp(v: Dict[str, Any]) -> str:
    key = "|".join([
        str(v.get("type") or v.get("vuln_type") or "").upper(),
        str(v.get("title") or "").lower().strip(),
        str(v.get("location") or v.get("target") or v.get("affected_endpoint") or "").lower(),
        str(v.get("cve_id") or "").upper(),
    ])
    return hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()[:16]


@dataclass
class ASMDelta:
    target: str
    timestamp: str
    is_first_run: bool = False
    new_subdomains: List[str] = field(default_factory=list)
    removed_subdomains: List[str] = field(default_factory=list)
    new_ips: List[str] = field(default_factory=list)
    removed_ips: List[str] = field(default_factory=list)
    new_services: List[str] = field(default_factory=list)       # host:port
    removed_services: List[str] = field(default_factory=list)
    new_endpoints: List[str] = field(default_factory=list)
    removed_endpoints: List[str] = field(default_factory=list)
    new_technologies: List[str] = field(default_factory=list)
    removed_technologies: List[str] = field(default_factory=list)
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = field(default_factory=list)
    header_regressions: List[str] = field(default_factory=list)  # headers that disappeared

    def has_changes(self) -> bool:
        return any([
            self.new_subdomains, self.removed_subdomains, self.new_ips, self.removed_ips,
            self.new_services, self.removed_services, self.new_endpoints, self.removed_endpoints,
            self.new_technologies, self.removed_technologies, self.new_findings,
            self.resolved_findings, self.header_regressions,
        ])

    def severity(self) -> str:
        """Coarse alert level for the delta."""
        crit = [f for f in self.new_findings
                if str(f.get("severity", "")).upper() in ("HIGH", "CRITICAL")]
        if crit or self.new_services or self.header_regressions:
            return "HIGH"
        if self.new_findings or self.new_subdomains or self.new_endpoints or self.new_technologies:
            return "MEDIUM"
        if self.has_changes():
            return "LOW"
        return "NONE"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity()
        d["has_changes"] = self.has_changes()
        return d


class ASMMonitor:
    def __init__(self, root: Path = _ASM_ROOT, webhook_url: Optional[str] = None):
        self.root = Path(root)
        self.webhook_url = webhook_url
        if webhook_url is None:
            try:
                from core.common.config import get_config
                self.webhook_url = get_config().get("ASM_WEBHOOK_URL", "") or None
            except Exception:
                self.webhook_url = None

    # ----------------------------------------------------------- snapshotting

    def snapshot_from_context(self, ctx: Any) -> Dict[str, Any]:
        """Build a normalized snapshot dict from a SharedContext."""
        subdomains = sorted({str(s).lower() for s in getattr(ctx, "subdomains", []) if s})
        ips = sorted({str(i) for i in getattr(ctx, "ips", []) if i})

        services = set()
        for p in getattr(ctx, "ports", []) or []:
            if isinstance(p, dict):
                host = p.get("host") or p.get("ip") or getattr(ctx, "target", "")
                port = p.get("port") or p.get("portid")
                if port:
                    services.add(f"{host}:{port}")
            else:
                services.add(str(p))

        endpoints = set()
        raw_eps = getattr(ctx, "endpoints", {}) or {}
        ep_iter = raw_eps.keys() if isinstance(raw_eps, dict) else raw_eps
        for e in ep_iter:
            endpoints.add(str(e))
        for d in getattr(ctx, "directories", []) or []:
            endpoints.add(str(d))

        technologies = set()
        techs = getattr(ctx, "technologies", {}) or {}
        if isinstance(techs, dict):
            for host, tlist in techs.items():
                for t in (tlist or []):
                    technologies.add(str(t).lower())
        elif isinstance(techs, list):
            technologies = {str(t).lower() for t in techs}

        headers = getattr(ctx, "headers", {}) or {}
        header_keys = sorted({str(k).lower() for k in headers.keys()}) if isinstance(headers, dict) else []

        findings = {}
        for v in getattr(ctx, "vulnerabilities", []) or []:
            findings[_finding_fp(v)] = {
                "type": v.get("type") or v.get("vuln_type"),
                "title": v.get("title"),
                "severity": v.get("severity"),
                "location": v.get("location") or v.get("target"),
            }

        return {
            "target": getattr(ctx, "target", ""),
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "subdomains": subdomains,
            "ips": ips,
            "services": sorted(services),
            "endpoints": sorted(endpoints),
            "technologies": sorted(technologies),
            "header_keys": header_keys,
            "findings": findings,
        }

    def _target_dir(self, target: str) -> Path:
        d = self.root / _slug(target)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def load_latest(self, target: str) -> Optional[Dict[str, Any]]:
        latest = self._target_dir(target) / "latest.json"
        if latest.exists():
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.debug(f"[ASM] latest load error: {e}")
        return None

    def save_snapshot(self, target: str, snapshot: Dict[str, Any]) -> Path:
        d = self._target_dir(target)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = d / f"snapshot_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)
        with open(d / "latest.json", "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)
        return path

    # ------------------------------------------------------------------- diff

    def diff(self, old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> ASMDelta:
        target = new.get("target", "")
        ts = new.get("captured_at", datetime.now(timezone.utc).isoformat())
        if not old:
            return ASMDelta(
                target=target, timestamp=ts, is_first_run=True,
                new_findings=list(new.get("findings", {}).values()),
            )

        def _setdiff(key):
            o, n = set(old.get(key, [])), set(new.get(key, []))
            return sorted(n - o), sorted(o - n)

        new_sub, rem_sub = _setdiff("subdomains")
        new_ip, rem_ip = _setdiff("ips")
        new_svc, rem_svc = _setdiff("services")
        new_ep, rem_ep = _setdiff("endpoints")
        new_tech, rem_tech = _setdiff("technologies")

        old_headers, new_headers = set(old.get("header_keys", [])), set(new.get("header_keys", []))
        # A security header present before and missing now is a regression.
        security_headers = {
            "content-security-policy", "strict-transport-security", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy",
        }
        header_regressions = sorted((old_headers - new_headers) & security_headers)

        old_f, new_f = old.get("findings", {}), new.get("findings", {})
        new_findings = [new_f[k] for k in new_f.keys() - old_f.keys()]
        resolved = [old_f[k] for k in old_f.keys() - new_f.keys()]

        return ASMDelta(
            target=target, timestamp=ts, is_first_run=False,
            new_subdomains=new_sub, removed_subdomains=rem_sub,
            new_ips=new_ip, removed_ips=rem_ip,
            new_services=new_svc, removed_services=rem_svc,
            new_endpoints=new_ep, removed_endpoints=rem_ep,
            new_technologies=new_tech, removed_technologies=rem_tech,
            new_findings=new_findings, resolved_findings=resolved,
            header_regressions=header_regressions,
        )

    # --------------------------------------------------------------- reporting

    def render_delta_md(self, delta: ASMDelta) -> str:
        if delta.is_first_run:
            return (f"# ASM Baseline Established — {delta.target}\n\n"
                    f"First snapshot captured at {delta.timestamp}. "
                    f"{len(delta.new_findings)} findings recorded as baseline.\n")

        lines = [f"# ASM Delta Report — {delta.target}",
                 f"_Generated {delta.timestamp} · Alert level: **{delta.severity()}**_\n"]

        def _section(title, items, fmt=lambda x: f"- {x}"):
            if items:
                lines.append(f"## {title} ({len(items)})")
                lines.extend(fmt(i) for i in items[:50])
                lines.append("")

        _section("🆕 New Subdomains", delta.new_subdomains)
        _section("❌ Removed Subdomains", delta.removed_subdomains)
        _section("🆕 New Services (host:port)", delta.new_services)
        _section("❌ Removed Services", delta.removed_services)
        _section("🆕 New Endpoints", delta.new_endpoints)
        _section("🆕 New Technologies", delta.new_technologies)
        _section("⚠️ Security Header Regressions", delta.header_regressions)
        _section("🔴 New Findings", delta.new_findings,
                 fmt=lambda f: f"- [{f.get('severity','?')}] {f.get('title','?')} @ {f.get('location','?')}")
        _section("✅ Resolved Findings", delta.resolved_findings,
                 fmt=lambda f: f"- [{f.get('severity','?')}] {f.get('title','?')} @ {f.get('location','?')}")

        if not delta.has_changes():
            lines.append("No changes since last snapshot. Attack surface stable.\n")
        return "\n".join(lines)

    def save_delta(self, delta: ASMDelta) -> Optional[Path]:
        d = self._target_dir(delta.target)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        md_path = d / f"delta_{ts}.md"
        try:
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self.render_delta_md(delta))
            with open(d / f"delta_{ts}.json", "w", encoding="utf-8") as f:
                json.dump(delta.to_dict(), f, indent=2, default=str)
            return md_path
        except Exception as e:
            logger.error(f"[ASM] delta save error: {e}")
            return None

    async def _notify(self, delta: ASMDelta) -> None:
        if not self.webhook_url or not delta.has_changes():
            return
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self.webhook_url, json={
                    "type": "asm_delta", "severity": delta.severity(),
                    "delta": delta.to_dict(),
                })
        except Exception as e:
            logger.debug(f"[ASM] webhook notify failed: {e}")

    # --------------------------------------------------------------- top-level

    async def record_and_diff(self, ctx: Any, notify: bool = True) -> ASMDelta:
        """Snapshot the context, diff against the previous snapshot, persist, alert."""
        target = getattr(ctx, "target", "unknown")
        snapshot = self.snapshot_from_context(ctx)
        old = self.load_latest(target)
        delta = self.diff(old, snapshot)
        self.save_snapshot(target, snapshot)
        self.save_delta(delta)

        if delta.is_first_run:
            logger.info(f"[ASM] baseline established for {target}")
        elif delta.has_changes():
            logger.warning(f"[ASM] {delta.severity()} delta for {target}: "
                           f"+{len(delta.new_findings)} findings, +{len(delta.new_subdomains)} subs, "
                           f"+{len(delta.new_services)} services, {len(delta.resolved_findings)} resolved")
            if notify:
                await self._notify(delta)
        else:
            logger.info(f"[ASM] no attack-surface change for {target}")
        return delta
