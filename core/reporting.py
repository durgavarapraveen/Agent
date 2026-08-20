"""
Enterprise Reporting (Phase 4, Module 1)

Produces a self-contained professional HTML report (PDF if a renderer is
available) from SharedContext:
  - Executive summary + technical details
  - Attack-path visualization (inline SVG)
  - MITRE ATT&CK heatmap
  - Risk scoring + remediation guidance

No external template/runtime dependencies; the HTML is fully self-contained.
"""

import html
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SEV_WEIGHT = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0, "INFO": 0.2}
SEV_COLOR = {"CRITICAL": "#b00020", "HIGH": "#d9531e", "MEDIUM": "#c9a227",
             "LOW": "#2e7d32", "INFO": "#607d8b"}

# ATT&CK tactic column order for the heatmap
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


class EnterpriseReporter:
    """Builds enterprise-grade HTML/PDF reports from a SharedContext."""

    def __init__(self, ctx, report_dir: str = "reports"):
        self.ctx = ctx
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)

    # ── risk scoring ──

    def risk_score(self) -> Dict:
        """Aggregate risk score (0-100) from vulnerability severities."""
        counts = {k: 0 for k in SEV_WEIGHT}
        for v in self.ctx.vulnerabilities:
            sev = str(v.get("severity", "MEDIUM")).upper()
            counts[sev] = counts.get(sev, 0) + 1
        raw = sum(SEV_WEIGHT.get(s, 0) * n for s, n in counts.items())
        # Normalize with diminishing returns
        score = min(100.0, raw)
        rating = ("CRITICAL" if score >= 80 else "HIGH" if score >= 50
                  else "MEDIUM" if score >= 20 else "LOW")
        # Floor the rating by the worst single finding: one CRITICAL is never
        # an overall "LOW" risk regardless of the aggregate score.
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        floor = "LOW"
        if counts.get("CRITICAL"):
            floor = "HIGH"
        elif counts.get("HIGH"):
            floor = "MEDIUM"
        if order.index(rating) < order.index(floor):
            rating = floor
        return {"score": round(score, 1), "rating": rating, "counts": counts}

    # ── HTML sections ──

    def _bar(self, counts: Dict[str, int]) -> str:
        total = max(1, sum(counts.values()))
        segs = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            if n:
                pct = 100 * n / total
                segs.append(
                    f'<div style="width:{pct:.1f}%;background:{SEV_COLOR[sev]};" '
                    f'title="{sev}: {n}">{n}</div>')
        return f'<div class="bar">{"".join(segs)}</div>'

    def _vuln_table(self) -> str:
        rows = []
        for v in sorted(self.ctx.vulnerabilities,
                        key=lambda x: SEV_WEIGHT.get(str(x.get("severity", "")).upper(), 0),
                        reverse=True):
            sev = str(v.get("severity", "MEDIUM")).upper()
            rows.append(
                f"<tr>"
                f'<td><span class="pill" style="background:{SEV_COLOR.get(sev,"#777")}">{html.escape(sev)}</span></td>'
                f"<td>{html.escape(str(v.get('id','')))}</td>"
                f"<td>{html.escape(str(v.get('title', v.get('type',''))))}</td>"
                f"<td>{html.escape(str(v.get('location','')))}</td>"
                f"<td>{html.escape(str(v.get('details',''))[:300])}</td>"
                f"</tr>")
        if not rows:
            rows.append('<tr><td colspan="5">No vulnerabilities recorded.</td></tr>')
        return ("<table><thead><tr><th>Severity</th><th>ID</th><th>Title</th>"
                "<th>Location</th><th>Details</th></tr></thead><tbody>"
                + "".join(rows) + "</tbody></table>")

    def _attack_path_svg(self) -> str:
        """Render attack chains as a horizontal node-arrow SVG."""
        chains = self.ctx.attack_chains or []
        if not chains:
            return "<p class='muted'>No multi-step attack chains identified.</p>"
        svg_blocks = []
        for ci, chain in enumerate(chains[:6]):
            steps = chain.get("steps") or chain.get("path") or []
            if isinstance(steps, dict):
                steps = list(steps.values())
            labels = []
            for s in steps:
                if isinstance(s, dict):
                    labels.append(str(s.get("type") or s.get("vuln_id") or s.get("title") or "?"))
                else:
                    labels.append(str(s))
            if not labels:
                continue
            w = 20 + len(labels) * 170
            nodes = []
            for i, lab in enumerate(labels):
                x = 20 + i * 170
                nodes.append(
                    f'<rect x="{x}" y="25" rx="6" width="140" height="40" '
                    f'fill="#1e3a5f" stroke="#3d6ea5"/>'
                    f'<text x="{x+70}" y="50" fill="#fff" font-size="12" '
                    f'text-anchor="middle">{html.escape(lab[:18])}</text>')
                if i < len(labels) - 1:
                    ax = x + 140
                    nodes.append(
                        f'<line x1="{ax}" y1="45" x2="{ax+30}" y2="45" '
                        f'stroke="#3d6ea5" stroke-width="2" marker-end="url(#arw)"/>')
            svg_blocks.append(
                f'<div class="chain"><b>Chain #{ci+1}</b> '
                f'(score {chain.get("score","?")})'
                f'<svg width="{w}" height="90" xmlns="http://www.w3.org/2000/svg">'
                f'<defs><marker id="arw" markerWidth="8" markerHeight="8" refX="6" refY="3" '
                f'orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#3d6ea5"/></marker></defs>'
                f'{"".join(nodes)}</svg></div>')
        return "".join(svg_blocks) or "<p class='muted'>No renderable chains.</p>"

    def _mitre_heatmap(self) -> str:
        mappings = self.ctx.mitre_mappings or []
        if not mappings:
            return "<p class='muted'>No ATT&CK techniques mapped.</p>"
        by_tactic: Dict[str, List[Dict]] = {}
        for m in mappings:
            by_tactic.setdefault(m.get("tactic", "Unknown"), []).append(m)
        cols = [t for t in TACTIC_ORDER if t in by_tactic]
        cols += [t for t in by_tactic if t not in cols]
        cells = []
        for t in cols:
            techs = by_tactic[t]
            intensity = min(1.0, len(techs) / 4.0)
            bg = f"rgba(176,0,32,{0.25 + 0.6*intensity:.2f})"
            items = "".join(
                f'<div class="tech" title="{html.escape(m.get("detection",""))}">'
                f'{html.escape(m.get("technique_id",""))} '
                f'{html.escape(m.get("name","")[:22])}</div>' for m in techs)
            cells.append(
                f'<div class="tcol"><div class="thead" style="background:{bg}">'
                f'{html.escape(t)} ({len(techs)})</div>{items}</div>')
        return f'<div class="heatmap">{"".join(cells)}</div>'

    def _remediation(self) -> str:
        rem = {
            "CRITICAL": "Immediate remediation required (patch/disable within 24-48h).",
            "HIGH": "Remediate in the current sprint; add compensating controls now.",
            "MEDIUM": "Schedule remediation; monitor for exploitation.",
            "LOW": "Track and remediate opportunistically.",
        }
        seen = {}
        for v in self.ctx.vulnerabilities:
            sev = str(v.get("severity", "MEDIUM")).upper()
            seen.setdefault(sev, []).append(v.get("title", v.get("type", "?")))
        blocks = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in seen:
                items = "".join(f"<li>{html.escape(str(t))}</li>" for t in seen[sev][:15])
                blocks.append(
                    f'<h4 style="color:{SEV_COLOR[sev]}">{sev} — {rem[sev]}</h4>'
                    f"<ul>{items}</ul>")
        return "".join(blocks) or "<p class='muted'>No remediation items.</p>"

    # ── build ──

    def build_html(self, executive_summary: str = "") -> str:
        risk = self.risk_score()
        meta_rows = (
            f"<tr><td>Target</td><td>{html.escape(str(self.ctx.target))}</td></tr>"
            f"<tr><td>Generated</td><td>{datetime.now().isoformat(timespec='seconds')}</td></tr>"
            f"<tr><td>Vulnerabilities</td><td>{len(self.ctx.vulnerabilities)}</td></tr>"
            f"<tr><td>Exploits run</td><td>{len(self.ctx.exploit_results)}</td></tr>"
            f"<tr><td>Agents</td><td>{len(self.ctx.agents_spawned)}</td></tr>"
        )
        exec_html = html.escape(executive_summary).replace("\n", "<br>") or \
            "<span class='muted'>No executive summary provided.</span>"
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Penetration Test Report — {html.escape(str(self.ctx.target))}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f5f6f8;color:#1c2430}}
 header{{background:#12233b;color:#fff;padding:28px 40px}}
 header h1{{margin:0;font-size:22px}} header .sub{{opacity:.8;font-size:13px}}
 main{{max-width:1100px;margin:0 auto;padding:24px 40px}}
 section{{background:#fff;border:1px solid #e2e6ec;border-radius:8px;padding:20px 24px;margin:18px 0}}
 h2{{font-size:17px;border-bottom:2px solid #12233b;padding-bottom:6px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #eef1f4;vertical-align:top}}
 th{{background:#f0f3f7}}
 .pill,.score{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
 .bar{{display:flex;height:26px;border-radius:5px;overflow:hidden;font-size:11px}}
 .bar div{{display:flex;align-items:center;justify-content:center;color:#fff}}
 .scorebox{{font-size:40px;font-weight:700}}
 .muted{{color:#8a94a3}} .chain{{margin:12px 0;overflow-x:auto}}
 .heatmap{{display:flex;gap:8px;overflow-x:auto}} .tcol{{min-width:150px}}
 .thead{{color:#fff;font-size:12px;font-weight:600;padding:6px;border-radius:5px;text-align:center}}
 .tech{{background:#eef1f4;margin:4px 0;padding:5px 6px;border-radius:4px;font-size:11px}}
</style></head><body>
<header><h1>Penetration Test Report</h1>
 <div class="sub">{html.escape(str(self.ctx.target))} · generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
</header><main>
 <section><h2>Risk Overview</h2>
  <p><span class="score" style="background:{SEV_COLOR.get(risk['rating'],'#777')}">
   Overall risk: {risk['rating']}</span> &nbsp; <span class="scorebox">{risk['score']}</span><span class="muted">/100</span></p>
  {self._bar(risk['counts'])}
  <table>{meta_rows}</table>
 </section>
 <section><h2>Executive Summary</h2><p>{exec_html}</p></section>
 <section><h2>Findings</h2>{self._vuln_table()}</section>
 <section><h2>Attack Path Visualization</h2>{self._attack_path_svg()}</section>
 <section><h2>MITRE ATT&amp;CK Heatmap</h2>{self._mitre_heatmap()}</section>
 <section><h2>Remediation</h2>{self._remediation()}</section>
</main></body></html>"""

    def generate(self, executive_summary: str = "", stem: str = "") -> Dict[str, str]:
        """Write HTML (and PDF if a renderer is available). Returns paths."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = stem or f"report_{ts}"
        html_str = self.build_html(executive_summary)
        html_path = self.report_dir / f"{stem}.html"
        html_path.write_text(html_str, encoding="utf-8")
        logger.info(f"[Report] HTML report written: {html_path}")

        out = {"html": str(html_path)}
        pdf_path = self.report_dir / f"{stem}.pdf"
        try:
            from weasyprint import HTML as _WHTML   # optional dependency
            _WHTML(string=html_str).write_pdf(str(pdf_path))
            out["pdf"] = str(pdf_path)
            logger.info(f"[Report] PDF report written: {pdf_path}")
        except Exception as e:      # noqa: BLE001
            logger.info(f"[Report] PDF skipped (install 'weasyprint' to enable): {e}")
        return out
