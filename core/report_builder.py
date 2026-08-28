"""
Phase 5 Module 5.5: Custom Report Builder (core/report_builder.py)

Multi-format report generation (PDF, HTML with DataTables.js/Chart.js, JSON, Markdown)
with customizable section controls and compliance framework mapping (PCI-DSS, HIPAA).
"""

import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.reporting import MANDATORY_DISCLAIMER, mask_sensitive_data

logger = logging.getLogger(__name__)

# Compliance Framework Mappings
COMPLIANCE_MAP = {
    "PCI-DSS": {
        "SQLI": "Requirement 6.5.1: Injection flaws (SQLi)",
        "XSS": "Requirement 6.5.7: Cross-site scripting (XSS)",
        "AUTH": "Requirement 8.2: Identification and authentication management",
        "HEADER": "Requirement 6.5.10: Broken HTTP security configurations",
        "DEFAULT": "Requirement 6.5: Address common vulnerabilities in software development",
    },
    "HIPAA": {
        "SQLI": "§ 164.312(a)(1) Access Control & Data Integrity",
        "XSS": "§ 164.312(e)(1) Transmission Security & Session Integrity",
        "AUTH": "§ 164.312(d) Person or Entity Authentication",
        "HEADER": "§ 164.312(e)(2)(i) Integrity Controls",
        "DEFAULT": "§ 164.308(a)(1)(ii)(A) Risk Analysis and Management",
    }
}


class CustomReportBuilder:
    """Multi-format report generator with customization engine."""

    def __init__(self, config_path: str = "data/report_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load report_config.yaml if present."""
        default_config = {
            "sections_to_include": ["executive_summary", "findings_table", "trends", "compliance_mapping"],
            "branding_logo_path": "assets/logo.png",
            "hide_remediation_details": False,
            "compliance_frameworks": ["PCI-DSS", "HIPAA"]
        }
        if self.config_path.exists():
            try:
                import yaml
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                    default_config.update(loaded)
            except Exception as e:
                logger.warning(f"[ReportBuilder] Config load fallback: {e}")
        return default_config

    def build_compliance_mapping(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
        """Map findings to selected compliance framework requirements."""
        frameworks = self.config.get("compliance_frameworks", ["PCI-DSS", "HIPAA"])
        mapping_result = {}

        for fw in frameworks:
            fw_upper = fw.upper()
            fw_map = COMPLIANCE_MAP.get(fw_upper, COMPLIANCE_MAP.get("PCI-DSS"))
            mapped_controls = []

            for v in vulnerabilities:
                vtype = str(v.get("type") or v.get("title") or "DEFAULT").upper()
                cve = v.get("cve") or v.get("id") or "VULN"

                matched_control = fw_map.get("DEFAULT")
                for key, control_text in fw_map.items():
                    if key in vtype:
                        matched_control = control_text
                        break

                mapped_controls.append({
                    "cve_id": cve,
                    "title": v.get("title") or vtype,
                    "severity": v.get("severity", "MEDIUM"),
                    "framework": fw_upper,
                    "control": matched_control
                })

            mapping_result[fw_upper] = mapped_controls

        return mapping_result

    def export_json(self, scan_id: str, target: str, vulnerabilities: List[Dict[str, Any]], mask_sensitive: bool = True) -> str:
        """Export raw machine-readable JSON format with masked sensitive data."""
        masked_target = mask_sensitive_data(target, mask_sensitive)
        masked_findings = []

        for v in vulnerabilities:
            masked_findings.append({
                "cve": v.get("cve") or v.get("cve_id") or v.get("id", "N/A"),
                "title": mask_sensitive_data(str(v.get("title", v.get("type", ""))), mask_sensitive),
                "severity": v.get("severity", "MEDIUM"),
                "risk_score": v.get("risk_score", 5.0),
                "remediation": mask_sensitive_data(str(v.get("remediation", "")), mask_sensitive),
                "estimated_hours": v.get("estimated_hours", 4)
            })

        data = {
            "scan_id": scan_id,
            "target": masked_target,
            "scan_date": datetime.now().isoformat(),
            "mandatory_disclaimer": MANDATORY_DISCLAIMER,
            "total_findings": len(masked_findings),
            "findings": masked_findings
        }

        return json.dumps(data, indent=2)

    def export_markdown(self, scan_id: str, target: str, vulnerabilities: List[Dict[str, Any]], roadmap: List[str] = None, mask_sensitive: bool = True) -> str:
        """Export version-control friendly Markdown document (report.md)."""
        masked_target = mask_sensitive_data(target, mask_sensitive)
        lines = [
            f"# Security Assessment Report — {masked_target}",
            f"**Scan ID:** `{scan_id}`  ",
            f"**Date:** `{datetime.now().strftime('%Y-%m-%d %H:%M')}`\n",
            f"> **Disclaimer:** {MANDATORY_DISCLAIMER}\n",
            "## Executive Summary",
            f"Total validated findings: **{len(vulnerabilities)}**\n",
            "## Prioritized Remediation Roadmap"
        ]

        if roadmap:
            for item in roadmap:
                lines.append(f"- {item}")
        else:
            lines.append("- Apply standard security patches and input validation.")

        lines.extend(["\n## Validated Findings Table\n", "| Severity | CVE / ID | Title | Risk Score | Remediation |", "| --- | --- | --- | --- | --- |"])

        for v in vulnerabilities:
            sev = v.get("severity", "MEDIUM")
            cve = v.get("cve") or v.get("id") or "N/A"
            title = mask_sensitive_data(str(v.get("title", v.get("type", ""))), mask_sensitive)
            score = v.get("risk_score", 5.0)
            rem = mask_sensitive_data(str(v.get("remediation", ""))[:100], mask_sensitive)
            lines.append(f"| {sev} | {cve} | {title} | {score} | {rem} |")

        # Compliance mapping section if configured
        if "compliance_mapping" in self.config.get("sections_to_include", []):
            lines.append("\n## Compliance Mapping\n")
            comp = self.build_compliance_mapping(vulnerabilities)
            for fw, controls in comp.items():
                lines.append(f"### {fw} Control Violations")
                for c in controls:
                    lines.append(f"- **{c['cve_id']}** ({c['severity']}): {c['control']}")

        return "\n".join(lines)

    def export_html_interactive(self, scan_id: str, target: str, vulnerabilities: List[Dict[str, Any]], trend_info: Dict[str, Any] = None, mask_sensitive: bool = True) -> str:
        """Export single self-contained HTML file with DataTables.js and Chart.js integration."""
        masked_target = mask_sensitive_data(target, mask_sensitive)
        comp_mapping = self.build_compliance_mapping(vulnerabilities)

        rows = []
        for v in vulnerabilities:
            sev = str(v.get("severity", "MEDIUM")).upper()
            cve = v.get("cve") or v.get("id") or "N/A"
            title = html.escape(mask_sensitive_data(str(v.get("title", v.get("type", ""))), mask_sensitive))
            score = v.get("risk_score", 5.0)
            rem = html.escape(mask_sensitive_data(str(v.get("remediation", "")), mask_sensitive))
            hours = v.get("estimated_hours", 4)
            rows.append(
                f"<tr><td><span class='badge {sev.lower()}'>{sev}</span></td>"
                f"<td>{html.escape(str(cve))}</td><td>{title}</td><td>{score}</td>"
                f"<td>{rem}</td><td>{hours} hrs</td></tr>"
            )

        rows_html = "".join(rows) if rows else "<tr><td colspan='6'>No findings recorded.</td></tr>"

        # Chart.js counts
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulnerabilities:
            s = str(v.get("severity", "MEDIUM")).upper()
            counts[s] = counts.get(s, 0) + 1

        chart_data_json = json.dumps([counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]])

        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Interactive Security Report — {html.escape(masked_target)}</title>

  <!-- DataTables CSS/JS via CDN -->
  <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
  <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f4f6f9; color: #212529; }}
    .header {{ background: #12233b; color: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
    .disclaimer {{ background: #fff3cd; color: #856404; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: 500; }}
    .card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }}
    .badge {{ padding: 4px 8px; border-radius: 4px; color: #fff; font-size: 11px; font-weight: bold; }}
    .badge.critical {{ background: #b00020; }} .badge.high {{ background: #d9531e; }}
    .badge.medium {{ background: #c9a227; }} .badge.low {{ background: #2e7d32; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Interactive Penetration Test Report</h1>
    <div>Target: {html.escape(masked_target)} | Scan ID: {html.escape(scan_id)}</div>
  </div>

  <div class="disclaimer">
    {MANDATORY_DISCLAIMER}
  </div>

  <div class="card">
    <h2>Severity Distribution</h2>
    <div style="max-width: 400px; margin: 0 auto;">
      <canvas id="sevChart"></canvas>
    </div>
  </div>

  <div class="card">
    <h2>Interactive Findings Table</h2>
    <table id="findingsTable" class="display" style="width:100%">
      <thead>
        <tr><th>Severity</th><th>CVE / ID</th><th>Title</th><th>Risk Score</th><th>Remediation</th><th>Effort</th></tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

  <script>
    $(document).ready(function() {{
      $('#findingsTable').DataTable({{
        "pageLength": 10,
        "order": [[3, "desc"]]
      }});

      const ctx = document.getElementById('sevChart').getContext('2d');
      new Chart(ctx, {{
        type: 'doughnut',
        data: {{
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{{
            data: {chart_data_json},
            backgroundColor: ['#b00020', '#d9531e', '#c9a227', '#2e7d32']
          }}]
        }}
      }});
    }});
  </script>
</body>
</html>"""

    def export_pdf(self, scan_id: str, target: str, vulnerabilities: List[Dict[str, Any]], mask_sensitive: bool = True, output_path: str = None) -> str:
        """Generate professional PDF report using ReportLab platypus with logo injection."""
        out_file = Path(output_path) if output_path else Path(f"reports/{scan_id}/report.pdf")
        out_file.parent.mkdir(parents=True, exist_ok=True)
        masked_target = mask_sensitive_data(target, mask_sensitive)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

            doc = SimpleDocTemplate(str(out_file), pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            story = []

            # Logo injection if available
            logo_path = Path(self.config.get("branding_logo_path", "assets/logo.png"))
            if logo_path.exists():
                try:
                    img = Image(str(logo_path), width=120, height=40)
                    story.append(img)
                    story.append(Spacer(1, 10))
                except Exception as e:
                    logger.warning(f"[ReportBuilder] Logo render error: {e}")

            # Title & Header
            title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#12233b"))
            story.append(Paragraph(f"Penetration Test Report — {masked_target}", title_style))
            story.append(Paragraph(f"<b>Scan ID:</b> {scan_id} | <b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
            story.append(Spacer(1, 12))

            # Mandatory Disclaimer
            disc_style = ParagraphStyle('Disclaimer', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#856404"), backColor=colors.HexColor("#fff3cd"), borderPadding=6)
            story.append(Paragraph(f"<b>MANDATORY DISCLAIMER:</b> {MANDATORY_DISCLAIMER}", disc_style))
            story.append(Spacer(1, 14))

            # Executive Summary Section
            story.append(Paragraph("Executive Summary & Risk Prioritization", styles['Heading2']))
            story.append(Paragraph(f"Total Validated Findings: <b>{len(vulnerabilities)}</b>", styles['Normal']))
            story.append(Spacer(1, 10))

            # Table layout
            table_data = [["Severity", "CVE / ID", "Title", "Risk Score", "Effort (hrs)"]]
            for v in vulnerabilities:
                sev = str(v.get("severity", "MEDIUM")).upper()
                cve = v.get("cve") or v.get("id") or "N/A"
                title = mask_sensitive_data(str(v.get("title", v.get("type", ""))), mask_sensitive)
                score = str(v.get("risk_score", 5.0))
                hours = str(v.get("estimated_hours", 4))
                table_data.append([sev, cve, title[:40], score, hours])

            t = Table(table_data, colWidths=[70, 90, 240, 70, 70])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12233b")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(t)

            doc.build(story)
            logger.info(f"[ReportBuilder] ReportLab PDF built successfully: {out_file}")
            return str(out_file)
        except Exception as e:
            logger.warning(f"[ReportBuilder] ReportLab PDF fallback to HTML: {e}")
            html_content = self.export_html_interactive(scan_id, target, vulnerabilities, mask_sensitive=mask_sensitive)
            out_file.write_text(html_content, encoding="utf-8")
            return str(out_file)
