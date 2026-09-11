
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _yaml_str(value: str) -> str:
    if value is None:
        return '""'
    try:
        import yaml
        # Force double-quoted style so multi-line finding fields collapse safely.
        return yaml.dump(str(value), default_style='"',
                          default_flow_style=True).rstrip("\n... \n").rstrip()
    except Exception:
        s = str(value).replace("\\", "\\\\").replace('"', '\\"')
        s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return f'"{s}"'


class NucleiTemplateGenerator:

    def __init__(self, output_dir: str = None, scan_id: str = None):
        from core.common.reports_config import reports_enabled, reports_dir
        self._reports_enabled = reports_enabled()
        self.scan_id = scan_id  # when set, templates are persisted to Postgres
        if output_dir is None:
            output_dir = str(reports_dir() / "custom_templates")
        self.output_dir = Path(output_dir)
        if self._reports_enabled:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated: List[str] = []

    def _safe_id(self, text: str) -> str:
        safe = re.sub(r'[^a-z0-9-]', '-', text.lower())
        safe = re.sub(r'-+', '-', safe).strip('-')[:60]
        return safe or "custom-check"

    def _severity_map(self, severity: str) -> str:
        return (severity or "info").lower()

    def _extract_path(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            return parsed.path or "/"
        except Exception:
            return "/"

    def generate_missing_header_template(self, finding: Dict) -> Optional[str]:
        title = finding.get("title", "")
        header_match = re.search(r'(?:missing\s+)?(\S+(?:-\S+)*)\s*header', title, re.IGNORECASE)
        if not header_match:
            return None

        header_name = header_match.group(1).strip()
        template_id = self._safe_id(f"custom-missing-{header_name}")

        template = f"""id: {template_id}

info:
  name: Missing {header_name} Header
  author: antigravity-scanner
  severity: {self._severity_map(finding.get('severity', 'LOW'))}
  description: |
    The {header_name} security header is not present in the HTTP response.
    {finding.get('details', '')}
  remediation: |
    {finding.get('remediation', f'Add the {header_name} header to all HTTP responses.')}
  tags: custom,header,security,misconfig
  classification:
    cwe-id: {finding.get('cwe_id', 'CWE-693')}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 301
          - 302
      - type: word
        part: header
        words:
          - "{header_name.lower()}"
        negative: true
"""
        return template

    def generate_info_disclosure_template(self, finding: Dict) -> Optional[str]:
        target = finding.get("target") or finding.get("location") or ""
        path = self._extract_path(target)
        title = finding.get("title", "Information Disclosure")
        template_id = self._safe_id(f"custom-disclosure-{title[:30]}")

        proof = finding.get("proof", "")
        match_words = []
        if proof:
            # Extract key phrases from proof for matching
            for word in proof.split()[:5]:
                clean = re.sub(r'[^\w.-]', '', word)
                if len(clean) >= 4:
                    match_words.append(clean)

        if not match_words:
            match_words = ["error", "exception", "stack trace"]

        words_yaml = "\n".join(f'          - "{w}"' for w in match_words[:3])

        template = f"""id: {template_id}

info:
  name: "{title}"
  author: antigravity-scanner
  severity: {self._severity_map(finding.get('severity', 'MEDIUM'))}
  description: |
    {finding.get('details', 'Information disclosure detected.')}
  tags: custom,disclosure,exposure

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
{words_yaml}
        condition: or
"""
        return template

    def generate_endpoint_check_template(self, finding: Dict) -> Optional[str]:
        target = finding.get("target") or finding.get("location") or ""
        path = self._extract_path(target)
        if path == "/":
            return None

        title = finding.get("title", "Exposed Endpoint")
        template_id = self._safe_id(f"custom-endpoint-{path}")

        template = f"""id: {template_id}

info:
  name: "{title}"
  author: antigravity-scanner
  severity: {self._severity_map(finding.get('severity', 'MEDIUM'))}
  description: |
    {finding.get('details', 'Exposed endpoint detected.')}
  tags: custom,exposure,panel

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 301
          - 302
      - type: word
        words:
          - "<html"
          - "<body"
          - "{{"
        condition: or
        part: body
"""
        return template

    def generate_default_creds_template(self, finding: Dict) -> Optional[str]:
        target = finding.get("target") or finding.get("location") or ""
        path = self._extract_path(target)
        title = finding.get("title", "")

        # Try to extract username from title
        cred_match = re.search(r"(?:credentials?|login).*?['\"]?(\w+)['\"]?\s*(?:@|at|on)", title, re.IGNORECASE)
        username = cred_match.group(1) if cred_match else "admin"

        template_id = self._safe_id(f"custom-default-login-{username}")

        template = f"""id: {template_id}

info:
  name: "Default Credentials: {username}"
  author: antigravity-scanner
  severity: critical
  description: |
    Default or weak credentials detected for user '{username}'.
    {finding.get('details', '')}
  remediation: |
    Change default credentials immediately and enforce strong password policies.
  tags: custom,default-login,credentials
  classification:
    cwe-id: CWE-798

http:
  - raw:
      - |
        POST {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: application/x-www-form-urlencoded

        username={username}&password=admin
      - |
        POST {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: application/x-www-form-urlencoded

        username={username}&password=password
      - |
        POST {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: application/x-www-form-urlencoded

        username={username}&password={username}

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 302
      - type: word
        words:
          - "dashboard"
          - "welcome"
          - "logout"
          - "session"
        condition: or
        part: body
      - type: word
        words:
          - "invalid"
          - "incorrect"
          - "failed"
          - "error"
        negative: true
        condition: and
        part: body
"""
        return template

    def generate_cors_template(self, finding: Dict) -> Optional[str]:
        target = finding.get("target") or finding.get("location") or ""
        path = self._extract_path(target)
        template_id = self._safe_id(f"custom-cors-{path}")

        template = f"""id: {template_id}

info:
  name: CORS Misconfiguration
  author: antigravity-scanner
  severity: {self._severity_map(finding.get('severity', 'MEDIUM'))}
  description: |
    {finding.get('details', 'Permissive CORS policy detected.')}
  tags: custom,cors,misconfig
  classification:
    cwe-id: CWE-942

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    headers:
      Origin: "https://evil.com"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Origin: *"
          - "Access-Control-Allow-Credentials: true"
        condition: or
"""
        return template

    def generate_from_finding(self, finding: Dict) -> Optional[str]:
        vuln_type = (finding.get("type") or "").upper()
        title_lower = (finding.get("title") or "").lower()

        if vuln_type == "MISSING_HEADER" or "missing" in title_lower and "header" in title_lower:
            return self.generate_missing_header_template(finding)
        elif vuln_type in ("INFORMATION_DISCLOSURE", "INFO_DISCLOSURE", "DIRECTORY_LISTING"):
            return self.generate_info_disclosure_template(finding)
        elif vuln_type == "DEFAULT_CREDENTIALS" or "default cred" in title_lower:
            return self.generate_default_creds_template(finding)
        elif vuln_type in ("CORS_MISCONFIGURATION", "CORS"):
            return self.generate_cors_template(finding)
        elif vuln_type in ("NUCLEI_MATCH",):
            return None  # Already has a template
        else:
            return self.generate_endpoint_check_template(finding)

    def generate_all(self, findings: List[Dict], max_templates: int = 50) -> List[str]:
        generated_paths = []
        seen_ids = set()
        count = 0

        for f in findings:
            if count >= max_templates:
                break

            template_content = self.generate_from_finding(f)
            if not template_content:
                continue

            # Extract template ID
            id_match = re.search(r'^id:\s*(.+)$', template_content, re.MULTILINE)
            template_id = id_match.group(1).strip() if id_match else f"custom-{count}"

            if template_id in seen_ids:
                continue
            seen_ids.add(template_id)

            filename = f"{template_id}.yaml"
            # DB path (default when reports/ is disabled)
            if not self._reports_enabled and self.scan_id:
                try:
                    from core.database.pg_store import ScanArtifactRepo
                    aid = ScanArtifactRepo.insert(
                        self.scan_id, "nuclei_template", filename,
                        template_content, mime_type="application/yaml",
                        metadata={"template_id": template_id})
                    generated_paths.append(f"db:scan_artifacts:{aid}")
                    count += 1
                except Exception as e:
                    logger.warning(f"[TemplateGen] DB persist failed for {filename}: {e}")
            elif self._reports_enabled:
                filepath = self.output_dir / filename
                try:
                    filepath.write_text(template_content, encoding="utf-8")
                    generated_paths.append(str(filepath))
                    count += 1
                except Exception as e:
                    logger.warning(f"[TemplateGen] Failed to write {filename}: {e}")

        self.generated = generated_paths
        logger.info(f"[TemplateGen] Generated {len(generated_paths)} custom nuclei templates in {self.output_dir}")
        return generated_paths

    def get_template_dir(self) -> str:
        return str(self.output_dir)
