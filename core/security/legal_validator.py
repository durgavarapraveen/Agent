"""
Phase 6 Module 6.1: Automated Legal Validator (core/legal_validator.py)

Parses signed Statement of Work (SOW) / Rules of Engagement (ROE) documents,
enforces authorized target CIDRs/domains, tracks contract expiration,
and logs immutable authorization audit checks.
"""

import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


class ScopeViolationException(Exception):
    """Raised when a target IP or domain falls outside authorized legal scope."""
    pass


class LegalValidator:
    """Automated legal and scope enforcement validator."""

    def __init__(self, db_path: str = "data/authorized_scopes.sqlite", audit_log_path: str = "data/audit_trail.jsonl"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create authorized_scopes SQLite table."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS authorized_scopes (
                    scope_id TEXT PRIMARY KEY,
                    target_cidr TEXT,
                    target_domain TEXT,
                    authorization_date TEXT,
                    expiry_date TEXT,
                    document_hash TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _log_audit_event(self, event_data: Dict[str, Any]):
        """Append-only audit trail logger."""
        event_data["timestamp"] = datetime.now().isoformat()
        line = json.dumps(event_data) + "\n"
        with open(self.audit_log_path, mode="a", encoding="utf-8") as f:
            f.write(line)

    def parse_authorization_document(self, doc_path: str, scope_id: str = "scope_default") -> Dict[str, Any]:
        """
        Parse SOW or ROE authorization documents (Text, PDF, or DOCX),
        extract CIDR blocks, IPv4 addresses, domains, signing and expiry dates.
        """
        path = Path(doc_path)
        if not path.exists():
            raise FileNotFoundError(f"Authorization document not found: {doc_path}")

        raw_text = ""
        file_bytes = path.read_bytes()
        doc_hash = f"sha256:{hashlib.sha256(file_bytes).hexdigest()}"

        ext = path.suffix.lower()
        if ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(str(path))
                raw_text = "\n".join(page.extract_text() or "" for page in reader.pages)
            except Exception as e:
                logger.warning(f"[LegalValidator] PyPDF fallback: {e}")
                raw_text = file_bytes.decode("utf-8", errors="ignore")
        elif ext in [".docx", ".doc"]:
            try:
                import docx
                doc = docx.Document(str(path))
                raw_text = "\n".join(p.text for p in doc.paragraphs)
            except Exception as e:
                logger.warning(f"[LegalValidator] DOCX fallback: {e}")
                raw_text = file_bytes.decode("utf-8", errors="ignore")
        else:
            raw_text = file_bytes.decode("utf-8", errors="ignore")

        # Regex extractors
        cidr_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}\b'
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        date_pattern = r'\b\d{4}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{4}\b'

        cidrs = set(re.findall(cidr_pattern, raw_text))
        ips = set(re.findall(ip_pattern, raw_text))
        # Add single IPs as /32 CIDRs
        for ip in ips:
            if not any(ip in c for c in cidrs):
                try:
                    ipaddress.ip_address(ip)
                    cidrs.add(f"{ip}/32")
                except ValueError:
                    pass

        raw_domains = set(re.findall(domain_pattern, raw_text))
        valid_domains = set()
        ignore_exts = {".pdf", ".docx", ".txt", ".png", ".jpg", ".sqlite", ".json"}
        for d in raw_domains:
            if not any(d.lower().endswith(ie) for ie in ignore_exts):
                valid_domains.add(d.lower())

        dates = re.findall(date_pattern, raw_text)
        auth_date = datetime.now().strftime("%Y-%m-%d")
        expiry_date = (datetime.now().replace(year=datetime.now().year + 1)).strftime("%Y-%m-%d")

        if len(dates) >= 2:
            auth_date = dates[0]
            expiry_date = dates[1]
        elif len(dates) == 1:
            expiry_date = dates[0]

        # Save to SQLite authorized_scopes
        conn = sqlite3.connect(self.db_path)
        try:
            for cidr in cidrs:
                conn.execute(
                    "INSERT OR REPLACE INTO authorized_scopes (scope_id, target_cidr, target_domain, authorization_date, expiry_date, document_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"{scope_id}_{cidr}", cidr, "", auth_date, expiry_date, doc_hash)
                )
            for dom in valid_domains:
                conn.execute(
                    "INSERT OR REPLACE INTO authorized_scopes (scope_id, target_cidr, target_domain, authorization_date, expiry_date, document_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"{scope_id}_{dom}", "", dom, auth_date, expiry_date, doc_hash)
                )
            conn.commit()
        finally:
            conn.close()

        result = {
            "scope_id": scope_id,
            "cidrs": list(cidrs),
            "domains": list(valid_domains),
            "authorization_date": auth_date,
            "expiry_date": expiry_date,
            "document_hash": doc_hash
        }

        self._log_audit_event({
            "event_type": "PARSED_AUTHORIZATION_DOC",
            "document": str(path),
            "document_hash": doc_hash,
            "cidrs_extracted": len(cidrs),
            "domains_extracted": len(valid_domains)
        })

        return result

    def add_authorized_scope(self, cidr: str = "", domain: str = "", auth_date: str = None, expiry_date: str = None, doc_hash: str = "manual"):
        """Manually register authorized CIDR range or domain."""
        auth_date = auth_date or datetime.now().strftime("%Y-%m-%d")
        expiry_date = expiry_date or (datetime.now().replace(year=datetime.now().year + 1)).strftime("%Y-%m-%d")
        scope_id = f"manual_{cidr or domain}"

        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO authorized_scopes (scope_id, target_cidr, target_domain, authorization_date, expiry_date, document_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (scope_id, cidr, domain, auth_date, expiry_date, doc_hash)
            )
            conn.commit()
        finally:
            conn.close()

    def validate_target(self, target_ip: str, target_domain: Optional[str] = None, force_expired: bool = False) -> bool:
        """
        Validate target_ip and target_domain against authorized_scopes SQLite table.
        Check expiration date.
        If invalid, raise ScopeViolationException and log critical audit event.
        If valid, return True and log authorization check event.
        """
        conn = sqlite3.connect(self.db_path)
        authorized = False
        doc_hash = "N/A"
        expiry_date_str = None

        try:
            cursor = conn.execute("SELECT target_cidr, target_domain, expiry_date, document_hash FROM authorized_scopes")
            rows = cursor.fetchall()
            
            # Check IP scope
            try:
                ip_obj = ipaddress.ip_address(target_ip)
            except ValueError:
                ip_obj = None

            for cidr, dom, exp_date, d_hash in rows:
                if exp_date:
                    expiry_date_str = exp_date

                # Check CIDR match
                if cidr and ip_obj:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if ip_obj in net:
                            authorized = True
                            doc_hash = d_hash
                            break
                    except ValueError:
                        pass

                # Check Domain match
                if target_domain and dom:
                    t_dom = target_domain.lower()
                    a_dom = dom.lower()
                    if t_dom == a_dom or t_dom.endswith(f".{a_dom}"):
                        authorized = True
                        doc_hash = d_hash
                        break
        finally:
            conn.close()

        # Contract Expiration Check
        if authorized and expiry_date_str:
            try:
                exp_dt = datetime.strptime(expiry_date_str, "%Y-%m-%d")
                if datetime.now() > exp_dt:
                    if not force_expired:
                        event = {
                            "event_type": "EXPIRED_CONTRACT_ATTEMPT",
                            "target": target_ip,
                            "domain": target_domain,
                            "expiry_date": expiry_date_str,
                            "document_hash": doc_hash
                        }
                        self._log_audit_event(event)
                        raise ScopeViolationException(
                            f"Authorization document expired on {expiry_date_str}. Require --force-expired flag to proceed."
                        )
                    else:
                        logger.warning(f"[LegalValidator] Expired contract override applied for target {target_ip}")
            except ValueError:
                pass

        if not authorized:
            event = {
                "event_type": "SCOPE_VIOLATION",
                "target": target_ip,
                "domain": target_domain,
                "scope_match": False,
                "document_hash": doc_hash,
                "severity": "CRITICAL"
            }
            self._log_audit_event(event)
            raise ScopeViolationException(f"Target {target_ip} ({target_domain or 'no domain'}) is outside authorized legal scope.")

        # Record successful audit check
        self._log_audit_event({
            "event_type": "AUTHORIZATION_CHECK",
            "target": target_ip,
            "domain": target_domain,
            "scope_match": True,
            "document_hash": doc_hash
        })

        return True
