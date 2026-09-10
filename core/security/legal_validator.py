
import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)


class ScopeViolationException(Exception):
    pass


class LegalValidator:

    def __init__(self, db_path: str = None, audit_log_path: str = "data/audit_trail.jsonl"):
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    def _log_audit_event(self, event_data: Dict[str, Any]):
        event_data["timestamp"] = datetime.now().isoformat()
        line = json.dumps(event_data) + "\n"
        with open(self.audit_log_path, mode="a", encoding="utf-8") as f:
            f.write(line)
        try:
            from core.database.pg_store import AuditRepo
            AuditRepo.log_event(event_data.get("event_type", ""), event_data.get("target", ""), event_data)
        except Exception as e:
            raise SystemError(f"Policy enforcement failed: {e}") from e

    def parse_authorization_document(self, doc_path: str, scope_id: str = "scope_default") -> Dict[str, Any]:
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

        cidr_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}\b'
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        date_pattern = r'\b\d{4}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{4}\b'

        cidrs = set(re.findall(cidr_pattern, raw_text))
        ips = set(re.findall(ip_pattern, raw_text))
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

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for cidr in cidrs:
                    cur.execute("""
                        INSERT INTO authorized_scopes (scope_id, target_cidr, target_domain, authorization_date, expiry_date, document_hash)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (scope_id) DO UPDATE SET
                            target_cidr = EXCLUDED.target_cidr, expiry_date = EXCLUDED.expiry_date, document_hash = EXCLUDED.document_hash
                    """, (f"{scope_id}_{cidr}", cidr, "", auth_date, expiry_date, doc_hash))
                for dom in valid_domains:
                    cur.execute("""
                        INSERT INTO authorized_scopes (scope_id, target_cidr, target_domain, authorization_date, expiry_date, document_hash)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (scope_id) DO UPDATE SET
                            target_domain = EXCLUDED.target_domain, expiry_date = EXCLUDED.expiry_date, document_hash = EXCLUDED.document_hash
                    """, (f"{scope_id}_{dom}", "", dom, auth_date, expiry_date, doc_hash))
                conn.commit()

        result = {
            "scope_id": scope_id, "cidrs": list(cidrs), "domains": list(valid_domains),
            "authorization_date": auth_date, "expiry_date": expiry_date, "document_hash": doc_hash,
        }
        self._log_audit_event({
            "event_type": "PARSED_AUTHORIZATION_DOC", "document": str(path),
            "document_hash": doc_hash, "cidrs_extracted": len(cidrs), "domains_extracted": len(valid_domains),
        })
        return result

    def add_authorized_scope(self, cidr: str = "", domain: str = "", auth_date: str = None, expiry_date: str = None, doc_hash: str = "manual"):
        auth_date = auth_date or datetime.now().strftime("%Y-%m-%d")
        expiry_date = expiry_date or (datetime.now().replace(year=datetime.now().year + 1)).strftime("%Y-%m-%d")
        scope_id = f"manual_{cidr or domain}"
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO authorized_scopes (scope_id, target_cidr, target_domain, authorization_date, expiry_date, document_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scope_id) DO UPDATE SET
                        target_cidr = EXCLUDED.target_cidr, target_domain = EXCLUDED.target_domain,
                        expiry_date = EXCLUDED.expiry_date, document_hash = EXCLUDED.document_hash
                """, (scope_id, cidr, domain, auth_date, expiry_date, doc_hash))
                conn.commit()

    def validate_target(self, target_ip: str, target_domain: Optional[str] = None, force_expired: bool = False) -> bool:
        authorized = False
        doc_hash = "N/A"
        expiry_date_str = None

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT target_cidr, target_domain, expiry_date, document_hash FROM authorized_scopes")
                rows = cur.fetchall()

        try:
            ip_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            ip_obj = None

        for cidr, dom, exp_date, d_hash in rows:
            if exp_date:
                expiry_date_str = exp_date
            if cidr and ip_obj:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in net:
                        authorized = True
                        doc_hash = d_hash
                        break
                except ValueError:
                    pass
            if target_domain and dom:
                t_dom = target_domain.lower()
                a_dom = dom.lower()
                if t_dom == a_dom or t_dom.endswith(f".{a_dom}"):
                    authorized = True
                    doc_hash = d_hash
                    break

        if authorized and expiry_date_str:
            try:
                exp_dt = datetime.strptime(expiry_date_str, "%Y-%m-%d")
                if datetime.now() > exp_dt:
                    if not force_expired:
                        self._log_audit_event({
                            "event_type": "EXPIRED_CONTRACT_ATTEMPT", "target": target_ip,
                            "domain": target_domain, "expiry_date": expiry_date_str, "document_hash": doc_hash,
                        })
                        raise ScopeViolationException(
                            f"Authorization document expired on {expiry_date_str}. Require --force-expired flag to proceed."
                        )
                    else:
                        logger.warning(f"[LegalValidator] Expired contract override applied for target {target_ip}")
            except ValueError:
                pass

        if not authorized:
            self._log_audit_event({
                "event_type": "SCOPE_VIOLATION", "target": target_ip, "domain": target_domain,
                "scope_match": False, "document_hash": doc_hash, "severity": "CRITICAL",
            })
            raise ScopeViolationException(f"Target {target_ip} ({target_domain or 'no domain'}) is outside authorized legal scope.")

        self._log_audit_event({
            "event_type": "AUTHORIZATION_CHECK", "target": target_ip,
            "domain": target_domain, "scope_match": True, "document_hash": doc_hash,
        })
        return True
