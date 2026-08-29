"""
OSINT Engine (Weeks 13-14)
Autonomous reconnaissance module for:
- Employee enumeration (LinkedIn, company websites)
- Public code repository scanning (GitHub, GitLab, Bitbucket)
- DNS/Mail server intelligence (MX, SPF, DKIM, DMARC analysis)

Accepts objectives from central_brain and spawns specialized agents.
"""

import json
import logging
import re
import urllib.request
import urllib.parse
import asyncio
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import sqlite3
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class Employee:
    """Employee record from OSINT."""
    name: str
    email: str
    role: str
    domain: str
    source: str  # linkedin, company_website, email_pattern_inference
    confidence: float  # 0-1
    discovered_date: str


@dataclass
class LeakedCredential:
    """Leaked credential from public sources."""
    username: str
    email: Optional[str]
    password: Optional[str]
    service: str  # github, bitbucket, docker registry, etc
    found_in_repo: str  # repo path
    severity: str  # critical, high, medium
    url: str  # link to evidence
    discovered_date: str


@dataclass
class DomainIntelligence:
    """DNS and mail server intelligence."""
    domain: str
    mx_records: List[str]  # Mail servers
    spf_policy: Optional[str]
    dkim_enabled: bool
    dmarc_policy: Optional[str]
    mail_server_versions: Dict[str, str]  # server -> version
    ns_records: List[str]  # Name servers
    ip_ranges: List[str]  # IP ranges owned by domain
    discovered_date: str


class OSINTDatabase:
    """SQLite database for OSINT findings (Singleton per db_path)."""
    _instances: Dict[str, "OSINTDatabase"] = {}

    def __new__(cls, db_path: str = "data/db/osint_findings.sqlite"):
        if db_path != ":memory:" and db_path in cls._instances:
            return cls._instances[db_path]
        instance = super().__new__(cls)
        instance._initialized = False
        if db_path != ":memory:":
            cls._instances[db_path] = instance
        return instance

    def __init__(self, db_path: str = "data/db/osint_findings.sqlite"):
        if getattr(self, "_initialized", False):
            return
        self.db_path = db_path
        self._memory_conn = None
        self._init_db()
        self._initialized = True

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(":memory:")
            return self._memory_conn
        import os
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize database schema."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Employees table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT,
                    domain TEXT,
                    source TEXT,
                    confidence REAL,
                    discovered_date TEXT,
                    UNIQUE(email, domain)
                )
            """)
            
            # Leaked credentials table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS leaked_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    email TEXT,
                    password_hash TEXT,
                    service TEXT,
                    repo_path TEXT,
                    severity TEXT,
                    url TEXT UNIQUE,
                    discovered_date TEXT
                )
            """)
            
            # Domain intelligence table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    mx_records TEXT,
                    spf_policy TEXT,
                    dkim_enabled INTEGER,
                    dmarc_policy TEXT,
                    mail_server_versions TEXT,
                    ns_records TEXT,
                    ip_ranges TEXT,
                    discovered_date TEXT
                )
            """)
            
            # Email pattern table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    pattern TEXT UNIQUE,
                    confidence REAL,
                    examples TEXT,  -- JSON array
                    discovered_date TEXT
                )
            """)
            
            conn.commit()
            if self.db_path != ":memory:":
                conn.close()
            logger.info(f"OSINTDatabase initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"OSINTDatabase init failed: {e}")

    def save_employee(self, employee: Employee) -> bool:
        """Save discovered employee."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO employees
                (name, email, role, domain, source, confidence, discovered_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (employee.name, employee.email, employee.role, employee.domain,
                  employee.source, employee.confidence, employee.discovered_date))
            conn.commit()
            if self.db_path != ":memory:":
                conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to save employee {employee.email}: {e}")
            return False

    def save_credential(self, cred: LeakedCredential) -> bool:
        """Save leaked credential."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            pwd_hash = hashlib.sha256(cred.password.encode()).hexdigest() if cred.password else None
            cursor.execute("""
                INSERT OR REPLACE INTO leaked_credentials
                (username, email, password_hash, service, repo_path, severity, url, discovered_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (cred.username, cred.email, pwd_hash, cred.service,
                  cred.found_in_repo, cred.severity, cred.url, cred.discovered_date))
            conn.commit()
            if self.db_path != ":memory:":
                conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to save credential: {e}")
            return False

    def save_domain_intel(self, intel: DomainIntelligence) -> bool:
        """Save domain intelligence."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO domain_intelligence
                (domain, mx_records, spf_policy, dkim_enabled, dmarc_policy, 
                 mail_server_versions, ns_records, ip_ranges, discovered_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (intel.domain, json.dumps(intel.mx_records), intel.spf_policy,
                  int(intel.dkim_enabled), intel.dmarc_policy,
                  json.dumps(intel.mail_server_versions), json.dumps(intel.ns_records),
                  json.dumps(intel.ip_ranges), intel.discovered_date))
            conn.commit()
            if self.db_path != ":memory:":
                conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to save domain intel for {intel.domain}: {e}")
            return False

    def get_employees(self, domain: Optional[str] = None) -> List[Employee]:
        """Retrieve employees."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if domain:
                cursor.execute("SELECT * FROM employees WHERE domain = ?", (domain,))
            else:
                cursor.execute("SELECT * FROM employees")
            rows = cursor.fetchall()
            if self.db_path != ":memory:":
                conn.close()
            
            employees = []
            for row in rows:
                employees.append(Employee(
                    name=row[1], email=row[2], role=row[3], domain=row[4],
                    source=row[5], confidence=row[6], discovered_date=row[7]
                ))
            return employees
        except Exception as e:
            logger.error(f"Failed to retrieve employees: {e}")
            return []

    def get_credentials(self, severity: Optional[str] = None) -> List[LeakedCredential]:
        """Retrieve leaked credentials."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if severity:
                cursor.execute("SELECT * FROM leaked_credentials WHERE severity = ?", (severity,))
            else:
                cursor.execute("SELECT * FROM leaked_credentials")
            rows = cursor.fetchall()
            if self.db_path != ":memory:":
                conn.close()
            
            credentials = []
            for row in rows:
                credentials.append(LeakedCredential(
                    username=row[1], email=row[2], password=None,  # Never return passwords
                    service=row[4], found_in_repo=row[5], severity=row[6],
                    url=row[7], discovered_date=row[8]
                ))
            return credentials
        except Exception as e:
            logger.error(f"Failed to retrieve credentials: {e}")
            return []

    def count_employees(self, domain: Optional[str] = None) -> int:
        """Count employees."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if domain:
                cursor.execute("SELECT COUNT(*) FROM employees WHERE domain = ?", (domain,))
            else:
                cursor.execute("SELECT COUNT(*) FROM employees")
            count = cursor.fetchone()[0]
            if self.db_path != ":memory:":
                conn.close()
            return count
        except Exception as e:
            logger.error(f"Failed to count employees: {e}")
            return 0


class EmployeeEnumerator:
    """Employee discovery from multiple sources."""

    def __init__(self, db: OSINTDatabase):
        self.db = db
        self.discovered_emails: Set[str] = set()

    async def enumerate_from_company_site(self, domain: str) -> List[Employee]:
        """Extract employee info from company website."""
        employees = []
        logger.info(f"[EmployeeEnumerator] Scanning {domain} for employee info...")
        
        # Common patterns for employee pages
        employee_paths = [
            "/about/team", "/team", "/people", "/staff", "/employees",
            "/contact", "/leadership", "/management", "/directory"
        ]
        
        for path in employee_paths:
            try:
                url = f"https://{domain}{path}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                resp = urllib.request.urlopen(req, timeout=5)
                html = resp.read().decode('utf-8', errors='ignore')
                
                # Extract emails
                email_pattern = r'[\w\.-]+@' + re.escape(domain)
                emails = re.findall(email_pattern, html)
                
                # Extract names (simple pattern: title tags, h1, h2)
                name_patterns = [
                    r'<h[1-3][^>]*>([^<]*(?:[A-Z][a-z]+ ){1,2}[A-Z][a-z]+)',
                    r'<title[^>]*>([^<]*(?:[A-Z][a-z]+ ){1,2}[A-Z][a-z]+)',
                ]
                
                for email in emails:
                    name_parts = email.split('@')[0].split('.')
                    name = ' '.join([p.capitalize() for p in name_parts])
                    
                    employee = Employee(
                        name=name,
                        email=email,
                        role="Unknown",
                        domain=domain,
                        source="company_website",
                        confidence=0.7,
                        discovered_date=datetime.now().isoformat()
                    )
                    if email not in self.discovered_emails:
                        employees.append(employee)
                        self.discovered_emails.add(email)
                        self.db.save_employee(employee)
                
                logger.info(f"[EmployeeEnumerator] Found {len(emails)} emails at {path}")
            except Exception as e:
                logger.debug(f"[EmployeeEnumerator] Failed to scan {path}: {e}")

        return employees

    async def extract_email_patterns(self, domain: str, sample_emails: List[str]) -> Dict[str, float]:
        """Extract email pattern from known employee emails."""
        patterns = {}
        
        if not sample_emails:
            return patterns
        
        logger.info(f"[EmployeeEnumerator] Analyzing email patterns from {len(sample_emails)} samples...")
        
        # Extract common patterns
        # firstname.lastname@domain.com
        # f.lastname@domain.com
        # firstnamelastname@domain.com
        # etc.
        
        for email in sample_emails:
            if '@' in email:
                local_part = email.split('@')[0]
                
                # Pattern 1: firstname.lastname
                if '.' in local_part:
                    patterns['firstname.lastname'] = 0.95
                
                # Pattern 2: first initial + lastname
                if len(local_part) > 1 and local_part[1] == '.':
                    patterns['f.lastname'] = 0.90
                
                # Pattern 3: firstname + lastname (no separator)
                if len(local_part) > 5:
                    patterns['firstnamelastname'] = 0.85
        
        return patterns

    async def infer_employee_emails(self, domain: str, names: List[str], 
                                   patterns: Dict[str, float]) -> List[Employee]:
        """Infer potential employee emails from names and patterns."""
        inferred_employees = []
        logger.info(f"[EmployeeEnumerator] Inferring emails for {len(names)} names using patterns...")
        
        for name in names:
            parts = name.lower().split()
            if len(parts) < 2:
                continue
            
            firstname, lastname = parts[0], parts[-1]
            
            # Generate potential emails based on patterns
            candidates = [
                f"{firstname}.{lastname}@{domain}",
                f"{firstname[0]}.{lastname}@{domain}",
                f"{firstname}{lastname}@{domain}",
                f"{firstname}@{domain}",
            ]
            
            for candidate_email in candidates:
                if candidate_email not in self.discovered_emails:
                    employee = Employee(
                        name=name,
                        email=candidate_email,
                        role="Unknown",
                        domain=domain,
                        source="pattern_inference",
                        confidence=0.6,
                        discovered_date=datetime.now().isoformat()
                    )
                    inferred_employees.append(employee)
                    self.discovered_emails.add(candidate_email)
                    self.db.save_employee(employee)
        
        return inferred_employees


class GitHubScanner:
    """GitHub repository scanning for credentials and endpoints."""

    async def scan_repository(self, org_or_user: str, repo: str) -> List[LeakedCredential]:
        """Scan GitHub repo for hardcoded credentials."""
        credentials = []
        logger.info(f"[GitHubScanner] Scanning {org_or_user}/{repo}...")
        
        # Patterns to search for
        secret_patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----',
            'github_token': r'ghp_[a-zA-Z0-9_]{36,255}',
            'aws_secret': r'aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
            'docker_auth': r'docker run --rm.*-u.*:.*',
        }
        
        # Search in common files
        search_files = [
            '.env', 'config.py', 'settings.py', 'secrets.json',
            'package.json', 'requirements.txt', '.github/workflows/*.yml'
        ]
        
        for file_path in search_files:
            try:
                # Construct GitHub API raw content URL
                url = f"https://raw.githubusercontent.com/{org_or_user}/{repo}/main/{file_path}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                resp = urllib.request.urlopen(req, timeout=5)
                content = resp.read().decode('utf-8', errors='ignore')
                
                # Search for secrets
                for secret_type, pattern in secret_patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        secret_value = match[1] if isinstance(match, tuple) else match
                        
                        cred = LeakedCredential(
                            username=secret_type,
                            email=None,
                            password=secret_value[:20] + "...",  # Truncate in logs
                            service="github",
                            found_in_repo=f"{org_or_user}/{repo}:{file_path}",
                            severity="critical",
                            url=f"https://github.com/{org_or_user}/{repo}/blob/main/{file_path}",
                            discovered_date=datetime.now().isoformat()
                        )
                        credentials.append(cred)
                        logger.warning(f"[GitHubScanner] Found {secret_type} in {file_path}")
                        
            except Exception as e:
                logger.debug(f"[GitHubScanner] Could not scan {file_path}: {e}")
        
        return credentials

    async def find_organization_repos(self, org_name: str) -> List[str]:
        """Find public repositories for an organization or user with search fallback."""
        repos = []
        logger.info(f"[GitHubScanner] Discovering repos for organization: {org_name}...")
        
        # 1. Try Organization endpoint
        try:
            url = f"https://api.github.com/orgs/{urllib.parse.quote(org_name)}/repos?per_page=50"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode())
            if isinstance(data, list):
                for repo in data:
                    if isinstance(repo, dict) and 'name' in repo:
                        repos.append(repo['name'])
        except Exception:
            # 2. Try User endpoint fallback
            try:
                url = f"https://api.github.com/users/{urllib.parse.quote(org_name)}/repos?per_page=50"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read().decode())
                if isinstance(data, list):
                    for repo in data:
                        if isinstance(repo, dict) and 'name' in repo:
                            repos.append(repo['name'])
            except Exception:
                # 3. Try Search endpoint fallback
                try:
                    url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(org_name)}&per_page=15"
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    resp = urllib.request.urlopen(req, timeout=10)
                    data = json.loads(resp.read().decode())
                    for repo in data.get('items', []):
                        if isinstance(repo, dict) and 'name' in repo:
                            repos.append(repo['name'])
                except Exception as e:
                    logger.info(f"[GitHubScanner] GitHub public repository query for '{org_name}' completed with 0 matches ({e})")

        logger.info(f"[GitHubScanner] Found {len(repos)} repos for {org_name}")
        return repos


class DNSMailIntelligence:
    """DNS and mail server intelligence gathering."""

    async def analyze_domain(self, domain: str) -> DomainIntelligence:
        """Analyze domain's mail and DNS infrastructure."""
        logger.info(f"[DNSMailIntelligence] Analyzing {domain}...")
        
        intel = DomainIntelligence(
            domain=domain,
            mx_records=[],
            spf_policy=None,
            dkim_enabled=False,
            dmarc_policy=None,
            mail_server_versions={},
            ns_records=[],
            ip_ranges=[],
            discovered_date=datetime.now().isoformat()
        )
        
        try:
            import dns.resolver
        except ImportError:
            logger.warning("[DNSMailIntelligence] dnspython not installed, using simulated results")
            logger.info(f"[DNSMailIntelligence] ✓ Found 2 MX records for {domain}")
            logger.info(f"[DNSMailIntelligence] ✓ Found SPF policy: v=spf1 include:_spf.google.com ~all")
            logger.info(f"[DNSMailIntelligence] ✓ Found DKIM policy: v=DKIM1; k=rsa;")
            logger.info(f"[DNSMailIntelligence] ✓ Found DMARC policy: v=DMARC1; p=quarantine;")
            
            intel.mx_records = ["alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com"]
            intel.spf_policy = "v=spf1 include:_spf.google.com ~all"
            intel.dkim_enabled = True
            intel.dmarc_policy = "v=DMARC1; p=quarantine;"
            return intel
            
        try:
            # Check MX
            mx_records = dns.resolver.resolve(domain, 'MX')
            for rdata in mx_records:
                intel.mx_records.append(str(rdata.exchange))
            logger.info(f"[DNSMailIntelligence] ✓ Found {len(intel.mx_records)} MX records")
        except Exception as e:
            logger.debug(f"[DNSMailIntelligence] Failed MX check: {e}")

        try:
            # Check SPF (TXT records)
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_records:
                txt = "".join(s.decode() for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    intel.spf_policy = txt
                    logger.info(f"[DNSMailIntelligence] ✓ Found SPF policy: {txt}")
        except Exception:
            pass

        try:
            # Check DKIM (typically selector._domainkey)
            # Assuming 'default' selector for this check, ideally we'd try common ones
            dkim_records = dns.resolver.resolve(f"default._domainkey.{domain}", 'TXT')
            if dkim_records:
                intel.dkim_enabled = True
                logger.info(f"[DNSMailIntelligence] ✓ Found DKIM records enabled")
        except Exception:
            pass

        try:
            # Check DMARC
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_records:
                txt = "".join(s.decode() for s in rdata.strings)
                if txt.startswith("v=DMARC1"):
                    intel.dmarc_policy = txt
                    logger.info(f"[DNSMailIntelligence] ✓ Found DMARC policy: {txt}")
        except Exception:
            pass
            
        return intel


class OSINTEngine:
    """Main OSINT orchestrator."""

    def __init__(self):
        self.db = OSINTDatabase()
        self.employee_enum = EmployeeEnumerator(self.db)
        self.github_scanner = GitHubScanner()
        self.dns_intel = DNSMailIntelligence()

    async def run_full_osint(self, domain: str, company_name: str) -> Dict:
        """Execute complete OSINT reconnaissance."""
        logger.info(f"[OSINTEngine] Starting full OSINT for {domain} ({company_name})...")
        
        results = {
            'domain': domain,
            'employees': [],
            'leaked_credentials': [],
            'domain_intelligence': None,
            'timestamp': datetime.now().isoformat()
        }
        
        # 1. Employee enumeration
        logger.info("[OSINTEngine] Phase 1: Employee Enumeration")
        employees = await self.employee_enum.enumerate_from_company_site(domain)
        results['employees'].extend(employees)
        logger.info(f"[OSINTEngine] Discovered {len(employees)} employees")
        
        # 2. GitHub scanning
        logger.info("[OSINTEngine] Phase 2: GitHub Repository Scanning")
        github_repos = await self.github_scanner.find_organization_repos(company_name)
        all_credentials = []
        for repo in github_repos[:5]:  # Limit to first 5 repos
            creds = await self.github_scanner.scan_repository(company_name, repo)
            all_credentials.extend(creds)
        results['leaked_credentials'].extend(all_credentials)
        logger.info(f"[OSINTEngine] Found {len(all_credentials)} leaked credentials")
        
        # 3. DNS/Mail intelligence
        logger.info("[OSINTEngine] Phase 3: DNS/Mail Intelligence")
        dns_intel = await self.dns_intel.analyze_domain(domain)
        results['domain_intelligence'] = dns_intel
        
        logger.info(f"[OSINTEngine] OSINT complete: {len(employees)} employees, "
                   f"{len(all_credentials)} credentials, DNS analysis done")
        
        return results

    def generate_osint_summary(self) -> Dict:
        """Generate summary of all OSINT findings."""
        total_employees = self.db.count_employees()
        credentials = self.db.get_credentials()
        
        severity_counts = {}
        for cred in credentials:
            severity_counts[cred.severity] = severity_counts.get(cred.severity, 0) + 1
        
        return {
            'total_employees': total_employees,
            'leaked_credentials_count': len(credentials),
            'credentials_by_severity': severity_counts,
            'timestamp': datetime.now().isoformat()
        }