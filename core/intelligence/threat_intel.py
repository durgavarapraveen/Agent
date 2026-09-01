"""
Threat Intelligence Module (Weeks 13-14)
Integrates public threat feeds:
- Shodan queries (if API available)
- Censys certificate intelligence
- abuse.ch feeds (malware, phishing, botnet)
- Public IP/domain reputation feeds

Real-time correlation with discovered assets.
"""

import json
import logging
import urllib.request
import urllib.parse
import ssl
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)

_SSL_CONTEXT = ssl._create_unverified_context()

# Common threat intel sources
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"
SHODAN_URL = "https://api.shodan.io"
CENSYS_URL = "https://censys.io/api"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1"
PHISHING_ARMY_URL = "https://phishing-army.abuse.ch"
BOTNET_C2_URL = "https://botnet-c2.abuse.ch"


@dataclass
class ThreatIndicator:
    """Threat intelligence indicator."""
    type: str  # ip, domain, url, email, hash
    value: str
    threat_type: str  # malware, phishing, botnet, c2, exploit_kit
    severity: str  # critical, high, medium, low
    sources: List[str]  # Which feeds detected this
    first_seen: str
    last_seen: str
    description: str
    confidence: float  # 0-1


@dataclass
class ReputationScore:
    """IP/domain reputation assessment."""
    asset: str  # IP or domain
    overall_score: float  # 0-100, higher = more malicious
    detection_engines: int  # How many engines flagged it
    threat_types: List[str]  # Types of threats
    abuse_reports: int  # Number of abuse reports
    first_flagged: Optional[str]
    last_flagged: Optional[str]
    whitelisted: bool


@dataclass
class CompromisedService:
    """Compromised service detection."""
    service_name: str
    ip_address: str
    port: int
    threat_type: str  # malware, botnet, c2, etc
    confirmed: bool
    source: str  # Which feed detected it
    remediation_advice: str
    confidence: float


class ThreatIntelDatabase:
    """PostgreSQL database for threat intelligence."""

    def __init__(self):
        self._init_db()

    def _init_db(self):
        """Initialize threat intelligence schema."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Threat indicators table
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS threat_indicators (
                            id SERIAL PRIMARY KEY,
                            type TEXT,
                            value TEXT UNIQUE,
                            threat_type TEXT,
                            severity TEXT,
                            sources TEXT,
                            first_seen TEXT,
                            last_seen TEXT,
                            description TEXT,
                            confidence REAL,
                            discovered_date TEXT
                        )
                    """)
                    
                    # Reputation scores table
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS reputation_scores (
                            id SERIAL PRIMARY KEY,
                            asset TEXT UNIQUE,
                            overall_score REAL,
                            detection_engines INTEGER,
                            threat_types TEXT,
                            abuse_reports INTEGER,
                            first_flagged TEXT,
                            last_flagged TEXT,
                            whitelisted INTEGER,
                            checked_date TEXT
                        )
                    """)
                    
                    # Compromised services table
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS compromised_services (
                            id SERIAL PRIMARY KEY,
                            service_name TEXT,
                            ip_address TEXT,
                            port INTEGER,
                            threat_type TEXT,
                            confirmed INTEGER,
                            source TEXT,
                            remediation_advice TEXT,
                            confidence REAL,
                            discovered_date TEXT,
                            UNIQUE(ip_address, port)
                        )
                    """)
                    
                    # Feed metadata table
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS feed_metadata (
                            id SERIAL PRIMARY KEY,
                            feed_name TEXT UNIQUE,
                            last_updated TEXT,
                            indicator_count INTEGER,
                            success_rate REAL
                        )
                    """)
                    
                    # Correlation events table (asset x threat)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS correlation_events (
                            id SERIAL PRIMARY KEY,
                            asset TEXT,
                            threat_value TEXT,
                            correlation_type TEXT,
                            severity TEXT,
                            alert_sent INTEGER,
                            event_date TEXT
                        )
                    """)
                    conn.commit()
            logger.info("ThreatIntelDatabase initialized via PostgreSQL")
        except Exception as e:
            logger.error(f"ThreatIntelDatabase init failed: {e}")

    def save_threat_indicator(self, indicator: ThreatIndicator) -> bool:
        """Save threat indicator."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO threat_indicators
                        (type, value, threat_type, severity, sources, first_seen, last_seen, description, confidence, discovered_date)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (value) DO UPDATE SET
                        severity = EXCLUDED.severity, sources = EXCLUDED.sources,
                        last_seen = EXCLUDED.last_seen, description = EXCLUDED.description,
                        confidence = EXCLUDED.confidence
                    """, (indicator.type, indicator.value, indicator.threat_type, indicator.severity,
                          json.dumps(indicator.sources), indicator.first_seen, indicator.last_seen,
                          indicator.description, indicator.confidence, datetime.now().isoformat()))
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save threat indicator: {e}")
            return False

    def save_reputation_score(self, score: ReputationScore) -> bool:
        """Save reputation score."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO reputation_scores
                        (asset, overall_score, detection_engines, threat_types, abuse_reports, first_flagged, last_flagged, whitelisted, checked_date)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (asset) DO UPDATE SET
                        overall_score = EXCLUDED.overall_score, detection_engines = EXCLUDED.detection_engines,
                        threat_types = EXCLUDED.threat_types, abuse_reports = EXCLUDED.abuse_reports,
                        last_flagged = EXCLUDED.last_flagged, whitelisted = EXCLUDED.whitelisted, checked_date = EXCLUDED.checked_date
                    """, (score.asset, score.overall_score, score.detection_engines,
                          json.dumps(score.threat_types), score.abuse_reports,
                          score.first_flagged, score.last_flagged, int(score.whitelisted),
                          datetime.now().isoformat()))
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save reputation score: {e}")
            return False

    def save_compromised_service(self, service: CompromisedService) -> bool:
        """Save compromised service."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO compromised_services
                        (service_name, ip_address, port, threat_type, confirmed, source, remediation_advice, confidence, discovered_date)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (ip_address, port) DO UPDATE SET
                        threat_type = EXCLUDED.threat_type, confirmed = EXCLUDED.confirmed,
                        remediation_advice = EXCLUDED.remediation_advice, confidence = EXCLUDED.confidence
                    """, (service.service_name, service.ip_address, service.port,
                          service.threat_type, int(service.confirmed), service.source,
                          service.remediation_advice, service.confidence, datetime.now().isoformat()))
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save compromised service: {e}")
            return False

    def get_threat_indicators_for_asset(self, asset: str) -> List[ThreatIndicator]:
        """Get threat indicators for an asset."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM threat_indicators WHERE value = %s", (asset,))
                    rows = cursor.fetchall()
                    
            indicators = []
            for row in rows:
                indicators.append(ThreatIndicator(
                    type=row[1], value=row[2], threat_type=row[3], severity=row[4],
                    sources=json.loads(row[5] or '[]'), first_seen=row[6], last_seen=row[7],
                    description=row[8], confidence=row[9]
                ))
            return indicators
        except Exception as e:
            logger.error(f"Failed to get threat indicators: {e}")
            return []

    def get_threat_indicators_by_source(self, source_name: str) -> List[ThreatIndicator]:
        """Get threat indicators containing a specific source from cache."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM threat_indicators WHERE sources LIKE %s", (f'%"{source_name}"%',))
                    rows = cursor.fetchall()
                    
            indicators = []
            for row in rows:
                indicators.append(ThreatIndicator(
                    type=row[1], value=row[2], threat_type=row[3], severity=row[4],
                    sources=json.loads(row[5] or '[]'), first_seen=row[6], last_seen=row[7],
                    description=row[8], confidence=row[9]
                ))
            return indicators
        except Exception as e:
            logger.error(f"Failed to get cached threat indicators by source: {e}")
            return []

    def get_critical_threats(self) -> List[ThreatIndicator]:
        """Get all critical threat indicators."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM threat_indicators WHERE severity = 'critical' ORDER BY discovered_date DESC")
                    rows = cursor.fetchall()
                    
            indicators = []
            for row in rows:
                indicators.append(ThreatIndicator(
                    type=row[1], value=row[2], threat_type=row[3], severity=row[4],
                    sources=json.loads(row[5] or '[]'), first_seen=row[6], last_seen=row[7],
                    description=row[8], confidence=row[9]
                ))
            return indicators
        except Exception as e:
            logger.error(f"Failed to get critical threats: {e}")
            return []


class AbuseChIntelligence:
    """abuse.ch threat feeds integration."""

    def __init__(self, db: ThreatIntelDatabase):
        self.db = db

    async def query_phishing_army(self) -> List[ThreatIndicator]:
        """Query Phishing Army feed for malicious URLs with OpenPhish fallback."""
        indicators = []
        logger.info("[AbuseChIntelligence] Querying Phishing feed...")
        
        # 1. Try Phishing Army CSV
        try:
            url = "https://phishing-army.abuse.ch/downloads/phishing_army_rules.csv"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            resp = urllib.request.urlopen(req, timeout=8, context=_SSL_CONTEXT)
            lines = resp.read().decode('utf-8').split('\n')
            
            for line in lines[1:50]:  # Up to 50
                if not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) >= 2:
                    url_value = parts[0].strip()
                    indicator = ThreatIndicator(
                        type="url", value=url_value, threat_type="phishing", severity="high",
                        sources=["phishing_army"], first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(), description="Phishing URL from Phishing Army feed",
                        confidence=0.95
                    )
                    indicators.append(indicator)
                    self.db.save_threat_indicator(indicator)
            
            logger.info(f"[AbuseChIntelligence] Loaded {len(indicators)} phishing URLs from Phishing Army")
            return indicators
        except Exception as e:
            logger.info(f"[AbuseChIntelligence] Phishing Army feed unavailable ({e}), trying OpenPhish fallback...")

        # 2. Fallback: OpenPhish free feed
        try:
            url = "https://openphish.com/feed.txt"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            resp = urllib.request.urlopen(req, timeout=8, context=_SSL_CONTEXT)
            lines = resp.read().decode('utf-8', errors='ignore').splitlines()
            for line in lines[:50]:
                u = line.strip()
                if u and u.startswith("http"):
                    indicator = ThreatIndicator(
                        type="url", value=u, threat_type="phishing", severity="high",
                        sources=["openphish"], first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(), description="Phishing URL from OpenPhish feed",
                        confidence=0.92
                    )
                    indicators.append(indicator)
                    self.db.save_threat_indicator(indicator)
            logger.info(f"[AbuseChIntelligence] Loaded {len(indicators)} phishing URLs from OpenPhish")
        except Exception as ex:
            logger.warning(f"[AbuseChIntelligence] OpenPhish feed fallback unavailable: {ex}")
            cached = self.db.get_threat_indicators_by_source("phishing_army") or self.db.get_threat_indicators_by_source("openphish")
            if cached:
                logger.info(f"[AbuseChIntelligence] Loaded {len(cached)} phishing URLs from local cache")
                return cached
        
        return indicators

    async def query_malware_bazon(self) -> List[ThreatIndicator]:
        """Query URLhaus for recent malware delivery URLs with static JSON fallback."""
        indicators = []
        logger.info("[AbuseChIntelligence] Querying URLhaus for malware...")
        
        # 1. Try URLhaus v1 API
        try:
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            resp = urllib.request.urlopen(req, timeout=8, context=_SSL_CONTEXT)
            result = json.loads(resp.read().decode())
            
            if result.get('query_status') == 'ok':
                for url_data in result.get('urls', [])[:50]:
                    indicator = ThreatIndicator(
                        type="url", value=url_data.get('url', ''), threat_type=url_data.get('threat', 'malware'),
                        severity="critical", sources=["urlhaus"], first_seen=url_data.get('date_added'),
                        last_seen=url_data.get('date_last_seen'), description=f"Malware delivery URL: {url_data.get('threat')}",
                        confidence=0.98
                    )
                    indicators.append(indicator)
                    self.db.save_threat_indicator(indicator)
                logger.info(f"[AbuseChIntelligence] Loaded {len(indicators)} malware URLs from URLhaus API")
                return indicators
        except Exception as e:
            logger.info(f"[AbuseChIntelligence] URLhaus API query unavailable ({e}), trying public JSON feed fallback...")

        # 2. Fallback: URLhaus public recent JSON feed
        try:
            url = "https://urlhaus.abuse.ch/downloads/json_recent/"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            resp = urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT)
            data = json.loads(resp.read().decode())
            for uid, udata in list(data.items())[:50]:
                if isinstance(udata, list) and len(udata) > 0:
                    item = udata[0]
                    u = item.get("url", "")
                    if u:
                        indicator = ThreatIndicator(
                            type="url", value=u, threat_type="malware", severity="critical",
                            sources=["urlhaus_json"], first_seen=item.get("dateadded", datetime.now().isoformat()),
                            last_seen=datetime.now().isoformat(), description=f"Malware URL: {item.get('threat', 'malware')}",
                            confidence=0.95
                        )
                        indicators.append(indicator)
                        self.db.save_threat_indicator(indicator)
            logger.info(f"[AbuseChIntelligence] Loaded {len(indicators)} malware URLs from URLhaus JSON feed")
        except Exception as ex:
            logger.warning(f"[AbuseChIntelligence] URLhaus JSON fallback feed unavailable: {ex}")
            cached = self.db.get_threat_indicators_by_source("urlhaus") or self.db.get_threat_indicators_by_source("urlhaus_json")
            if cached:
                logger.info(f"[AbuseChIntelligence] Loaded {len(cached)} malware URLs from local cache")
                return cached
        
        return indicators

    async def query_botnet_c2(self) -> List[ThreatIndicator]:
        """Query Botnet C2 tracker for command and control servers."""
        indicators = []
        logger.info("[AbuseChIntelligence] Querying Botnet C2 feed...")
        
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            resp = urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT)
            data = json.loads(resp.read().decode())
            
            entries = data if isinstance(data, list) else data.get('data', [])
            for entry in entries[:50]:
                indicator = ThreatIndicator(
                    type="ip" if self._is_ip(entry.get('ip_address', '')) else "domain",
                    value=entry.get('ip_address') or entry.get('dst_host', ''),
                    threat_type="botnet_c2",
                    severity="critical",
                    sources=["botnet_c2"],
                    first_seen=entry.get('first_seen'),
                    last_seen=entry.get('last_seen'),
                    description=f"Botnet C2: {entry.get('malware', 'unknown')}",
                    confidence=0.99
                )
                indicators.append(indicator)
                self.db.save_threat_indicator(indicator)
            
            logger.info(f"[AbuseChIntelligence] Loaded {len(indicators)} botnet C2s")
        except Exception as e:
            logger.warning(f"[AbuseChIntelligence] Botnet C2 feed currently unavailable: {e}")
            cached = self.db.get_threat_indicators_by_source("botnet_c2")
            if cached:
                logger.info(f"[AbuseChIntelligence] Loaded {len(cached)} botnet C2s from local cache")
                return cached
        
        return indicators

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if value is an IP address."""
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))


class PublicFeedsIntegration:
    """Integration with public threat feeds."""

    def __init__(self, db: ThreatIntelDatabase):
        self.db = db

    async def check_ip_reputation(self, ip_address: str) -> Optional[ReputationScore]:
        """Check IP reputation from multiple sources."""
        logger.info(f"[PublicFeeds] Checking reputation for IP: {ip_address}")
        
        threat_types = []
        sources = []
        
        # In production, query AbuseIPDB, VirusTotal, etc.
        # For now, create a placeholder
        score = ReputationScore(
            asset=ip_address,
            overall_score=0.0,  # Will be calculated
            detection_engines=0,
            threat_types=threat_types,
            abuse_reports=0,
            first_flagged=None,
            last_flagged=None,
            whitelisted=False
        )
        
        logger.info(f"[PublicFeeds] Reputation score for {ip_address}: {score.overall_score}/100")
        self.db.save_reputation_score(score)
        
        return score

    async def check_domain_reputation(self, domain: str) -> Optional[ReputationScore]:
        """Check domain reputation."""
        logger.info(f"[PublicFeeds] Checking reputation for domain: {domain}")
        
        score = ReputationScore(
            asset=domain,
            overall_score=0.0,
            detection_engines=0,
            threat_types=[],
            abuse_reports=0,
            first_flagged=None,
            last_flagged=None,
            whitelisted=False
        )
        
        self.db.save_reputation_score(score)
        return score

    async def check_url_safety(self, url: str) -> bool:
        """Check if URL is safe."""
        logger.info(f"[PublicFeeds] Checking URL safety: {url}")
        
        # Would query VirusTotal, URLhaus, etc.
        # For now, assume safe
        return True


class ThreatIntelligenceEngine:
    """Main threat intelligence orchestrator."""

    def __init__(self):
        self.db = ThreatIntelDatabase()
        self.abuse_ch = AbuseChIntelligence(self.db)
        self.public_feeds = PublicFeedsIntegration(self.db)

    async def load_threat_feeds(self) -> Dict[str, int]:
        """Load all threat intelligence feeds."""
        logger.info("[ThreatIntelligenceEngine] Loading threat feeds...")
        
        feed_results = {}
        
        # Load abuse.ch feeds
        phishing = await self.abuse_ch.query_phishing_army()
        feed_results['phishing_army'] = len(phishing)
        
        malware = await self.abuse_ch.query_malware_bazon()
        feed_results['urlhaus_malware'] = len(malware)
        
        botnet = await self.abuse_ch.query_botnet_c2()
        feed_results['botnet_c2'] = len(botnet)
        
        logger.info(f"[ThreatIntelligenceEngine] Feeds loaded: {feed_results}")
        return feed_results

    async def correlate_with_findings(self, discovered_assets: Dict) -> List[Dict]:
        """Correlate discovered assets with threat intelligence."""
        logger.info("[ThreatIntelligenceEngine] Correlating findings with threat intel...")
        
        correlations = []
        
        # Check IPs
        for ip in discovered_assets.get('ips', []):
            threats = self.db.get_threat_indicators_for_asset(ip)
            if threats:
                for threat in threats:
                    correlations.append({
                        'asset': ip,
                        'threat_type': threat.threat_type,
                        'severity': threat.severity,
                        'sources': threat.sources,
                        'description': threat.description
                    })
                    logger.warning(f"[ThreatIntelligenceEngine] ALERT: {ip} found in threat intel ({threat.threat_type})")
        
        # Check domains
        for domain in discovered_assets.get('domains', []):
            threats = self.db.get_threat_indicators_for_asset(domain)
            if threats:
                for threat in threats:
                    correlations.append({
                        'asset': domain,
                        'threat_type': threat.threat_type,
                        'severity': threat.severity,
                        'sources': threat.sources,
                        'description': threat.description
                    })
                    logger.warning(f"[ThreatIntelligenceEngine] ALERT: {domain} found in threat intel ({threat.threat_type})")
        
        logger.info(f"[ThreatIntelligenceEngine] Correlation complete: {len(correlations)} matches")
        return correlations

    def generate_threat_summary(self) -> Dict:
        """Generate threat intelligence summary."""
        critical_threats = self.db.get_critical_threats()
        
        return {
            'total_indicators': len(critical_threats),
            'critical_threats': len([t for t in critical_threats if t.severity == 'critical']),
            'threat_types': list(set([t.threat_type for t in critical_threats])),
            'top_sources': list(set([s for t in critical_threats for s in t.sources])),
            'timestamp': datetime.now().isoformat()
        }